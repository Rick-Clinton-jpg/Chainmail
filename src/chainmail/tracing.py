"""
Chainmail v5 --- optional OpenTelemetry tracing.

Strictly additive: if ``opentelemetry`` is not installed, or tracing setup
fails, ``evaluate`` still runs and ``span`` is a no-op object. A tracing
outage can never become a governor outage.

Enable by installing the ``tracing`` extra and setting
``CHAINMAIL_TRACING=1`` (or calling ``configure(enabled=True)``). Spans export
to the console by default; wire your own ``TracerProvider`` before first use to
send them elsewhere.

Adapted from ``Quorum/gate/otel_tracing.py`` (Rick-Clinton-jpg, PolyForm NC 1.0.0).
"""

from __future__ import annotations

import logging
import os
import sys
from contextlib import contextmanager
from typing import Any, Iterator, Optional

logger = logging.getLogger(__name__)

_tracer: Optional[Any] = None
_init_attempted = False
_enabled = os.environ.get("CHAINMAIL_TRACING", "").lower() in ("1", "true", "yes", "on")


def configure(*, enabled: bool) -> None:
    """Turn tracing on/off explicitly. Resets the lazy init so the next span
    call re-evaluates."""
    global _enabled, _init_attempted, _tracer
    _enabled = enabled
    _init_attempted = False
    _tracer = None


def _init_tracer() -> Optional[Any]:
    global _tracer, _init_attempted
    if _init_attempted:
        return _tracer
    _init_attempted = True
    if not _enabled:
        return None
    try:
        from opentelemetry import trace
        from opentelemetry.sdk.resources import Resource
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import ConsoleSpanExporter, SimpleSpanProcessor
    except ImportError:
        logger.warning("CHAINMAIL_TRACING is set but opentelemetry is not installed; "
                       "install the 'tracing' extra. Continuing untraced.")
        return None
    try:
        if trace.get_tracer_provider().__class__.__name__ == "ProxyTracerProvider":
            provider = TracerProvider(resource=Resource.create({"service.name": "chainmail"}))
            provider.add_span_processor(SimpleSpanProcessor(ConsoleSpanExporter()))
            trace.set_tracer_provider(provider)
        _tracer = trace.get_tracer("chainmail.governor")
    except Exception as exc:  # noqa: BLE001
        logger.warning("OTel tracer setup failed (%s); continuing untraced.", exc)
        return None
    return _tracer


def current_trace_id() -> Optional[str]:
    """32-hex-char trace id of the active span, or None when there is nothing
    real to reference (tracing off, or no active span)."""
    tracer = _init_tracer()
    if tracer is None:
        return None
    from opentelemetry import trace

    ctx = trace.get_current_span().get_span_context()
    return format(ctx.trace_id, "032x") if ctx.is_valid else None


class _NullSpan:
    def set_attribute(self, *_a: Any, **_k: Any) -> None:
        pass


@contextmanager
def span(name: str, **attributes: Any) -> Iterator[Any]:
    """One span, yielded so the caller can attach outcome attributes once the
    result is known. Setup failures degrade to a null span; a real exception
    from the caller's block is recorded then re-raised unmodified."""
    tracer = _init_tracer()
    if tracer is None:
        yield _NullSpan()
        return
    try:
        cm = tracer.start_as_current_span(name)
        active = cm.__enter__()
        for key, value in attributes.items():
            if value is None:
                continue
            active.set_attribute(
                key, value if isinstance(value, (str, int, float, bool)) else str(value))
    except Exception as exc:  # noqa: BLE001
        logger.warning("OTel span %r failed to start (%s); untraced for this call.", name, exc)
        yield _NullSpan()
        return
    try:
        yield active
    except BaseException:
        try:
            cm.__exit__(*sys.exc_info())
        except Exception:  # noqa: BLE001
            pass
        raise
    else:
        try:
            cm.__exit__(None, None, None)
        except Exception as exc:  # noqa: BLE001
            logger.warning("OTel span %r failed to close cleanly (%s)", name, exc)
