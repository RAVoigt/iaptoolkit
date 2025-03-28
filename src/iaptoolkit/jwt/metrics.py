import asyncio
import typing as t

try:
    from prometheus_client import Counter
    # TODO move to constants
    default_metric = Counter(
        "iaptoolkit_jwt_event_total",
        "Count of JWT verification events",
        labelnames=["event"]
    )
except ImportError:
    Counter = t.TypeVar("Counter")
    default_metric = None


def inc_metric(metric: Counter | None, event: str):
    if not metric:
        return
    metric.labels(event=event).inc()


async def inc_metric_async(metric: Counter | None, event: str):
    if not metric:
        return
    # TODO: Does prometheus_client have built-in async support?
    await asyncio.to_thread(metric.labels(event=event).inc)

__all__ = [
    "default_metric",
    "Counter",
    "inc_metric",
    "inc_metric_async"
]
