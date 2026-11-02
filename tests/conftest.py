"""Shared, bounded Hypothesis profiles; ordinary pytest runs no extra analyses."""

from hypothesis import settings

settings.register_profile(
    "fast",
    max_examples=100,
    derandomize=True,
    deadline=None,
    database=None,
    print_blob=True,
    suppress_health_check=(),
)
settings.register_profile("ci", parent=settings.get_profile("fast"))
settings.register_profile(
    "exploratory",
    parent=settings.get_profile("fast"),
    max_examples=1000,
    derandomize=False,
)
settings.load_profile("fast")
