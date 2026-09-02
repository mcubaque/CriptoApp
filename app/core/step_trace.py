"""Shared data structures used by every algorithm module to describe, step by
step, how it reached its result. A single Jinja partial (templates/partials/
_step_trace.html) knows how to render any Step, regardless of which algorithm
produced it.
"""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Any


@dataclass
class StepTable:
    """A rectangular table attached to one step, e.g. one row per letter,
    one row per S-box lookup, one row per hypothesis tried."""

    columns: list[str]
    rows: list[list[Any]]


@dataclass
class Step:
    index: int
    title: str
    explanation: str
    formula: str | None = None
    table: StepTable | None = None
    ok: bool = True
    extra: dict[str, Any] = field(default_factory=dict)
    chart: dict[str, Any] | None = None


@dataclass
class AlgorithmRunResult:
    ok: bool
    family: str
    algorithm: str
    operation: str
    input_summary: dict[str, Any]
    output: str | None
    output_label: str
    steps: list[Step]
    error: str | None = None

    def to_json(self) -> dict:
        return asdict(self)


def step(
    index: int,
    title: str,
    explanation: str,
    *,
    formula: str | None = None,
    columns: list[str] | None = None,
    rows: list[list[Any]] | None = None,
    ok: bool = True,
    extra: dict[str, Any] | None = None,
    chart: dict[str, Any] | None = None,
) -> Step:
    """Convenience constructor: build a Step, optionally with a table, in one call."""
    table = StepTable(columns=columns, rows=rows) if columns is not None else None
    return Step(
        index=index,
        title=title,
        explanation=explanation,
        formula=formula,
        table=table,
        ok=ok,
        extra=extra or {},
        chart=chart,
    )
