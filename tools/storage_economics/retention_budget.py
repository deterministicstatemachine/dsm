# SPDX-License-Identifier: Apache-2.0
"""Exact commercial retention accounting; never a DSM acceptance mechanism."""

from dataclasses import dataclass
from fractions import Fraction


def amount(value):
    """Require exact, nonnegative cost-currency inputs, including decimal strings."""
    if isinstance(value, (float, bool)):
        raise ValueError("use an integer, Fraction or decimal string")
    result = Fraction(value)
    if result < 0:
        raise ValueError("negative amount")
    return result


def count(value):
    if type(value) is not int or value < 0:
        raise ValueError("expected a nonnegative integer")
    return value


@dataclass(frozen=True)
class Costs:
    storage_per_byte: Fraction
    handover_per_byte: Fraction
    fixed_per_period: Fraction
    retention_periods: int
    handover_periods: int

    def __post_init__(self):
        for name in ("storage_per_byte", "handover_per_byte", "fixed_per_period"):
            object.__setattr__(self, name, amount(getattr(self, name)))
        for name in ("retention_periods", "handover_periods"):
            if count(getattr(self, name)) == 0:
                raise ValueError("a projection horizon must be positive")

    def handover_floor(self, capacity):
        return (count(capacity) * self.handover_per_byte
                + self.handover_periods * self.fixed_per_period)

    def target(self, capacity):
        return (self.handover_floor(capacity)
                + self.retention_periods * capacity * self.storage_per_byte)


@dataclass(frozen=True)
class Book:
    held_bytes: int
    unused_sold_bytes: int
    reserve: Fraction
    equity: Fraction

    def __post_init__(self):
        count(self.held_bytes)
        count(self.unused_sold_bytes)
        object.__setattr__(self, "reserve", amount(self.reserve))
        object.__setattr__(self, "equity", amount(self.equity))

    @property
    def capacity(self):
        return self.held_bytes + self.unused_sold_bytes


@dataclass(frozen=True)
class SaleAssessment:
    capacity: int
    reserve_top_up: Fraction
    operating_cost: Fraction
    cash_surplus: Fraction
    execution_shortfall: Fraction

    @property
    def funded(self):
        return self.cash_surplus >= 0 and self.execution_shortfall == 0


def assess_sale(book, costs, new_capacity, settled_revenue, activity_cost,
                unsettled_exposure):
    """Assess an operator budget, without choosing a price or admitting a write.

    Revenue is already net of actual payment costs. Unsettled exposure is the
    caller's maximum execution loss, covered separately by existing equity.
    Provisions restrict cash; they are not a second operating expense.
    """
    capacity = book.capacity + count(new_capacity)
    top_up = max(Fraction(0), costs.target(capacity) - book.reserve)
    operating = (costs.fixed_per_period + capacity * costs.storage_per_byte
                 + amount(activity_cost))
    return SaleAssessment(
        capacity, top_up, operating,
        amount(settled_revenue) - operating - top_up,
        max(Fraction(0), amount(unsettled_exposure) - book.equity),
    )


@dataclass(frozen=True)
class Maintenance:
    book: Book
    expense_paid: Fraction
    unpaid: Fraction
    reserve_deficit: Fraction


def maintain(book, costs):
    """Project one reporting period, retaining every byte and the handover floor.

    An unpaid expense reports a commercial deficit. It never deletes evidence,
    unlocks a stake, claims a handover succeeded, or changes protocol validity.
    """
    due = costs.fixed_per_period + book.capacity * costs.storage_per_byte
    equity_payment = min(book.equity, due)
    available_reserve = max(Fraction(0), book.reserve - costs.handover_floor(book.capacity))
    reserve_payment = min(available_reserve, due - equity_payment)
    after = Book(book.held_bytes, book.unused_sold_bytes,
                 book.reserve - reserve_payment, book.equity - equity_payment)
    return Maintenance(after, equity_payment + reserve_payment,
                       due - equity_payment - reserve_payment,
                       max(Fraction(0), costs.target(after.capacity) - after.reserve))
