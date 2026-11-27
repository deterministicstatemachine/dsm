# SPDX-License-Identifier: Apache-2.0
from fractions import Fraction as F
import unittest

from retention_budget import Book, Costs, assess_sale, maintain


class RetentionTests(unittest.TestCase):
    def setUp(self):
        # Deliberately explicit scenario assumptions, not network parameters.
        self.costs = Costs("0.01", "0.02", 5, 12, 2)

    def test_unused_capacity_is_funded_as_well_as_held_bytes(self):
        book = Book(100, 200, 0, 100)
        result = assess_sale(book, self.costs, 50, 100, 2, 50)
        self.assertEqual(result.capacity, 350)
        self.assertEqual(result.reserve_top_up, 59)
        self.assertEqual(result.cash_surplus, F(61, 2))
        self.assertTrue(result.funded)

    def test_reserve_cannot_collateralize_execution_exposure(self):
        result = assess_sale(Book(0, 0, 1000, 1), self.costs, 10, 100, 0, 2)
        self.assertGreater(result.cash_surplus, 0)
        self.assertEqual(result.execution_shortfall, 1)
        self.assertFalse(result.funded)

    def test_revenue_shortfall_remains_visible_without_assumed_emissions(self):
        book = Book(100, 0, 0, 100)
        result = assess_sale(book, self.costs, 0, 0, 0, 0)
        self.assertEqual(result.cash_surplus, -30)
        self.assertFalse(result.funded)
        self.assertEqual(book, Book(100, 0, 0, 100))

    def test_maintenance_conserves_cash_and_keeps_all_liabilities(self):
        book = Book(100, 200, 60, 3)
        result = maintain(book, self.costs)
        self.assertEqual(result.expense_paid, 8)
        self.assertEqual(result.book, Book(100, 200, 55, 0))
        self.assertEqual(result.unpaid, 0)
        self.assertEqual(book.reserve + book.equity,
                         result.book.reserve + result.book.equity + result.expense_paid)

    def test_no_demand_eventually_exposes_unpaid_cost_without_deleting_bytes(self):
        book = Book(100, 200, 60, 3)
        total_paid = F(0)
        for _ in range(100):
            result = maintain(book, self.costs)
            total_paid += result.expense_paid
            book = result.book
        self.assertEqual(book.capacity, 300)
        self.assertEqual(book.reserve, self.costs.handover_floor(300))
        self.assertGreater(result.unpaid, 0)
        self.assertEqual(total_paid + book.reserve + book.equity, 63)

    def test_cost_shock_reports_already_underfunded_reserve(self):
        book = Book(100, 0, 5, 0)
        result = maintain(book, self.costs)
        self.assertEqual(result.book.reserve, 5)
        self.assertEqual(result.unpaid, 6)
        self.assertEqual(result.reserve_deficit, 19)

    def test_exact_decimal_inputs_do_not_round_to_float(self):
        costs = Costs("0.000000000000000001", "0.02", 0, 1, 1)
        self.assertEqual(costs.target(3), F(60000000000000003, 10**18))

    def test_invalid_inputs_cannot_fabricate_capacity_or_cash(self):
        for bad in (-1, 0.1, True):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    Book(bad, 0, 0, 0)
                with self.assertRaises(ValueError):
                    Book(0, 0, bad, 0)
        with self.assertRaises(ValueError):
            Costs(1, 1, 1, 0, 1)

    def test_provision_is_counted_once_and_unused_sale_never_mutates_book(self):
        book = Book(100, 0, 24, 0)
        result = assess_sale(book, self.costs, 100, 20, 0, 0)
        self.assertEqual(result.reserve_top_up, 14)
        self.assertEqual(result.cash_surplus, -1)
        self.assertEqual(book, Book(100, 0, 24, 0))


if __name__ == "__main__":
    unittest.main()
