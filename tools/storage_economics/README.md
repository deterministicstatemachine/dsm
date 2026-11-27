# Commercial retention budget

Run `python3 -m unittest discover -s tools/storage_economics -v` (Python 3.11+).

This offline accounting tool recovers the useful retention analysis from the
local, withdrawn `tools/era_economics/operator_lifecycle.py` experiment. It counts
held bytes and all unused sold capacity, separates retention reserves from
execution equity, accounts for provisions once, and exposes cash shortfalls
without deleting evidence or assuming new customers or emission income.

Every cost, projection horizon, revenue and execution exposure is an explicit
scenario input. Costs include whichever replicas the operator is budgeting for;
the tool does not assume a replication count or fetch a vendor's current prices.
Values use exact fractions. Reporting periods and currency conversion assumptions
are commercial analysis only and enter no protocol objects or decisions.

`assess_sale` reports funding at the supplied revenue; it never sets a tariff,
admits a write, or changes credits. `maintain` projects paid and unpaid expense
while preserving byte liabilities and the assumed handover reserve. An existing
reserve deficit remains visible. A funded finite projection is not a promise of
permanent solvency, a proof of backing, or evidence of a completed handover.

The governing boundaries remain storage specification §§15–20 (fixed committed
credit pricing, retention, free verification, and exit by real handover) and SoFi
S18/S32 (two beta ERA decimals; fixed supply; production occupancy-based release
from its own genesis; beta replacement without migration). Core remains the
protocol authority. The tool has no imports into Core, SDK, nodes or the wallet.

The withdrawn burn rebate, 4,096 source lanes, eight-decimal ERA, operator-chosen
protocol prices, fee percentages and vesting changes are excluded. No occupancy
emission mechanism is implemented: S32 explicitly forbids premature implementation.
