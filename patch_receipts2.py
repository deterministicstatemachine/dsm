import re
with open("dsm_client/deterministic_state_machine/dsm_sdk/src/sdk/receipts.rs", "r") as f:
    lines = f.readlines()

for i, line in enumerate(lines):
    if "return false;" in line:
        lines[i] = line.replace("return false;", f'{{ log::warn!("[verify_receipt_bytes] returning false at line {i+1}"); return false; }}')

with open("dsm_client/deterministic_state_machine/dsm_sdk/src/sdk/receipts.rs", "w") as f:
    f.writelines(lines)
