import re
with open("dsm_client/deterministic_state_machine/dsm_sdk/src/sdk/receipts.rs", "r") as f:
    text = f.read()

def repl(m):
    return f'{{ log::warn!("[verify_receipt_bytes] returning false"); return false; }}'

text = text.replace('return false;', '{ log::warn!("[verify_receipt_bytes] returning false at line..."); return false; }')

with open("dsm_client/deterministic_state_machine/dsm_sdk/src/sdk/receipts.rs", "w") as f:
    f.write(text)

