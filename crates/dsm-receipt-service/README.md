# DSM receipt service

DSM Amendment A17. When a wallet owner has switched **Email receipts** on and
pays someone whose email the wallet holds, the wallet posts a signed request
here and the service emails that person one plain, fixed receipt.

Outside the DSM protocol: the service decides nothing about any transfer,
keeps no record of who was emailed, and logs no address.

## What it checks

- The request is the canonical encoding of a `ReceiptEmailRequestV1`.
- Every field is within its bound and free of control characters; the email is an address.
- The sender device's AK signature over `H(DSM/receipt-email ‖ request with an empty signature)` verifies.
- The sending device and the receiving address are each under their rate.

Open: the signature proves a device asked, not that the device is in the
network's directory. The service does not read the directory yet.

## Configuration (environment)

| Variable | Meaning |
|---|---|
| `RECEIPT_BIND` | listen address, e.g. `0.0.0.0:8090` |
| `RECEIPT_SMTP_URL` | the mail server, e.g. `smtps://USER:PASSWORD@smtp.example.com:465` |
| `RECEIPT_FROM` | sender mailbox, e.g. `DSM Receipts <receipts@example.com>` |
| `RECEIPT_PER_DEVICE` / `RECEIPT_PER_RECIPIENT` | receipts allowed per window |
| `RECEIPT_WINDOW_SECS` | the rate window |

The service listens on plain HTTP; put an HTTPS proxy in front of it. The
wallet names the service in its env config as
`receipt_service_url = "https://receipts.example.com"`.

## Before it can send

A sending domain with SPF and DKIM set up at the mail provider, and that
provider's SMTP credentials. Hosts named by IP (sslip.io) cannot send mail
that arrives.
