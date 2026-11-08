# DSM receipt service

DSM Amendment A17. When a wallet owner has switched **Email receipts** on and
pays someone whose email the wallet holds, the wallet posts a signed request
here and the service emails that person one plain, fixed receipt.

Outside the DSM protocol: the service decides nothing about any transfer,
keeps no record of who was emailed, and logs no address.

## What it checks

- The request is the canonical encoding of a `ReceiptEmailRequestV1`.
- Every field is within its bound and free of control characters; the email is a bare address
  (`user@domain.tld`: no display name, nothing before or after it), and the receipt is sent to
  exactly that address.
- The sender device's AK signature over `H(DSM/receipt-email ‖ request with an empty signature)` verifies.
- The sending device and the receiving address are each under their rate. A device is counted by
  the key its request is signed under (the device id is not bound by anything the request
  carries); an address is counted case-insensitively and without a `+` subaddress, so spellings
  of one inbox share its rate.

It works on at most 64 requests at once (one more is answered `503`), answers each within 30 s
(`408` after), and closes a connection that has not sent a request's headers within 10 s. It logs
why a receipt was not sent by the mail server's status code alone: the server's own text often
quotes the address.

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
