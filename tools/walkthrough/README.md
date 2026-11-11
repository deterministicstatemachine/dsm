# Walkthrough tapes

The developer walkthrough ("Plug your app into DSM"), step by step, as scripted terminal sessions. What a tape types is what a developer types, and CI runs every command, so a step that breaks fails CI before a developer meets it.

| Step | Tape |
|---|---|
| Set up your machine | [ep2-setup.tape](tapes/ep2-setup.tape) |
| Your app's own DSM account | [ep3-account.tape](tapes/ep3-account.tape) |
| Make an offer, connect a wallet | [ep4-connect.tape](tapes/ep4-connect.tape) |
| Ask the wallet for things | [ep5-requests.tape](tapes/ep5-requests.tape) |
| Trades, matches and duels (advanced) | [ep6-advanced.tape](tapes/ep6-advanced.tape) |

A tape is in VHS's tape format: each `Type` line is a command, run with the `Enter` after it. [check_tapes.py](check_tapes.py) checks them.

Every `make` target a tape types is a documented target of the Makefile (`make help` lists it):

```bash
python3 tools/walkthrough/check_tapes.py
```

With `--run`, it also runs every command the tapes type, in order, in one bash session from the repo root, and fails on the first command that fails. CI's developer-path job runs it after `make developer-path`, on the local storage set that leaves running. A command no CI runner can run is named in `NOT_RUN` in check_tapes.py, with why.
