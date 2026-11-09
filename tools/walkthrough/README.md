# Walkthrough videos

The developer walkthrough ("Building apps on DSM") is a short series of videos. Everything in them is scripted, so any shot can be rendered again when the code changes.

| Episode | Terminal shots (VHS) | Phone shots |
|---|---|---|
| 2. Set up your machine | [ep2-setup.tape](tapes/ep2-setup.tape) | the wallet's first run on Android and in the iOS Simulator |
| 3. Your app's own DSM account | [ep3-account.tape](tapes/ep3-account.tape) | none |
| 4. Make an offer, connect a wallet | [ep4-connect.tape](tapes/ep4-connect.tape) | scanning the starter's code and approving, on both |
| 5. Ask the wallet for things | [ep5-requests.tape](tapes/ep5-requests.tape) | approving a payment over the cap, on both |

## Terminal shots

```bash
brew install vhs                                  # renders .tape files to video
make dev-down && make nodes-reset                 # a clean start, as a new developer has
vhs tools/walkthrough/tapes/ep2-setup.tape        # writes ep2-setup.mp4, and so on in episode order
```

Every `make` target a tape types must be a documented target, and CI's developer-path job runs every command the tapes type, in order (`tools/walkthrough/check_tapes.py --run`). A step that breaks fails CI before a video shows it.

## Phone shots

With `make app-dev` and `make starter` running, and the wallets on your local set (`make phones-local`):

```bash
scrcpy --record ep4-android.mp4                                        # Android, straight from the phone
xcrun simctl io booted recordVideo --codec=h264 ep4-ios.mp4            # the iOS Simulator; Ctrl-C stops it
make phones-connect CODE=dsm:connect/v1:...                            # open the starter's code in both wallets
```

## Putting an episode together

Concept slides are rendered from HTML; narration is recorded or generated from each episode's script; `ffmpeg` joins the clips, lays the narration and burns in captions.
