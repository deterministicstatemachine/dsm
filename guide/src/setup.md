# Set up your machine

Plugging an app in needs Node.js 20 or later, Python 3 if you use the Python client, and `curl`. No Rust, no protobuf compiler, and no copy of the DSM repo: DSM's tools come prebuilt from a release, for Linux (x86-64 and ARM64) and macOS (Apple silicon and Intel). On Windows, use WSL2 with Ubuntu and follow the Ubuntu lines. PostgreSQL is not on the list either: you need it only if you later run storage nodes of your own.

## 1. Install the prerequisites

**macOS**, with [Homebrew](https://brew.sh). macOS already has Python 3 with `venv`, and `curl`.

```bash
brew install node
```

**Ubuntu or Debian.** Ubuntu's own `nodejs` package is older than the Node.js 20 the tools need, so Node comes from NodeSource:

```bash
sudo apt update
sudo apt install -y curl ca-certificates python3-venv
curl -fsSL https://deb.nodesource.com/setup_22.x | sudo -E bash -
sudo apt install -y nodejs
```

These four lines are the ones the newcomer check (`make first-run`) runs on a clean Ubuntu before it follows this path to a payment received.

## 2. Install DSM's tools

Download the release's install script, then run it:

```bash
curl -fsSLO https://github.com/deterministicstatemachine/dsm/releases/download/v0.1.0-beta.4/install.sh
sh install.sh
```

It downloads the release's `SHA256SUMS`, then the app host built for your machine and the developer archive, and checks each against `SHA256SUMS` before it unpacks anything. A file that is missing from it or does not match stops the install, and nothing is changed. Then it installs into `~/.local`:

- `dsm-app-host`: your app's own DSM account.
- `dsm-app`: your app's account from the terminal.
- `dsm-dev-wallet`: a player's wallet in the terminal, to test with no phone.
- `dsm-connect-starter`: the starter app, a page to build your app from.
- The TypeScript and Python clients, as packages you install into your app, under `~/.local/share/dsm/clients`.

What it printed on a Mac:

```text
DSM 0.1.0-beta.4 for macos-arm64, from …
  verified  dsm-app-host-0.1.0-beta.4-macos-arm64.tar.gz  sha256 bfaebcc172e33f0a519bd4e50d42968bb7d67cee2a73eed78712a62c9af4f3eb
  verified  dsm-developer-0.1.0-beta.4.tar.gz  sha256 7ecc867880f1c6feeb82d7b1f48d7c840a58bb6bcfb6593e26360a3afe2cf40e

installed:
  ~/.local/bin/dsm-app-host        dsm-app-host 0.1.0-beta.4
  ~/.local/bin/dsm-app
  ~/.local/bin/dsm-dev-wallet
  ~/.local/bin/dsm-connect-starter
  the clients, to install into your app:
    ~/.local/share/dsm/clients/dsm-app-client-0.1.0-beta.4.tgz
    ~/.local/share/dsm/clients/dsm_app_client-0.1.0b4-py3-none-any.whl
note: ~/.local/bin is not on your PATH; add it (and the same line to your shell's profile):
  export PATH="$HOME/.local/bin:$PATH"
```

`…` is where it downloaded from, and the checksums are that build's; yours name the release's. To check the script itself before you run it, read it: it is short, and it is [`scripts/install.sh`](https://github.com/deterministicstatemachine/dsm/blob/main/scripts/install.sh) in the repo.

## 3. Put the tools on your PATH

If the install said `~/.local/bin` is not on your PATH, add it to this terminal, and the same line to your shell's profile (`~/.zshrc` on macOS, `~/.bashrc` on Ubuntu):

```bash
export PATH="$HOME/.local/bin:$PATH"
```

Then check:

```bash
dsm-app-host --version
```

```text
dsm-app-host 0.1.0-beta.4
```

## 4. A folder for your app

Your app's account lives in the folder you start it from, so start from your app's own folder. To follow this guide, make one:

```bash
mkdir my-app && cd my-app
```

Every command from here on runs in this folder.

## Building from source instead

To work on DSM itself, build the wallet ([next page](wallet.md)), or run storage nodes of your own ([A storage set of your own](own-storage-set.md)), clone the repo and build it. That needs a C toolchain, Git, protobuf's compiler and Rust as well; a JDK 17 is for the Android wallet.

```bash
git clone https://github.com/deterministicstatemachine/dsm.git
cd dsm
make doctor
```

[QUICKSTART.md](https://github.com/deterministicstatemachine/dsm/blob/main/QUICKSTART.md) lists the prerequisites. `make doctor` reads every tool the build needs and says what it found; it changes nothing on your machine. From the repo, the make targets run the same programs as the installed commands, built from your checkout:

| Installed | From the repo |
|---|---|
| `dsm-app up`, `dsm-app down` | `make app-dev`, `make app-dev-down` |
| `dsm-app <command>` | `make app ARGS="<command>"` |
| `dsm-dev-wallet up` | `make dev-wallet` |
| `dsm-dev-wallet <command>` | `make wallet ARGS="<command>"` |
| `DSM_WALLET_NAME=wallet2 dsm-dev-wallet up` | `make dev-wallet2` |
| `DSM_WALLET_NAME=wallet2 dsm-dev-wallet <command>` | `make wallet2 ARGS="<command>"` |
| `dsm-connect-starter` | `make starter` |
| the clients' packages | `clients/typescript`, `clients/python` |

The repo's accounts live in its own `.dsm-dev` folder, so run those from the repo's root.

Next: [The wallet on Android and iOS](wallet.md), or skip straight to [your app's own DSM account](account.md).
