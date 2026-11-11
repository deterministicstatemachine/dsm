# A storage set of your own

Everything in this guide runs on the beta network, which is already there. If you would rather depend on no hosted node, run the network's storage set yourself, on your machine: the network's five pinned members, `dsm-node-1` to `dsm-node-5`, as five local nodes. Each is the production storage node program, on its own PostgreSQL database, serving TLS from a certificate authority of the set's own. Nothing then reaches outside your machine.

## 1. PostgreSQL

The set keeps each node's data on a PostgreSQL server on this machine, reached as your own login.

**macOS.** Homebrew's server already has a role named after your login, and takes it on localhost:

```bash
brew install postgresql@17 && brew services start postgresql@17
```

**Linux.** The server takes your login over its socket once it has a role of that name:

```bash
sudo apt install -y postgresql && sudo service postgresql start
sudo -u postgres createuser -s "$(id -un)"
```

PostgreSQL must run with `fsync=on` and `full_page_writes=on`, which are the defaults.

## 2. Your app's account on your set

An account exists only on the set it was made on. If you made accounts on the beta network with the earlier pages, forget them first:

```bash
make dev-reset
```

Then start the set and your app's account on it:

```bash
make app-dev-local
```

`make dev-wallet`, `make dev-wallet2` and the rest follow your account to the set it is on.

## 3. The nodes

`make app-dev-local` starts the nodes. These manage them:

```bash
make nodes-status
```

```bash
make nodes-down
```

```bash
make nodes-up
```

`nodes-status` checks every node's health over verified TLS. `nodes-down` stops the nodes, and `nodes-up` prepares the set the first time and starts every node, on ports 8080 to 8084. `make nodes-reset` stops them, drops their databases, and forgets the set and the accounts made on it.

Everything the set needs lives under `.dsm-dev/net/` in the repo, including the client config wallets use, `dsm_env_config.toml`, which trusts the set's `dev-ca.pem`.

## 4. The phones

Point the wallet on your phones at your set: every adb device (through `adb reverse`) and every booted iOS Simulator. Debug builds only:

```bash
make phones-local
```

A wallet that already made its identity on another set keeps it there, so clear the app's data first. On Android, `adb shell pm clear com.dsm.wallet`, then grant its Bluetooth permissions again; on iOS, delete the app and run `make ios-simulator-run`. The same holds after `make nodes-reset`: it makes a new set with a new certificate authority, so clear the wallets and run `make phones-local` again, or they refuse every node (`invalid peer certificate`).

## Back to the beta network

```bash
make dev-reset
```

This forgets the accounts on this machine, and your local set if they were on it. The next `make app-dev` makes new ones on the beta network.

Next: [Grants, commands and routes](reference.md).
