# Bringing up the public storage set

What the owner does to bring five independent operators up as the public beta storage set. Operators follow [RUN_A_NODE.md](../../RUN_A_NODE.md) and never talk to each other.

The owner's own five nodes are the private test fleet and aren't part of this.

## 1. Publish the node image

Operators download a ready-made image. This workflow only runs when someone starts it:

```bash
gh workflow run storage-node-image.yml --repo deterministicstatemachine/dsm -f commit=<full commit>
```

Test that image on the private fleet (`ghcr.io/deterministicstatemachine/dsm-storage-node:<full commit>`). Then make that exact image the one public nodes use:

```bash
gh workflow run storage-node-image.yml --repo deterministicstatemachine/dsm -f commit=<full commit> -f promote=true
```

The first time, make the package public: on GitHub, open the organization's **Packages** page, then **dsm-storage-node**, **Package settings**, **Change visibility**. Operators can't download it until then.

## 2. Send each person their line

Give each person a different seat number, 1 to 5:

```
curl -fsSL https://raw.githubusercontent.com/deterministicstatemachine/dsm/main/dsm_storage_node/deploy/operator/launch_on_google_cloud.sh | bash -s -- start <seat>
```

Send the guide with it: `dsm_storage_node/RUN_A_NODE.md`.

## 3. Take in each code

Each person sends back one `DSMNODE1:` code. Make sure it really comes from the person you gave that seat to, because a code decides which CA the app will trust for that seat. For each one:

```bash
python3 dsm_storage_node/deploy/operator/assemble_public_set.py add 'DSMNODE1:...'
```

This refuses a code unless its node is live and serving that seat's certificate from that code's CA. `status` shows who is still missing.

## 4. Publish the member list

Once all five are in:

```bash
python3 dsm_storage_node/deploy/operator/assemble_public_set.py build
```

It prints the `gh release create` command that publishes the list. Each node checks for it every five minutes, takes it once and never changes it again. A list that doesn't match a node exactly is refused.

**The set is immutable.** Publishing is the moment it becomes final, so check all five seats first.

Then confirm the five reached each other:

```bash
python3 dsm_storage_node/deploy/operator/assemble_public_set.py check
```

## 5. Build the public app

`build` also writes two files to `~/.dsm-public-beta/public/`:

- `dsm_env_config.nodes.toml`: the `[[nodes]]` entries for the app's env config
- `core_pins.txt`: the pinned members for `dsm::economic::register` and the values `dsm_sdk::sdk::storage_set` renders

Phones on the public set need an app built with these. Builds for the private fleet keep the private pins.

## Updates

Test on the private fleet, promote the image (step 1), then ask each operator to run the update line from the guide. Nothing updates by itself.

## What stays with the owner

- Assigning seats and accepting codes. Whoever does this decides who the five operators are.
- Publishing the member list.
- Which image `:beta` points to, which operators run when they update.

Each operator's key is theirs alone, so the owner can't pose as a node.
