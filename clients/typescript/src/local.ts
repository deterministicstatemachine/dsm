// SPDX-License-Identifier: MIT OR Apache-2.0

// The accounts `make app-dev` and `make dev-wallet` run on this machine
// (scripts/app_dev.sh). Each writes, under `.dsm-dev/<name>/`:
//
//   ingress-url            the address its ingress listens on
//   ingress/ingress-token  this launch's secret
//
// Outside the repo, name them yourself: DSM_INGRESS_URL and
// DSM_INGRESS_SECRET_FILE.

import { access, readFile } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { AppAccount, WalletAccount } from "./account.js";
import { Ingress } from "./ingress.js";

export type LocalAccountName = "app" | "wallet";

async function exists(path: string): Promise<boolean> {
  try {
    await access(path);
    return !!path;
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code === "ENOENT") {
      return !path;
    }
    throw e;
  }
}

/** The `.dsm-dev` directory: DSM_DEV_DIR, or the nearest one above the working directory. */
async function devDir(): Promise<string> {
  const named = process.env.DSM_DEV_DIR;
  if (named !== undefined && named.length > 0) {
    return resolve(named);
  }
  let dir = process.cwd();
  for (;;) {
    const candidate = join(dir, ".dsm-dev");
    if (await exists(candidate)) {
      return candidate;
    }
    const parent = dirname(dir);
    if (parent === dir) {
      throw new Error(
        "no .dsm-dev directory above here: run `make app-dev` in the DSM repo, or set DSM_DEV_DIR",
      );
    }
    dir = parent;
  }
}

async function localIngress(name: LocalAccountName): Promise<Ingress> {
  const url = process.env.DSM_INGRESS_URL;
  const secretFile = process.env.DSM_INGRESS_SECRET_FILE;
  if (name === "app" && url !== undefined && secretFile !== undefined) {
    return Ingress.fromSecretFile(url, secretFile);
  }
  const dir = join(await devDir(), name);
  const recorded = (await readFile(join(dir, "ingress-url"), "utf8")).trim();
  return Ingress.fromSecretFile(recorded, join(dir, "ingress", "ingress-token"));
}

/** The account `make app-dev` (app) or `make dev-wallet` (wallet) runs. */
export async function localAccount(name: "app"): Promise<AppAccount>;
export async function localAccount(name: "wallet"): Promise<WalletAccount>;
export async function localAccount(name: LocalAccountName): Promise<AppAccount | WalletAccount> {
  const ingress = await localIngress(name);
  return name === "app" ? new AppAccount(ingress) : new WalletAccount(ingress);
}
