// SPDX-License-Identifier: MIT OR Apache-2.0

// The accounts `make app-dev` and `make dev-wallet` run on this machine
// (scripts/app_dev.sh), or `dsm-app up` and `dsm-dev-wallet up` with an
// installed dsm-app-host (dev-host.ts). Each writes, under `.dsm-dev/<name>/`:
//
//   ingress-url            the address its ingress listens on
//   ingress/ingress-token  this launch's secret
//
// Outside the repo, name them yourself: DSM_INGRESS_URL and
// DSM_INGRESS_SECRET_FILE.

import { access, mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { AppAccount, WalletAccount } from "./account.js";
import { Ingress } from "./ingress.js";

/** "app" is your application's account; "wallet" and "wallet2" are players' wallets in the terminal. */
export type LocalAccountName = "app" | "wallet" | "wallet2";

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

/**
 * The `.dsm-dev` directory: DSM_DEV_DIR, or the nearest one above the working
 * directory; with `create`, a new one in the working directory when there is none.
 */
export async function findDevDir(create = false): Promise<string> {
  const named = process.env.DSM_DEV_DIR;
  if (named !== undefined && named.length > 0) {
    if (create) await mkdir(resolve(named), { recursive: true });
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
      if (create) {
        const made = join(process.cwd(), ".dsm-dev");
        await mkdir(made, { recursive: true, mode: 0o700 });
        // The directory holds an account's recovery phrase and its ingress
        // secret, and it is made inside the app's own folder: git is told to
        // leave everything in it alone, so `git add -A` never stages them.
        await writeFile(join(made, ".gitignore"), "*\n", { flag: "wx" }).catch((e: NodeJS.ErrnoException) => {
          if (e.code !== "EEXIST") throw e;
        });
        return made;
      }
      throw new Error(
        "no .dsm-dev directory above here: run `dsm-app up` in your app's folder (or `make app-dev` in the DSM repo), or set DSM_DEV_DIR",
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
  const dir = join(await findDevDir(), name);
  const recorded = (await readFile(join(dir, "ingress-url"), "utf8")).trim();
  return Ingress.fromSecretFile(recorded, join(dir, "ingress", "ingress-token"));
}

/** The account `dsm-app up` or `make app-dev` (app), or `dsm-dev-wallet up` or `make dev-wallet` (wallet, wallet2), runs. */
export async function localAccount(name: "app"): Promise<AppAccount>;
export async function localAccount(name: "wallet" | "wallet2"): Promise<WalletAccount>;
export async function localAccount(name: LocalAccountName): Promise<AppAccount | WalletAccount> {
  const ingress = await localIngress(name);
  return name === "app" ? new AppAccount(ingress) : new WalletAccount(ingress);
}
