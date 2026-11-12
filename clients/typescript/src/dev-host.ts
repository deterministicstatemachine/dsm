// SPDX-License-Identifier: MIT OR Apache-2.0

// An account on this machine run by an installed dsm-app-host, on the beta
// network: what `make app-dev` and `make dev-wallet` do from the DSM repo,
// for a machine with the host installed and no repo (`dsm-app up`,
// `dsm-dev-wallet up`).
//
// The layout is the repo's (scripts/app_dev.sh), so `localAccount("app")` and
// `local_app()` find it the same way. Under `.dsm-dev/<name>/` (DSM_DEV_DIR,
// else the nearest `.dsm-dev` above the working directory, else a new one in
// it):
//
//   data/                   the account's state, sealed seed and RECOVERY_MNEMONIC
//   ingress/ingress-token   this launch's ingress secret (only your server reads it)
//   ingress-url             the address the ingress listens on
//   relay-url               the address wallets reach the relay on
//   host.log, host.pid
//
// The host joins the beta network with the config it carries
// (`dsm-app-host --network beta`). DSM_APP_HOST names another binary than
// the `dsm-app-host` on PATH.

import { spawn } from "node:child_process";
import { closeSync, openSync } from "node:fs";
import { access, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { Ingress } from "./ingress.js";
import { findDevDir, type LocalAccountName } from "./local.js";

const PORTS: Record<LocalAccountName, { ingress: number; relay: number }> = {
  app: { ingress: 8787, relay: 8443 },
  wallet: { ingress: 8788, relay: 8444 },
  wallet2: { ingress: 8789, relay: 8445 },
};

interface Paths {
  dev: string;
  dir: string;
  ingressUrl: string;
  relayUrl: string;
}

async function exists(path: string): Promise<boolean> {
  try {
    await access(path);
    return path.length > 0;
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code === "ENOENT") return path.length === 0;
    throw e;
  }
}

async function paths(name: LocalAccountName, create: boolean): Promise<Paths> {
  const dev = await findDevDir(create);
  const ports = PORTS[name];
  return {
    dev,
    dir: join(dev, name),
    ingressUrl: `http://127.0.0.1:${ports.ingress}`,
    relayUrl: `https://127.0.0.1:${ports.relay}`,
  };
}

async function hostPid(p: Paths): Promise<number | undefined> {
  const file = join(p.dir, "host.pid");
  if (!(await exists(file))) return undefined;
  const pid = Number((await readFile(file, "utf8")).trim());
  if (!Number.isSafeInteger(pid) || pid <= 0) return undefined;
  try {
    process.kill(pid, 0);
    return pid;
  } catch {
    return undefined;
  }
}

async function ready(p: Paths): Promise<boolean> {
  const token = join(p.dir, "ingress", "ingress-token");
  if (!(await exists(token))) return false;
  try {
    const ingress = await Ingress.fromSecretFile(p.ingressUrl, token);
    await ingress.activity(0n);
    return true;
  } catch {
    return false;
  }
}

function show(tool: string, name: LocalAccountName, p: Paths): void {
  console.log(`[${tool}] ${name} account running`);
  console.log(`  storage set:    the beta network (carried in dsm-app-host)`);
  console.log(`  ingress:        ${p.ingressUrl}   (your server calls this)`);
  console.log(`  ingress secret: ${join(p.dir, "ingress", "ingress-token")}`);
  console.log(`  relay:          ${p.relayUrl}   (wallets reach this)`);
  console.log(`  recovery:       ${join(p.dir, "data", "RECOVERY_MNEMONIC")}`);
  console.log(`  log:            ${join(p.dir, "host.log")}`);
}

async function lastLines(file: string, count: number): Promise<string> {
  const text = await readFile(file, "utf8").catch(() => "");
  return text.trimEnd().split("\n").slice(-count).join("\n");
}

/** Start the account (a new one on the first run), and wait until its ingress answers. */
export async function up(tool: string, name: LocalAccountName): Promise<void> {
  const p = await paths(name, true);
  const setFile = join(p.dev, "set");
  if (await exists(setFile)) {
    const recorded = (await readFile(setFile, "utf8")).trim();
    if (recorded !== "beta") {
      throw new Error(
        `the accounts in ${p.dev} are on a storage set of your own (made from the DSM repo, make app-dev-local), ` +
          "and an account exists only on the set it was made on; an installed host joins the beta network. " +
          "Run them from the repo, or make them here in another folder.",
      );
    }
  }
  if ((await hostPid(p)) !== undefined && (await ready(p))) {
    console.log(`[${tool}] ${name} already running`);
    show(tool, name, p);
    return;
  }
  await mkdir(join(p.dir, "data"), { recursive: true, mode: 0o700 });
  await mkdir(join(p.dir, "ingress"), { recursive: true, mode: 0o700 });
  await writeFile(setFile, "beta\n");
  await rm(join(p.dir, "ingress", "ingress-token"), { force: true });
  await writeFile(join(p.dir, "ingress-url"), `${p.ingressUrl}\n`);
  await writeFile(join(p.dir, "relay-url"), `${p.relayUrl}\n`);

  const binary = process.env.DSM_APP_HOST ?? "dsm-app-host";
  const logFile = join(p.dir, "host.log");
  const log = openSync(logFile, "w");
  const ports = PORTS[name];
  const child = spawn(
    binary,
    [
      "--data-dir", join(p.dir, "data"),
      "--ingress-secret-dir", join(p.dir, "ingress"),
      "--network", "beta",
      "--game-bind", `127.0.0.1:${ports.ingress}`,
      "--relay-bind", `127.0.0.1:${ports.relay}`,
      "--relay-endpoint", p.relayUrl,
      "--relay-name", "127.0.0.1",
    ],
    { detached: true, stdio: ["ignore", log, log], env: { ...process.env, RUST_LOG: process.env.RUST_LOG ?? "info" } },
  );
  try {
    await new Promise<void>((resolve, reject) => {
      child.once("spawn", resolve);
      child.once("error", reject);
    });
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code === "ENOENT") {
      throw new Error(
        `${binary} is not on PATH: install it (the guide's "Set up your machine"), or name it with DSM_APP_HOST`,
      );
    }
    throw e;
  } finally {
    closeSync(log);
  }
  child.unref();
  await writeFile(join(p.dir, "host.pid"), `${child.pid}\n`);

  for (let i = 0; i < 240; i++) {
    if (await ready(p)) {
      show(tool, name, p);
      return;
    }
    if ((await hostPid(p)) === undefined) {
      throw new Error(`the ${name} host stopped; its log:\n${await lastLines(logFile, 30)}`);
    }
    await new Promise((r) => setTimeout(r, 500));
  }
  throw new Error(`the ${name} host did not answer in two minutes; its log is ${logFile}`);
}

/** Stop the account's host. */
export async function down(tool: string, name: LocalAccountName): Promise<void> {
  const p = await paths(name, false);
  const pid = await hostPid(p);
  if (pid !== undefined) {
    process.kill(pid, "SIGTERM");
    console.log(`[${tool}] stopped the ${name} host`);
  }
  await rm(join(p.dir, "host.pid"), { force: true });
}

/** Whether the account is running; it fails when it is not. */
export async function status(tool: string, name: LocalAccountName): Promise<void> {
  const p = await paths(name, false);
  if ((await hostPid(p)) !== undefined && (await ready(p))) {
    show(tool, name, p);
    return;
  }
  throw new Error(`[${tool}] the ${name} host is not running: ${tool} up`);
}
