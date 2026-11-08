// SPDX-License-Identifier: MIT OR Apache-2.0

// The local ingress a dsm-app-host serves (crates/dsm-app-host/src/game.rs):
//
//   POST /ingress          an IngressRequest, answered with an IngressResponse;
//                          a call that changes the account is recorded
//   POST /ingress/quiet    the same, never recorded (what you poll)
//   GET  /activity/{after} the record after `after` (AppHostActivityV1)
//
// It listens on a loopback address only. Every request carries the secret the
// host wrote for this launch, as `Authorization: Bearer <secret>`. Keep the
// secret on your server: a browser page must never hold it.
//
// This file carries bytes. Every rule is the SDK's, in Rust.

import { readFile } from "node:fs/promises";
import type { Message } from "@bufbuild/protobuf";
import {
  AppHostActivityV1,
  ArgPack,
  Codec,
  Envelope,
  IngressRequest,
  IngressResponse,
  RouterInvokeOp,
  RouterQueryOp,
} from "./generated/dsm_app_pb.js";

/** The envelope framing byte the SDK puts before every Envelope v3. */
const ENVELOPE_V3_FRAME = 0x03;

/** Why a call through the ingress did not succeed. */
export class IngressError extends Error {
  /**
   * @param route  the route called, or the HTTP path
   * @param code   the SDK's error code (1 invalid input, 2 refused by the route,
   *               5 not ready), or the HTTP status when the host refused it
   * @param detail what the SDK or the host said
   */
  constructor(
    readonly route: string,
    readonly code: number,
    readonly detail: string,
  ) {
    super(`${route}: ${detail} (code ${code})`);
    this.name = "IngressError";
  }
}

export interface IngressOptions {
  /** The ingress address, e.g. http://127.0.0.1:8787 */
  url: string;
  /** This launch's secret: the contents of `<ingress-secret-dir>/ingress-token`. */
  secret: string;
}

/** A call's kind: an invoke may change the account; a query only reads it. */
export type CallKind = "invoke" | "query";

export class Ingress {
  readonly url: string;
  readonly #secret: string;

  constructor(options: IngressOptions) {
    this.url = options.url.replace(/\/+$/, "");
    this.#secret = options.secret;
  }

  /** An ingress whose secret is read from the file the host wrote. */
  static async fromSecretFile(url: string, secretFile: string): Promise<Ingress> {
    const secret = await readFile(secretFile, "utf8");
    if (secret.length === 0) {
      throw new Error(`${secretFile} is empty: is the host running?`);
    }
    return new Ingress({ url, secret });
  }

  #headers(contentType: string | undefined): Record<string, string> {
    const headers: Record<string, string> = { authorization: `Bearer ${this.#secret}` };
    if (contentType !== undefined) {
      headers["content-type"] = contentType;
    }
    return headers;
  }

  async #post(path: string, body: Uint8Array, route: string): Promise<Uint8Array> {
    const response = await fetch(this.url + path, {
      method: "POST",
      headers: this.#headers("application/x-protobuf"),
      body,
    });
    const bytes = new Uint8Array(await response.arrayBuffer());
    if (!response.ok) {
      throw new IngressError(route, response.status, new TextDecoder().decode(bytes));
    }
    return bytes;
  }

  /**
   * Call a route. `args` is the route's own request message (or nothing, for a
   * route that takes none). Returns the Envelope the route answered with.
   */
  async call(
    kind: CallKind,
    method: string,
    args: Message | undefined,
    options: { quiet?: boolean } = {},
  ): Promise<Envelope> {
    const body = args === undefined ? new Uint8Array(0) : args.toBinary();
    const pack = new ArgPack({ codec: Codec.PROTO, body }).toBinary();
    const request =
      kind === "invoke"
        ? new IngressRequest({
            operation: { case: "routerInvoke", value: new RouterInvokeOp({ method, args: pack }) },
          })
        : new IngressRequest({
            operation: { case: "routerQuery", value: new RouterQueryOp({ method, args: pack }) },
          });
    const path = options.quiet ? "/ingress/quiet" : "/ingress";
    const raw = await this.#post(path, request.toBinary(), method);
    const response = IngressResponse.fromBinary(raw);
    switch (response.result.case) {
      case "error":
        throw new IngressError(method, response.result.value.code, response.result.value.message);
      case "okBytes": {
        const framed = response.result.value;
        if (framed.length === 0 || framed[0] !== ENVELOPE_V3_FRAME) {
          throw new IngressError(method, 0, "the answer is not a framed Envelope v3");
        }
        const envelope = Envelope.fromBinary(framed.subarray(1));
        if (envelope.payload.case === "error") {
          throw new IngressError(method, envelope.payload.value.code, envelope.payload.value.message);
        }
        return envelope;
      }
      default:
        throw new IngressError(method, 0, "the ingress answered with neither a result nor an error");
    }
  }

  /** The record of what calls and wallets did to this account, after `after`. */
  async activity(after: bigint = 0n): Promise<AppHostActivityV1> {
    const path = `/activity/${after}`;
    const response = await fetch(this.url + path, { headers: this.#headers(undefined) });
    const bytes = new Uint8Array(await response.arrayBuffer());
    if (!response.ok) {
      throw new IngressError(path, response.status, new TextDecoder().decode(bytes));
    }
    return AppHostActivityV1.fromBinary(bytes);
  }
}
