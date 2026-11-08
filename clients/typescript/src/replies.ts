// SPDX-License-Identifier: MIT OR Apache-2.0

// Taking the one answer a route gives out of its Envelope, and refusing any
// other: a route that answers with something else is an error to see, never a
// value to guess at.

import type { Envelope, ConnectReplyV1 } from "./generated/dsm_app_pb.js";
import { IngressError } from "./ingress.js";

type Payload = Envelope["payload"];
type PayloadCase = Exclude<Payload["case"], undefined>;
type PayloadOf<C extends PayloadCase> = Extract<Payload, { case: C }>["value"];

export function payload<C extends PayloadCase>(
  route: string,
  envelope: Envelope,
  expected: C,
): PayloadOf<C> {
  if (envelope.payload.case !== expected) {
    throw new IngressError(
      route,
      0,
      `answered with ${String(envelope.payload.case)}, not ${expected}`,
    );
  }
  return envelope.payload.value as PayloadOf<C>;
}

type Reply = ConnectReplyV1["reply"];
type ReplyCase = Exclude<Reply["case"], undefined>;
type ReplyOf<C extends ReplyCase> = Extract<Reply, { case: C }>["value"];

/** The Connect reply a `connect.*` route answers with. */
export function connectReply<C extends ReplyCase>(
  route: string,
  envelope: Envelope,
  expected: C,
): ReplyOf<C> {
  const reply = payload(route, envelope, "connectReply").reply;
  if (reply.case !== expected) {
    throw new IngressError(route, 0, `answered with ${String(reply.case)}, not ${expected}`);
  }
  return reply.value as ReplyOf<C>;
}
