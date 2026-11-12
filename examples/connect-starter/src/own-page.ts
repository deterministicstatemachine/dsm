// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Who this server answers. It acts with the app's DSM account for whoever
// calls it, so it answers its own page and nothing else on the machine.
//
// Your own app's server needs the same three checks, or a sign-in of its own:
// the DSM host refuses other pages, but a server in front of it that takes
// any caller acts for all of them.

/** What of a request says who sent it. */
export interface Caller {
  method: string | undefined;
  host: string | undefined;
  origin: string | undefined;
  contentType: string | undefined;
}

/**
 * Whether a request is this server's own page talking to it, the server
 * listening on 127.0.0.1 at `port`:
 *
 * - `Host` must be this server's address, by either of its names. A page
 *   elsewhere that points a name of its own at 127.0.0.1 arrives with that
 *   name as `Host`.
 * - `Origin`, when the browser sends one, must be this server. Another site's
 *   page sends its own.
 * - A POST must be `application/json`. A page on another site cannot send
 *   that without the browser asking this server first, and this server never
 *   says yes.
 */
export function fromOwnPage(caller: Caller, port: number): boolean {
  const own = [`127.0.0.1:${port}`, `localhost:${port}`];
  if (caller.host === undefined || !own.includes(caller.host.toLowerCase())) return false;
  const origin = caller.origin;
  if (origin !== undefined && !own.some((host) => origin.toLowerCase() === `http://${host}`)) return false;
  if (caller.method === "POST") {
    const type = (caller.contentType ?? "").split(";")[0].trim().toLowerCase();
    if (type !== "application/json") return false;
  }
  return true;
}
