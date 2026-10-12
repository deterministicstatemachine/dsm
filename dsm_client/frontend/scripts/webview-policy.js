// SPDX-License-Identifier: Apache-2.0
/*
 The WebView's Content-Security-Policy, read from the page the APK ships
 (pre-audit item 13). Every problem with it, by name; none is a pass.

 - No 'unsafe-eval' anywhere, and no 'unsafe-inline' for scripts: script
   runs only from the app's own files and from the inline scripts the page
   carries, each admitted by the SHA-256 of its exact text.
 - Every inline script in the page is one of those hashes, so the policy
   blocks none of the page's own code; no hash names a script the page lacks.
 - The page cannot be re-based, cannot post a form, and cannot frame
   anything (base-uri, form-action, frame-src 'none').
*/
const crypto = require('crypto');

function directives(html) {
  const meta = html.match(/<meta\s+http-equiv="Content-Security-Policy"\s+content="([^"]*)"/i);
  if (!meta) return null;
  const parsed = new Map();
  for (const part of meta[1].split(';')) {
    const [name, ...sources] = part.trim().split(/\s+/);
    if (name) parsed.set(name.toLowerCase(), sources);
  }
  return parsed;
}

function inlineScriptHashes(html) {
  // Tag names are case-insensitive, and a closing tag may carry whitespace:
  // every spelling a browser reads as a script is counted.
  return [...html.matchAll(/<script\b([^>]*)>([\s\S]*?)<\/script\b[^>]*>/gi)]
    .filter(([, attributes]) => !/\bsrc\s*=/i.test(attributes))
    .map(([, , text]) => `'sha256-${crypto.createHash('sha256').update(text, 'utf8').digest('base64')}'`);
}

function policyProblems(html) {
  const policy = directives(html);
  if (!policy) return ['the page carries no Content-Security-Policy'];
  const problems = [];
  for (const [name, sources] of policy) {
    if (sources.includes("'unsafe-eval'")) problems.push(`${name} admits 'unsafe-eval'`);
  }
  // Without script-src the policy falls back to default-src for scripts.
  const scriptSrc = policy.get('script-src') || policy.get('default-src');
  if (!scriptSrc) return [...problems, 'the policy names neither script-src nor default-src'];
  if (scriptSrc.includes("'unsafe-inline'")) problems.push("script-src admits 'unsafe-inline'");
  if (scriptSrc.some((source) => source.startsWith('__'))) {
    problems.push(`script-src still names the build's token: ${scriptSrc.join(' ')}`);
  }
  const pageHashes = inlineScriptHashes(html);
  for (const hash of pageHashes) {
    if (!scriptSrc.includes(hash)) problems.push(`an inline script is not admitted by its hash ${hash}`);
  }
  for (const source of scriptSrc.filter((s) => s.startsWith("'sha256-"))) {
    if (!pageHashes.includes(source)) problems.push(`script-src admits ${source}, which no inline script has`);
  }
  for (const name of ['base-uri', 'form-action', 'frame-src', 'object-src']) {
    const sources = policy.get(name);
    if (!sources || sources.join(' ') !== "'none'") problems.push(`${name} is not 'none'`);
  }
  return problems;
}

module.exports = { policyProblems };
