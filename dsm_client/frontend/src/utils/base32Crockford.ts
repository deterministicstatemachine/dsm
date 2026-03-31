// SPDX-License-Identifier: Apache-2.0
// IMPORTANT:
// This module is intentionally disabled.
//
// The frontend MUST use the single canonical Crockford Base32 implementation:
//   `src/utils/textId.ts`
//
// If you see an import of `../utils/base32Crockford`, replace it with:
//   `../utils/textId` and use encodeBase32Crockford/decodeBase32Crockford.

throw new Error(
  'Do not import src/utils/base32Crockford.ts. Use src/utils/textId.ts (single Crockford Base32 source).'
);
