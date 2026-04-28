// SPDX-License-Identifier: Apache-2.0
// Shared logger adapter for the WebViewBridge modules. Centralized to avoid
// duplicating the same boilerplate across every sub-module.

import { logger as appLogger } from "../../utils/logger";

export const log = {
  info: (...args: unknown[]) => appLogger.info(...args),
  warn: (...args: unknown[]) => appLogger.warn(...args),
  error: (...args: unknown[]) => appLogger.error(...args),
  debug: (...args: unknown[]) => appLogger.debug(...args),
  log: (...args: unknown[]) => appLogger.info(...args),
};
