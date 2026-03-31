/* eslint-disable no-console */
// Simple environment-aware logger. No-ops in production, console in development.
const isProd = typeof process !== 'undefined' && process.env.NODE_ENV === 'production';

type LogArgs = unknown[];

const noop = (..._args: LogArgs) => {};

export const logger = {
  debug: isProd ? noop : (...args: LogArgs) => console.debug(...args),
  info: isProd ? noop : (...args: LogArgs) => console.info(...args),
  warn: isProd ? noop : (...args: LogArgs) => console.warn(...args),
  error: isProd ? noop : (...args: LogArgs) => console.error(...args),
};

export default logger;
