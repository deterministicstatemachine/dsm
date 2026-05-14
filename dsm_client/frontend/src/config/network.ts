// Centralized network ID resolution (strict)
// Single source of truth: dsm_network_config.json
// - Uses client.mode if present; otherwise _generated.environment
// - If neither exists or is empty, throws an Error (fail fast)

export function getNetworkId(): string {
  // Using require to prevent TS static analysis complaining if JSON absent
  // eslint-disable-next-line @typescript-eslint/no-require-imports
  const netJson = require('../../dsm_network_config.json');
  const clientMode = netJson?.client?.mode;
  const generated = netJson?._generated?.environment;
  const picked = clientMode ?? generated;

  if (typeof picked === 'string' && picked.length > 0) {
    return picked;
  }

  throw new Error('networkId missing: expected client.mode or _generated.environment in dsm_network_config.json');
}
