jest.mock('../../../dsm/WebViewBridge', () => {
  const actual = jest.requireActual('../../../dsm/WebViewBridge');
  return {
    ...actual,
    configureLockViaRouter: jest.fn(),
  };
});

jest.mock('../../dsmClient', () => ({
  dsmClient: {
    getPreference: jest.fn(),
    setPreference: jest.fn(),
  },
}));

import { configureLockViaRouter } from '../../../dsm/WebViewBridge';
import { dsmClient } from '../../dsmClient';
import { LOCK_KEYS, saveLockPrefs } from '../lockService';

describe('lockService', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    const preferenceMap = new Map<string, string>([
      [LOCK_KEYS.ENABLED, 'true'],
      [LOCK_KEYS.METHOD, 'combo'],
      [LOCK_KEYS.PIN_HASH, ''],
      [LOCK_KEYS.COMBO_HASH, 'abc'],
      [LOCK_KEYS.TIMEOUT_MS, '60000'],
      [LOCK_KEYS.LOCK_ON_PAUSE, 'false'],
      [LOCK_KEYS.PROMPT_DISMISSED, 'false'],
    ]);
    (dsmClient.getPreference as jest.Mock).mockImplementation(async (key: string) => preferenceMap.get(key) ?? null);
    (dsmClient.setPreference as jest.Mock).mockImplementation(async (key: string, value: string) => {
      preferenceMap.set(key, value);
    });
  });

  test('saveLockPrefs persists prefs and mirrors native lock configuration', async () => {
    await saveLockPrefs({ enabled: true, method: 'combo', lockOnPause: false });

    expect(dsmClient.setPreference).toHaveBeenCalledWith(LOCK_KEYS.ENABLED, 'true');
    expect(dsmClient.setPreference).toHaveBeenCalledWith(LOCK_KEYS.METHOD, 'combo');
    expect(dsmClient.setPreference).toHaveBeenCalledWith(LOCK_KEYS.LOCK_ON_PAUSE, 'false');
    expect(configureLockViaRouter).toHaveBeenCalledWith({
      enabled: true,
      method: 'combo',
      lockOnPause: false,
    });
  });
});
