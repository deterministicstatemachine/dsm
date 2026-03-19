/* eslint-disable @typescript-eslint/no-explicit-any */
import { DsmClient } from '../../services/dsmClient';
import { hasIdentity } from '../../utils/identity';
import * as dsmIndex from '../../dsm/index';
import { encodeBase32Crockford } from '../../utils/textId';

jest.mock('../../utils/identity', () => ({
  hasIdentity: jest.fn(),
}));

jest.mock('../../dsm/index', () => ({
  getContacts: jest.fn(),
  addContact: jest.fn(),
  sendOnlineTransfer: jest.fn(),
  offlineSend: jest.fn(),
  acceptOfflineTransfer: jest.fn(),
  commitOfflineTransfer: jest.fn(),
  rejectOfflineTransfer: jest.fn(),
  getLogicalTick: jest.fn(),
  getWalletHistory: jest.fn(),
}));

const mockedHasIdentity = hasIdentity as jest.MockedFunction<typeof hasIdentity>;
const mockedDsm = dsmIndex as jest.Mocked<typeof dsmIndex>;

describe('DsmClient identity gating and bridge passthrough', () => {
  let client: DsmClient;

  beforeEach(() => {
    jest.clearAllMocks();
    client = new DsmClient();
  });

  test('getContacts throws when identity missing', async () => {
    mockedHasIdentity.mockResolvedValue(false);
    await expect(client.getContacts()).rejects.toThrow(/Identity not initialized/);
    expect(mockedDsm.getContacts).not.toHaveBeenCalled();
  });

  test('addContact returns {ok:false} when identity missing', async () => {
    mockedHasIdentity.mockResolvedValue(false);
    const keyB32 = encodeBase32Crockford(new Uint8Array(64));
    const genesisB32 = encodeBase32Crockford(new Uint8Array(32));
    const deviceB32 = encodeBase32Crockford(new Uint8Array(32));
    const res = await client.addContact({
      alias: 'a',
      genesisHash: genesisB32,
      deviceId: deviceB32,
      signingPublicKey: keyB32,
      storageNodes: ['http://localhost:8080', 'http://localhost:8081', 'http://localhost:8082'],
    });
    expect(res).toEqual({ ok: false });
    expect(mockedDsm.addContact).not.toHaveBeenCalled();
  });

  test('sendOnlineTransfer returns failure when identity missing', async () => {
    mockedHasIdentity.mockResolvedValue(false);
    const res = await client.sendOnlineTransfer({ tokenId: 't', to: new Uint8Array(0), amount: '1' });
    expect(res.success).toBe(false);
    expect(res.message).toMatch(/Identity not initialized/);
    expect(mockedDsm.sendOnlineTransfer).not.toHaveBeenCalled();
  });

  test('bridge passthrough for contacts when identity present', async () => {
    mockedHasIdentity.mockResolvedValue(true);
    mockedDsm.getContacts.mockResolvedValue({ contacts: [{ alias: 'b', device_id: new Uint8Array(32), genesis_hash: new Uint8Array(32) }] } as any);
    mockedDsm.addContact.mockResolvedValue({ accepted: true } as any);
    const keyB32 = encodeBase32Crockford(new Uint8Array(64));

    const got = await client.getContacts();
    expect(got.contacts.length).toBe(1);

    const genesisB32 = encodeBase32Crockford(new Uint8Array(32));
    const deviceB32 = encodeBase32Crockford(new Uint8Array(32));
    const added = await client.addContact({
      alias: 'z',
      genesisHash: genesisB32,
      deviceId: deviceB32,
      signingPublicKey: keyB32,
      storageNodes: ['http://localhost:8080', 'http://localhost:8081', 'http://localhost:8082'],
    });
    expect(added).toEqual({ ok: true });
    expect(mockedDsm.getContacts).toHaveBeenCalled();
    expect(mockedDsm.addContact).toHaveBeenCalled();
  });

  test('delegates online transfer and returns success when bridge ready', async () => {
    mockedHasIdentity.mockResolvedValue(true);
    mockedDsm.sendOnlineTransfer.mockResolvedValue({ accepted: true, result: 'ok', newBalance: 123n } as any);

    const on = await client.sendOnlineTransfer({ tokenId: 't', to: new Uint8Array(32), amount: '5' });
    expect(on.success).toBe(true);
    expect(on.newBalance).toBe(123n);
    expect(mockedDsm.sendOnlineTransfer).toHaveBeenCalled();
  });
});
