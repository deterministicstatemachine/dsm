import { getNfcBackupUiModel } from '../nfcBackupUi';

describe('getNfcBackupUiModel', () => {
  it('treats enabled plus pending as armed', () => {
    const model = getNfcBackupUiModel({
      enabled: true,
      configured: true,
      pendingCapsule: true,
      capsuleCount: 2,
      lastCapsuleIndex: 7,
      autoWriteEnabled: false,
    });

    expect(model.state).toBe('armed');
    expect(model.backupLabel).toBe('ON');
    expect(model.writeStateLabel).toBe('ARMED');
    expect(model.nextActionLabel).toBe('WRITE');
  });

  it('treats enabled without pending as waiting', () => {
    const model = getNfcBackupUiModel({
      enabled: true,
      configured: true,
      pendingCapsule: false,
      capsuleCount: 2,
      lastCapsuleIndex: 7,
      autoWriteEnabled: false,
    });

    expect(model.state).toBe('waiting');
    expect(model.writeStateLabel).toBe('WAITING');
    expect(model.nextActionLabel).toBe('REBUILD');
  });

  it('treats unconfigured backup as not set', () => {
    const model = getNfcBackupUiModel({
      enabled: false,
      configured: false,
      pendingCapsule: false,
      capsuleCount: 0,
      lastCapsuleIndex: 0,
      autoWriteEnabled: false,
    });

    expect(model.state).toBe('not_set');
    expect(model.backupLabel).toBe('NOT SET');
    expect(model.nextActionLabel).toBe('SET UP');
  });
});
