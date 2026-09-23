// SPDX-License-Identifier: Apache-2.0

import React, { useCallback } from 'react';
import type { ScreenType } from '../types/app';
import EnhancedWalletScreen from './screens/EnhancedWalletScreen';
import ContactsScreen from './screens/ContactsTabScreen';
import StorageScreen from './screens/StorageScreen';
import SettingsMainScreen from './screens/SettingsMainScreen';
import DevPolicyScreen from './screens/DevPolicyScreen';
import LockSetupScreen from './screens/LockSetupScreen';
import QRCodeScannerScreen from './screens/QRCodeScannerScreen';
import MyContactInfoScreen from './screens/MyContactInfoScreen';
import AccountsScreen from './screens/AccountsScreen';
import RecoveryScreen from './screens/RecoveryScreen';
import NfcRecoveryScreen from './screens/NfcRecoveryScreen';
import RecoveryPipelineScreen from './screens/RecoveryPipelineScreen';
import AdditionalDeviceScreen from './screens/AdditionalDeviceScreen';
import SofiScreen from './screens/SofiScreen';

const MemoWallet = React.memo(EnhancedWalletScreen);
const MemoContacts = React.memo(ContactsScreen);
const MemoStorage = React.memo(StorageScreen);
const MemoSettings = React.memo(SettingsMainScreen);
const MemoDevPolicy = React.memo(DevPolicyScreen);
const MemoLockSetup = React.memo(LockSetupScreen);
const MemoQR = React.memo(QRCodeScannerScreen);
const MemoMyContact = React.memo(MyContactInfoScreen);
const MemoAccounts = React.memo(AccountsScreen);
const MemoRecovery = React.memo(RecoveryScreen);
const MemoNfcRecovery = React.memo(NfcRecoveryScreen);
const MemoRecoveryPipeline = React.memo(RecoveryPipelineScreen);
const MemoAdditionalDevice = React.memo(AdditionalDeviceScreen);
const MemoSofi = React.memo(SofiScreen);

type Props = {
  currentScreen: ScreenType;
  navigate: (to: ScreenType) => void;
  eraTokenSrc: string;
  btcLogoSrc: string;
};

export default function AppScreenRouter({
  currentScreen,
  navigate,
  eraTokenSrc,
  btcLogoSrc,
}: Props) {
  const onNavigate = useCallback(
    (screen: string) => navigate(screen as ScreenType),
    [navigate],
  );

  const onQrCancel = useCallback(
    () => navigate('contacts'),
    [navigate],
  );

  switch (currentScreen) {
    case 'wallet':
      return <MemoWallet btcLogoSrc={btcLogoSrc} />;
    case 'contacts':
      return <MemoContacts onNavigate={onNavigate} eraTokenSrc={eraTokenSrc} />;
    case 'storage':
      return <MemoStorage />;
    case 'settings':
      return <MemoSettings onNavigate={onNavigate} />;
    case 'dev_policy':
      return <MemoDevPolicy />;
    case 'lock_setup':
      return <MemoLockSetup onNavigate={onNavigate} />;
    case 'qr':
      return <MemoQR onCancel={onQrCancel} eraTokenSrc={eraTokenSrc} />;
    case 'mycontact':
      return <MemoMyContact />;
    case 'vault':
      return <MemoWallet btcLogoSrc={btcLogoSrc} />;
    case 'transactions':
      return <MemoWallet initialTab="history" btcLogoSrc={btcLogoSrc} />;
    case 'accounts':
      return <MemoAccounts eraTokenSrc={eraTokenSrc} btcLogoSrc={btcLogoSrc} />;
    case 'recovery':
      return <MemoRecovery onNavigate={onNavigate} />;
    case 'nfc_recovery':
      return <MemoNfcRecovery onNavigate={onNavigate} />;
    case 'recovery_pipeline':
      return <MemoRecoveryPipeline onNavigate={onNavigate} />;
    case 'additional_device':
      return <MemoAdditionalDevice onNavigate={onNavigate} />;
    case 'sofi':
      return <MemoSofi />;
    default:
      return null;
  }
}
