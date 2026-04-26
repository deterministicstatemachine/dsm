// SPDX-License-Identifier: Apache-2.0

import React, { useCallback } from 'react';
import type { ScreenType } from '../types/app';
import EnhancedWalletScreen from './screens/EnhancedWalletScreen';
import ContactsScreen from './screens/ContactsTabScreen';
import StorageScreen from './screens/StorageScreen';
import TokenManagementScreen from './screens/TokenManagementScreen';
import SettingsMainScreen from './screens/SettingsMainScreen';
import DevDlvScreen from './screens/DevDlvScreen';
import DevCdbrwScreen from './screens/DevCdbrwScreen';
import DevPolicyScreen from './screens/DevPolicyScreen';
import DevDeTfiLaunchScreen from './screens/DevDeTfiLaunchScreen';
import DevAmmVaultScreen from './screens/DevAmmVaultScreen';
import DevAmmTradeScreen from './screens/DevAmmTradeScreen';
import DevPostedInboxScreen from './screens/DevPostedInboxScreen';
import LockSetupScreen from './screens/LockSetupScreen';
import QRCodeScannerScreen from './screens/QRCodeScannerScreen';
import MyContactInfoScreen from './screens/MyContactInfoScreen';
import AccountsScreen from './screens/AccountsScreen';
import RecoveryScreen from './screens/RecoveryScreen';
import NfcRecoveryScreen from './screens/NfcRecoveryScreen';
import RecoveryPipelineScreen from './screens/RecoveryPipelineScreen';

const MemoWallet = React.memo(EnhancedWalletScreen);
const MemoContacts = React.memo(ContactsScreen);
const MemoStorage = React.memo(StorageScreen);
const MemoTokens = React.memo(TokenManagementScreen);
const MemoSettings = React.memo(SettingsMainScreen);
const MemoDevDlv = React.memo(DevDlvScreen);
const MemoDevCdbrw = React.memo(DevCdbrwScreen);
const MemoDevPolicy = React.memo(DevPolicyScreen);
const MemoDevDeTfiLaunch = React.memo(DevDeTfiLaunchScreen);
const MemoDevAmmVault = React.memo(DevAmmVaultScreen);
const MemoDevAmmTrade = React.memo(DevAmmTradeScreen);
const MemoDevPostedInbox = React.memo(DevPostedInboxScreen);
const MemoLockSetup = React.memo(LockSetupScreen);
const MemoQR = React.memo(QRCodeScannerScreen);
const MemoMyContact = React.memo(MyContactInfoScreen);
const MemoAccounts = React.memo(AccountsScreen);
const MemoRecovery = React.memo(RecoveryScreen);
const MemoNfcRecovery = React.memo(NfcRecoveryScreen);
const MemoRecoveryPipeline = React.memo(RecoveryPipelineScreen);

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
      return <MemoWallet eraTokenSrc={eraTokenSrc} btcLogoSrc={btcLogoSrc} />;
    case 'contacts':
      return <MemoContacts onNavigate={onNavigate} eraTokenSrc={eraTokenSrc} />;
    case 'storage':
      return <MemoStorage />;
    case 'tokens':
      return <MemoTokens />;
    case 'settings':
      return <MemoSettings onNavigate={onNavigate} />;
    case 'dev_dlv':
      return <MemoDevDlv />;
    case 'dev_cdbrw':
      return <MemoDevCdbrw />;
    case 'dev_policy':
      return <MemoDevPolicy />;
    case 'dev_detfi_launch':
      return <MemoDevDeTfiLaunch />;
    case 'dev_amm_vault':
      return <MemoDevAmmVault />;
    case 'dev_amm_trade':
      return <MemoDevAmmTrade />;
    case 'dev_posted_inbox':
      return <MemoDevPostedInbox />;
    case 'lock_setup':
      return <MemoLockSetup onNavigate={onNavigate} />;
    case 'qr':
      return <MemoQR onCancel={onQrCancel} eraTokenSrc={eraTokenSrc} />;
    case 'mycontact':
      return <MemoMyContact />;
    case 'vault':
      return <MemoWallet eraTokenSrc={eraTokenSrc} btcLogoSrc={btcLogoSrc} />;
    case 'transactions':
      return <MemoWallet initialTab="history" eraTokenSrc={eraTokenSrc} btcLogoSrc={btcLogoSrc} />;
    case 'accounts':
      return <MemoAccounts eraTokenSrc={eraTokenSrc} btcLogoSrc={btcLogoSrc} />;
    case 'recovery':
      return <MemoRecovery onNavigate={onNavigate} />;
    case 'nfc_recovery':
      return <MemoNfcRecovery onNavigate={onNavigate} />;
    case 'recovery_pipeline':
      return <MemoRecoveryPipeline onNavigate={onNavigate} />;
    default:
      return null;
  }
}
