/* eslint-disable @typescript-eslint/no-explicit-any */
// Global bridge typings (loose) to keep TS happy without enforcing runtime availability
export {};

declare global {
  interface Window {
    DsmBridge?: {
      hasIdentityDirect?: () => boolean | Promise<boolean>;
      __binary?: boolean;
      sendMessageBin?: (payload: Uint8Array) => Promise<Uint8Array>;
    };
    __DSM_PENDING_BILATERAL_STORE_SYNC__?: boolean;
  }
}
