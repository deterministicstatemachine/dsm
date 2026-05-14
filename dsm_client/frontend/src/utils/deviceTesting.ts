/* eslint-disable @typescript-eslint/no-explicit-any */
// Device testing utilities for Android WebView
export function isAndroidWebView(): boolean {
  return typeof window !== 'undefined' && typeof navigator !== 'undefined' && navigator.userAgent.includes('Android');
}

export function hasDsmBridge(): boolean {
  return typeof window !== 'undefined' && !!(window as any).DsmBridge;
}

export function testBridgeConnectivity(): Promise<boolean> {
  return new Promise((resolve) => {
    if (!hasDsmBridge()) {
      resolve(false);
      return;
    }

    try {
      // Try to call a basic bridge method
      const bridge = (window as any).DsmBridge;
      if (bridge.hasIdentityDirect) {
        const result = bridge.hasIdentityDirect();
        resolve(typeof result === 'boolean');
      } else {
        resolve(false);
      }
    } catch (error) {
      console.error('Bridge connectivity test failed:', error);
      resolve(false);
    }
  });
}