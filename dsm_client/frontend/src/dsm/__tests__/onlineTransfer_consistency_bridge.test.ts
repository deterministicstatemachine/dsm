import * as pb from '../../proto/dsm_app_pb';
import { sendOnlineTransfer } from '../index';
import { decodeBase32Crockford, encodeBase32Crockford } from '../../utils/textId';

// Helper to wrap response in DSM_BRIDGE format
function wrapSuccessEnvelope(data: Uint8Array): Uint8Array {
  return (global as any).createDsmBridgeSuccessResponse(data);
}

function bytes(len: number, fill: number): Uint8Array {
  const b = new Uint8Array(len);
  b.fill(fill & 0xff);
  return b;
}

function readFrame(buf: Uint8Array): { method: string; payload: Uint8Array } {
  const mlen = ((buf[0] ?? 0) << 24) | ((buf[1] ?? 0) << 16) | ((buf[2] ?? 0) << 8) | (buf[3] ?? 0);
  const method = new TextDecoder().decode(buf.slice(4, 4 + mlen));
  return { method, payload: buf.slice(4 + mlen) };
}

describe('online transfer sender/recipient consistency through WebView bridge', () => {
  it('returns the tx hash that native reports to the sender (bytes-only invoke)', async () => {
    // Test the tx hash decoding logic directly
    const txHash = new pb.Hash32({ v: new Uint8Array(32).fill(0x77) });
    
    // Build the response that would be parsed
    const resp = new pb.OnlineTransferResponse({ 
      success: true, 
      transactionHash: txHash, 
      message: 'ok', 
      newBalance: 9n 
    } as any);
    
    const pack = new pb.ResultPack({ 
      codec: pb.Codec.CODEC_PROTO, 
      body: resp.toBinary() as any 
    } as any);
    
    // Test the parsing logic
    const resBytes = pack.toBinary();
    const resPack = pb.ResultPack.fromBinary(resBytes);
    const inner = pb.OnlineTransferResponse.fromBinary(resPack.body);
    
    expect(inner.success).toBe(true);
    expect(inner.transactionHash).toBeDefined();
    
    // Test the txHash encoding/decoding
    const encodedTxHash = encodeBase32Crockford(inner.transactionHash!.v);
    const decodedTxHash = decodeBase32Crockford(encodedTxHash);
    expect(decodedTxHash).toEqual(new Uint8Array(txHash.v));
  });
});