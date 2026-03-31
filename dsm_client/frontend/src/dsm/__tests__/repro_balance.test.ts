
import * as pb from '../../proto/dsm_app_pb';

describe('Balance Mapping Reproduction', () => {
  it('should correctly map available balance from protobuf', () => {
    // 1. Create a BalanceGetResponse with balance 5
    const balanceItem = new pb.BalanceGetResponse({
      tokenId: 'ERA',
      available: BigInt(5),
      locked: BigInt(0),
    });

    // 2. Create a BalancesListResponse containing the item
    const listResponse = new pb.BalancesListResponse({
      balances: [balanceItem],
    });

    // 3. Encode to binary
    const binary = listResponse.toBinary();

    // 4. Decode back (mimicking getAllBalances)
    const decodedList = pb.BalancesListResponse.fromBinary(binary);

    // 5. Map it (mimicking getAllBalances logic)
    const mapped = (decodedList.balances || []).map((b: any) => {
      // DEBUG: Inspect the object structure to verify field names
      console.log('[DSM] Balance item keys:', Object.keys(b));
      console.log('[DSM] Balance item:', b);
      
      return {
        tokenId: b.tokenId || 'ERA',
        symbol: (b.tokenId || 'ERA') === 'ERA' ? 'ERA' : b.tokenId,
        balance: String(b.available ?? 0),
      };
    });

    console.log('Mapped result:', mapped);

    // 6. Assertions
    expect(mapped).toHaveLength(1);
    expect(mapped[0].tokenId).toBe('ERA');
    expect(mapped[0].balance).toBe('5');
  });
});
