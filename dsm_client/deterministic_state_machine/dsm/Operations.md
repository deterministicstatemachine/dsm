# Operations

The variants of `Operation` (`src/types/operations.rs`, the authority for this table). Every
operation is applied through `DeviceState::advance`; an operation that would change nothing is
refused as a zero-effect transition.

| Operation | Purpose |
|-----------|---------|
| **Genesis** | The initial state of an identity |
| **Transfer** | An online send from this device to a contact (unilateral: the payer sends alone) |
| **Receive** | The receiving side of a transfer |
| **FaucetClaim** | One beta payout of ERA, released from the network's native reserve |
| **CreateToken** | A new token under its policy; the supply entered is the whole supply |
| **AdoptToken** | Adopt a token's public policy on this device; a device is never credited a token it has not adopted |
| **Burn** | Destroy tokens under their policy |
| **LockToken**, **UnlockToken**, **Lock**, **Unlock** | Lock and release a quantity of tokens |
| **CreateRelationship** | With the marker `establish`: a relationship's ESTABLISH step, the moneyless first step, countersigned by the other device (DSM Amendment A33) |
| **RemoveRelationship** | With the marker `terminate`: a relationship's TERMINATE step, the moneyless step that ends it (DSM Amendment A33) |
| **AddRelationship** | Register a relationship between two devices |
| **Recovery** | A recovery step |
| **SofiSetup** | SoFi: a trader's relationship setup claim; moves no value |
| **SofiVaultCreate** | SoFi: an owner's vault creation, funded from the owner's balances |
| **SofiFulfill** | SoFi: the trader's exercise of a trade, a route or a close |
| **EscrowVaultCreate** | An escrow vault's creation (SoFi Amendment S21) |
| **DlvCreate**, **DlvUnlock**, **DlvClaim**, **DlvInvalidate** | Bitcoin-tap vaults; they move no token balance |
| **Create**, **Update**, **Delete**, **Link**, **Unlink**, **Invalidate**, **Generic** | Identity and application operations |
| **Noop** | No-operation sentinel; produces no state change |
