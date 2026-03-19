| Operation | Category | Purpose |
|-----------|----------|---------|
| **Genesis** | System | Initializes the root state of a DSM identity chain with cryptographic entropy |
| **Create** | Identity | Creates a new identity with public key, metadata, and cryptographic commitments |
| **Update** | Identity | Updates identity data with proof of authorization and optional forward linking |
| **Transfer** | Token | Moves tokens between identities with pre-commitment support and cryptographic signatures |
| **Receive** | Token | Accepts incoming token transfers with verification of sender state and amounts |
| **Mint** | Token | Creates new tokens according to policy authorization and proof requirements |
| **Burn** | Token | Destroys tokens with proof of ownership and policy compliance |
| **LockToken** | Token | Temporarily locks tokens for specific purposes (escrow, staking, etc.) |
| **UnlockToken** | Token | Releases previously locked tokens with authorization |
| **CreateToken** | Token | Creates new token types with supply, metadata, and policy anchors |
| **AddRelationship** | Social | Establishes bilateral relationships between identities with metadata and proofs |
| **CreateRelationship** | Social | Initiates relationship creation with counterparty commitments |
| **RemoveRelationship** | Social | Terminates existing relationships with cryptographic proofs |
| **Recovery** | Security | Recovers compromised identities using state snapshots and authority signatures |
| **Delete** | Management | Removes entities with justification and cryptographic proofs |
| **Link** | Management | Creates links between entities (identities, tokens, etc.) |
| **Unlink** | Management | Removes links between entities |
| **Invalidate** | Management | Marks entities as invalid with justification and proofs |
| **Generic** | Extensibility | Extensible operation for custom logic with type, data, and message fields |
| **Noop** | System | No-operation placeholder for testing and protocol padding |