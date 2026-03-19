# Content-Addressed Token Policy Anchors (CTPA)

In the Deterministic State Machine (DSM), every token carries a **Content-Addressed Token Policy Anchor (CTPA)**—a cryptographic commitment included at genesis that defines the rules governing that token's usage. These policies are enforced deterministically by the state machine and cannot be bypassed.

## What is a CTPA?

A CTPA is a **hash-anchored policy file** that defines the behavioral constraints of a token. It is content-addressed, meaning the hash of the policy file itself serves as the anchor.

A token **cannot be received or processed** unless the CTPA is first retrieved and verified. This ensures all tokens in the system are traceable to a real, immutable, committed policy.

## Token Genesis and CTPA Binding

When a token is created:

1. A policy file is defined (e.g., time-locks, identity constraints, vault enforcement)
2. The file is hashed using Blake3
3. This hash becomes the **CTPA**
4. The token genesis process binds the CTPA to the token state
5. The policy file is stored in the DSM decentralized storage system
6. Names and symbols are **globally reserved**—duplicate claims are rejected deterministically

## Receiving Tokens

When a wallet or device receives tokens:

1. It checks for the token's CTPA hash
2. It fetches the full policy file from decentralized storage ahead of time
3. It verifies the hash matches the anchor
4. It **caches the policy locally**
5. If verification fails, the token is rejected automatically

A token with no verified policy is not recognized by the protocol. The policy is embedded in the token genesis state, and the hash is a pointer to the policy (CTPA) file.

## Implementation Components

The CTPA system consists of:

- **PolicyFile**: The actual policy definition with conditions and rules
- **PolicyAnchor**: The cryptographic hash (Blake3) of the policy file
- **PolicyStore**: Storage and retrieval mechanism for policy files
- **PolicyVerification**: Validation logic for token operations against policies

## Policy Conditions

The CTPA system supports various policy conditions, including:

- **TimeLock**: Restricts token operations until a specific time
- **IdentityConstraint**: Limits token operations to specific identities
- **VaultEnforcement**: Requires specific vault conditions to be met
- **OperationRestriction**: Limits which operations are allowed
- **GeographicRestriction**: Limits token usage to specific regions
- **Custom**: Extensible framework for additional constraints

## Default Policies

Every token must have a policy. If none is provided at creation, the system automatically generates a default policy using `generate_default_policy()` which includes:

- Basic time validity constraints
- Creator identity allowances
- Standard operation permissions

## Specialized Policies

The system supports specialized policy types through `generate_specialized_policy()`, including:

- **TimeLocked**: Tokens that cannot be transferred until a specific time
- **IdentityBound**: Tokens that can only be used by specific identities
- **RestrictedOperations**: Tokens with limited operation sets
- **GeographicRestriction**: Tokens restricted to specific regions

## Flow Example

```rust
// 1. Create or load a policy file
let policy = generate_default_policy("TOKEN_ID", "My Token", "creator_id")?;

// 2. Store the policy in the decentralized store
let policy_anchor = policy_store.store_policy(&policy).await?;

// 3. Create a token with this policy
let genesis = create_token_genesis(
    1,
    vec!["creator_id".to_string()],
    token_data.as_bytes(),
    Some(&policy)
)?;

// 4. The token now has the policy anchor embedded
let token = create_token_from_genesis(&genesis, "creator_id", metadata, balance);

// 5. Verification happens automatically during operations
// (The TokenStateManager will verify against policy constraints)
```

## Vault and Fork Enforcement

- **Vaults**: When a token enters a vault, its CTPA is registered; any withdrawal must satisfy the policy
- **Forks**: In forked transitions, each path includes a reference to the required CTPA; only matching policy conditions can finalize the transition

## Security Properties

- **Immutability**: Policy files are immutable and cannot be changed after token creation
- **Deterministic Enforcement**: Policies are enforced by the state machine automatically
- **Global Discoverability**: All policy anchors are globally discoverable
- **Caching**: Policies are cached after verification for efficiency
- **Rejection Guarantee**: Tokens with invalid or unverifiable CTPAs are treated as non-existent
