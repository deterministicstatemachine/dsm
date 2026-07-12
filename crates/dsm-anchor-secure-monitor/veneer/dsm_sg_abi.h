// SPDX-License-Identifier: MIT OR Apache-2.0
// DSM anchor Secure Gateway ABI — shared by the C veneer, the Secure Rust handler, and (as mirrored
// constants) the Non-secure app. The ONLY values that cross the boundary in registers are a fixed
// slot index and a sequence number; everything else is the bounded request/response in the fixed
// Non-secure SRAM slot, copied in/out by the Secure handler.
#ifndef DSM_SG_ABI_H
#define DSM_SG_ABI_H

// Fixed request/response mailbox: exactly ONE slot in Non-secure SRAM (data plane behind the SG).
#define DSM_SG_SLOT_INDEX      0u          // the only valid slot in v1
#define DSM_SG_SLOT_MAX_LEN    4096u       // bounded request/response length; larger => rejected

// Request opcodes (published by the Non-secure app in the slot header; validated from the Secure
// copy). The narrow state machine — no generic sign op exists.
#define DSM_SG_OP_STATUS       1u
#define DSM_SG_OP_PREPARE      2u
#define DSM_SG_OP_COMMIT       3u
#define DSM_SG_OP_EMIT         4u
#define DSM_SG_OP_FINALIZE     5u
#define DSM_SG_OP_RECOVER      6u

// dsm_secure_dispatch return status.
#define DSM_SG_OK              0u
#define DSM_SG_ERR_SLOT        1u          // bad slot index
#define DSM_SG_ERR_SEQ         2u          // stale / replayed sequence number
#define DSM_SG_ERR_SIZE        3u          // oversized / misaligned request
#define DSM_SG_ERR_OPCODE      4u          // unknown opcode
#define DSM_SG_ERR_ENCODING    5u          // canonical encoding invalid (from the Secure copy)
#define DSM_SG_ERR_STATE       6u          // wrong appliance state for this op
#define DSM_SG_ERR_MEASUREMENT 7u          // measurement_ok == false: fail closed, no signing
#define DSM_SG_ERR_INTERNAL    8u

#endif // DSM_SG_ABI_H
