// SPDX-License-Identifier: MIT OR Apache-2.0
// DSM anchor Secure Gateway ABI — shared by the C veneer, the Secure Rust handler, and (as mirrored
// constants) the Non-secure app. The ONLY values that cross the boundary in registers are a fixed
// slot index and a sequence number; everything else is the bounded request/response in the fixed
// Non-secure SRAM slot, copied in/out by the Secure handler.
#ifndef DSM_SG_ABI_H
#define DSM_SG_ABI_H

// Fixed request/response mailbox: exactly ONE slot in Non-secure SRAM (data plane behind the SG).
// ABI v2: a frame up to DSM_SG_FRAME_MAX_LEN moves through the slot in parts. The slot header names
// each part's offset and the whole frame's length; the Secure handler assembles a request frame from
// its parts and serves the response frame in parts. Nothing is cut short.
#define DSM_SG_SLOT_INDEX      0u          // the only valid slot
#define DSM_SG_SLOT_MAX_LEN    4096u       // the largest part
#define DSM_SG_FRAME_MAX_LEN   65536u      // the largest frame (anchor-core MAX_FRAME_LEN)
#define DSM_SG_ABI_VERSION     2u

// Transport opcodes (published by the Non-secure app in the slot header).
#define DSM_SG_OP_KEEPALIVE      1u        // feed the watchdog; touches no frame
#define DSM_SG_OP_REQUEST_PART   2u        // one part of a request frame
#define DSM_SG_OP_RESPONSE_PART  3u        // one part of the response frame, from `offset`

// dsm_secure_dispatch return status. Statuses 5, 7 and 8 are retired: an undecodable frame, a
// failed measurement and an anchor that did not come up are answered with a refusal frame.
#define DSM_SG_OK              0u
#define DSM_SG_ERR_SLOT        1u          // bad slot index
#define DSM_SG_ERR_SEQ         2u          // stale / replayed sequence number, or a part out of order
#define DSM_SG_ERR_SIZE        3u          // a part past its frame, or a frame past the largest frame
#define DSM_SG_ERR_OPCODE      4u          // unknown opcode
#define DSM_SG_ERR_STATE       6u          // wrong mailbox or ABI state for this op
#define DSM_SG_MORE            9u          // request part taken; the frame is not complete

#endif // DSM_SG_ABI_H
