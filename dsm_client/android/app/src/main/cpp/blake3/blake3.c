// BLAKE3 reference implementation — portable C (no SIMD)
// Source: https://github.com/BLAKE3-team/BLAKE3 (CC0 / Apache-2.0)
// Vendored for Android NDK. Only the portable path is included.

#include "blake3.h"
#include "blake3_impl.h"

// --- Compression function (portable) ---

static void g(uint32_t *state, size_t a, size_t b, size_t c, size_t d,
              uint32_t mx, uint32_t my) {
  state[a] = state[a] + state[b] + mx;
  state[d] = rotr32(state[d] ^ state[a], 16);
  state[c] = state[c] + state[d];
  state[b] = rotr32(state[b] ^ state[c], 12);
  state[a] = state[a] + state[b] + my;
  state[d] = rotr32(state[d] ^ state[a], 8);
  state[c] = state[c] + state[d];
  state[b] = rotr32(state[b] ^ state[c], 7);
}

static void round_fn(uint32_t state[16], const uint32_t *msg, size_t round) {
  const uint8_t *schedule = MSG_SCHEDULE[round];
  // Mix columns
  g(state, 0, 4,  8, 12, msg[schedule[ 0]], msg[schedule[ 1]]);
  g(state, 1, 5,  9, 13, msg[schedule[ 2]], msg[schedule[ 3]]);
  g(state, 2, 6, 10, 14, msg[schedule[ 4]], msg[schedule[ 5]]);
  g(state, 3, 7, 11, 15, msg[schedule[ 6]], msg[schedule[ 7]]);
  // Mix diagonals
  g(state, 0, 5, 10, 15, msg[schedule[ 8]], msg[schedule[ 9]]);
  g(state, 1, 6, 11, 12, msg[schedule[10]], msg[schedule[11]]);
  g(state, 2, 7,  8, 13, msg[schedule[12]], msg[schedule[13]]);
  g(state, 3, 4,  9, 14, msg[schedule[14]], msg[schedule[15]]);
}

static void compress_pre(uint32_t state[16], const uint32_t cv[8],
                         const uint8_t block[BLAKE3_BLOCK_LEN],
                         uint8_t block_len, uint64_t counter, uint8_t flags) {
  uint32_t block_words[16];
  block_words[ 0] = load32(block +  0 * 4);
  block_words[ 1] = load32(block +  1 * 4);
  block_words[ 2] = load32(block +  2 * 4);
  block_words[ 3] = load32(block +  3 * 4);
  block_words[ 4] = load32(block +  4 * 4);
  block_words[ 5] = load32(block +  5 * 4);
  block_words[ 6] = load32(block +  6 * 4);
  block_words[ 7] = load32(block +  7 * 4);
  block_words[ 8] = load32(block +  8 * 4);
  block_words[ 9] = load32(block +  9 * 4);
  block_words[10] = load32(block + 10 * 4);
  block_words[11] = load32(block + 11 * 4);
  block_words[12] = load32(block + 12 * 4);
  block_words[13] = load32(block + 13 * 4);
  block_words[14] = load32(block + 14 * 4);
  block_words[15] = load32(block + 15 * 4);

  state[ 0] = cv[0];
  state[ 1] = cv[1];
  state[ 2] = cv[2];
  state[ 3] = cv[3];
  state[ 4] = cv[4];
  state[ 5] = cv[5];
  state[ 6] = cv[6];
  state[ 7] = cv[7];
  state[ 8] = IV[0];
  state[ 9] = IV[1];
  state[10] = IV[2];
  state[11] = IV[3];
  state[12] = (uint32_t)counter;
  state[13] = (uint32_t)(counter >> 32);
  state[14] = (uint32_t)block_len;
  state[15] = (uint32_t)flags;

  round_fn(state, block_words, 0);
  round_fn(state, block_words, 1);
  round_fn(state, block_words, 2);
  round_fn(state, block_words, 3);
  round_fn(state, block_words, 4);
  round_fn(state, block_words, 5);
  round_fn(state, block_words, 6);
}

static void blake3_compress_in_place(uint32_t cv[8],
                                     const uint8_t block[BLAKE3_BLOCK_LEN],
                                     uint8_t block_len, uint64_t counter,
                                     uint8_t flags) {
  uint32_t state[16];
  compress_pre(state, cv, block, block_len, counter, flags);
  cv[0] = state[0] ^ state[8];
  cv[1] = state[1] ^ state[9];
  cv[2] = state[2] ^ state[10];
  cv[3] = state[3] ^ state[11];
  cv[4] = state[4] ^ state[12];
  cv[5] = state[5] ^ state[13];
  cv[6] = state[6] ^ state[14];
  cv[7] = state[7] ^ state[15];
}

static void blake3_compress_xof(const uint32_t cv[8],
                                const uint8_t block[BLAKE3_BLOCK_LEN],
                                uint8_t block_len, uint64_t counter,
                                uint8_t flags, uint8_t out[64]) {
  uint32_t state[16];
  compress_pre(state, cv, block, block_len, counter, flags);
  store32(out +  0, state[ 0] ^ state[ 8]);
  store32(out +  4, state[ 1] ^ state[ 9]);
  store32(out +  8, state[ 2] ^ state[10]);
  store32(out + 12, state[ 3] ^ state[11]);
  store32(out + 16, state[ 4] ^ state[12]);
  store32(out + 20, state[ 5] ^ state[13]);
  store32(out + 24, state[ 6] ^ state[14]);
  store32(out + 28, state[ 7] ^ state[15]);
  store32(out + 32, state[ 8] ^ cv[0]);
  store32(out + 36, state[ 9] ^ cv[1]);
  store32(out + 40, state[10] ^ cv[2]);
  store32(out + 44, state[11] ^ cv[3]);
  store32(out + 48, state[12] ^ cv[4]);
  store32(out + 52, state[13] ^ cv[5]);
  store32(out + 56, state[14] ^ cv[6]);
  store32(out + 60, state[15] ^ cv[7]);
}

// --- Chunk state ---

static void chunk_state_init(blake3_chunk_state *self, const uint32_t key[8],
                             uint8_t flags) {
  memcpy(self->cv, key, BLAKE3_KEY_LEN);
  self->chunk_counter = 0;
  memset(self->buf, 0, BLAKE3_BLOCK_LEN);
  self->buf_len = 0;
  self->blocks_compressed = 0;
  self->flags = flags;
}

static void chunk_state_reset(blake3_chunk_state *self, const uint32_t key[8],
                              uint64_t chunk_counter) {
  memcpy(self->cv, key, BLAKE3_KEY_LEN);
  self->chunk_counter = chunk_counter;
  memset(self->buf, 0, BLAKE3_BLOCK_LEN);
  self->buf_len = 0;
  self->blocks_compressed = 0;
}

static size_t chunk_state_len(const blake3_chunk_state *self) {
  return (size_t)BLAKE3_BLOCK_LEN * (size_t)self->blocks_compressed +
         (size_t)self->buf_len;
}

static uint8_t chunk_state_start_flag(const blake3_chunk_state *self) {
  if (self->blocks_compressed == 0) {
    return CHUNK_START;
  }
  return 0;
}

static void chunk_state_update(blake3_chunk_state *self, const uint8_t *input,
                               size_t input_len) {
  if (self->buf_len > 0) {
    size_t take = BLAKE3_BLOCK_LEN - (size_t)self->buf_len;
    if (take > input_len) {
      take = input_len;
    }
    memcpy(&self->buf[self->buf_len], input, take);
    self->buf_len += (uint8_t)take;
    input += take;
    input_len -= take;
    if (input_len > 0) {
      blake3_compress_in_place(
          self->cv, self->buf, BLAKE3_BLOCK_LEN, self->chunk_counter,
          self->flags | chunk_state_start_flag(self));
      self->blocks_compressed += 1;
      self->buf_len = 0;
      memset(self->buf, 0, BLAKE3_BLOCK_LEN);
    }
  }

  while (input_len > BLAKE3_BLOCK_LEN) {
    blake3_compress_in_place(self->cv, input, BLAKE3_BLOCK_LEN,
                             self->chunk_counter,
                             self->flags | chunk_state_start_flag(self));
    self->blocks_compressed += 1;
    input += BLAKE3_BLOCK_LEN;
    input_len -= BLAKE3_BLOCK_LEN;
  }

  size_t take = input_len;
  if (take > 0) {
    memcpy(self->buf, input, take);
    self->buf_len = (uint8_t)take;
  }
}

// output struct for finalization chaining
typedef struct {
  uint32_t input_cv[8];
  uint8_t block[BLAKE3_BLOCK_LEN];
  uint8_t block_len;
  uint64_t counter;
  uint8_t flags;
} output_t;

static output_t make_output(const uint32_t input_cv[8],
                            const uint8_t block[BLAKE3_BLOCK_LEN],
                            uint8_t block_len, uint64_t counter,
                            uint8_t flags) {
  output_t ret;
  memcpy(ret.input_cv, input_cv, 32);
  memcpy(ret.block, block, BLAKE3_BLOCK_LEN);
  ret.block_len = block_len;
  ret.counter = counter;
  ret.flags = flags;
  return ret;
}

static void output_chaining_value(const output_t *self, uint8_t cv[32]) {
  uint32_t cv_words[8];
  memcpy(cv_words, self->input_cv, 32);
  blake3_compress_in_place(cv_words, self->block, self->block_len,
                           self->counter, self->flags);
  store_cv_words(cv, cv_words);
}

static void output_root_bytes(const output_t *self, uint64_t seek, uint8_t *out,
                              size_t out_len) {
  uint64_t output_block_counter = seek / 64;
  size_t offset_within_block = (size_t)(seek % 64);
  uint8_t wide_buf[64];
  while (out_len > 0) {
    blake3_compress_xof(self->input_cv, self->block, self->block_len,
                        output_block_counter, self->flags | ROOT, wide_buf);
    size_t available_bytes = 64 - offset_within_block;
    size_t memcpy_len;
    if (out_len > available_bytes) {
      memcpy_len = available_bytes;
    } else {
      memcpy_len = out_len;
    }
    memcpy(out, wide_buf + offset_within_block, memcpy_len);
    out += memcpy_len;
    out_len -= memcpy_len;
    output_block_counter += 1;
    offset_within_block = 0;
  }
}

static output_t chunk_state_output(const blake3_chunk_state *self) {
  uint8_t block_flags = self->flags | chunk_state_start_flag(self) | CHUNK_END;
  return make_output(self->cv, self->buf, self->buf_len, self->chunk_counter,
                     block_flags);
}

static output_t parent_output(const uint8_t block[BLAKE3_BLOCK_LEN],
                              const uint32_t key[8], uint8_t flags) {
  return make_output(key, block, BLAKE3_BLOCK_LEN, 0, flags | PARENT);
}

static void parent_cv(const uint8_t block[BLAKE3_BLOCK_LEN],
                      const uint32_t key[8], uint8_t flags, uint8_t out[32]) {
  output_t o = parent_output(block, key, flags);
  output_chaining_value(&o, out);
}

// --- Hasher ---

static void hasher_init_base(blake3_hasher *self, const uint32_t key[8],
                             uint8_t flags) {
  memcpy(self->key, key, BLAKE3_KEY_LEN);
  chunk_state_init(&self->chunk, key, flags);
  self->cv_stack_len = 0;
}

static void hasher_merge_cv_stack(blake3_hasher *self, uint64_t total_chunks) {
  while (self->cv_stack_len > 0 && (total_chunks & 1) == 0) {
    uint8_t *parent_block =
        &self->cv_stack[(self->cv_stack_len - 2) * BLAKE3_OUT_LEN];
    parent_cv(parent_block, self->key, self->chunk.flags, parent_block);
    self->cv_stack_len -= 1;
    total_chunks >>= 1;
  }
}

static void hasher_push_chunk_cv(blake3_hasher *self, uint8_t new_cv[BLAKE3_OUT_LEN],
                                 uint64_t chunk_counter) {
  hasher_merge_cv_stack(self, chunk_counter);
  memcpy(&self->cv_stack[self->cv_stack_len * BLAKE3_OUT_LEN], new_cv,
         BLAKE3_OUT_LEN);
  self->cv_stack_len += 1;
}

// --- Public API ---

const char *blake3_version(void) {
  return BLAKE3_VERSION_STRING;
}

void blake3_hasher_init(blake3_hasher *self) {
  hasher_init_base(self, IV, 0);
}

void blake3_hasher_init_keyed(blake3_hasher *self,
                              const uint8_t key[BLAKE3_KEY_LEN]) {
  uint32_t key_words[8];
  load_key_words(key, key_words);
  hasher_init_base(self, key_words, KEYED_HASH);
}

void blake3_hasher_init_derive_key(blake3_hasher *self, const char *context) {
  blake3_hasher_init_derive_key_raw(self, context, strlen(context));
}

void blake3_hasher_init_derive_key_raw(blake3_hasher *self, const void *context,
                                       size_t context_len) {
  blake3_hasher context_hasher;
  hasher_init_base(&context_hasher, IV, DERIVE_KEY_CONTEXT);
  blake3_hasher_update(&context_hasher, context, context_len);
  uint8_t context_key[BLAKE3_KEY_LEN];
  blake3_hasher_finalize(&context_hasher, context_key, BLAKE3_KEY_LEN);
  uint32_t context_key_words[8];
  load_key_words(context_key, context_key_words);
  hasher_init_base(self, context_key_words, DERIVE_KEY_MATERIAL);
}

void blake3_hasher_update(blake3_hasher *self, const void *input,
                          size_t input_len) {
  if (input_len == 0) {
    return;
  }

  const uint8_t *input_bytes = (const uint8_t *)input;

  if (chunk_state_len(&self->chunk) > 0) {
    size_t take = BLAKE3_CHUNK_LEN - chunk_state_len(&self->chunk);
    if (take > input_len) {
      take = input_len;
    }
    chunk_state_update(&self->chunk, input_bytes, take);
    input_bytes += take;
    input_len -= take;
    if (input_len > 0) {
      output_t chunk_output = chunk_state_output(&self->chunk);
      uint8_t chunk_cv[32];
      output_chaining_value(&chunk_output, chunk_cv);
      uint64_t total_chunks = self->chunk.chunk_counter + 1;
      hasher_push_chunk_cv(self, chunk_cv, total_chunks);
      chunk_state_reset(&self->chunk, self->key, total_chunks);
    } else {
      return;
    }
  }

  while (input_len > BLAKE3_CHUNK_LEN) {
    uint64_t counter = self->chunk.chunk_counter;
    // Process one chunk at a time (portable path)
    chunk_state_update(&self->chunk, input_bytes, BLAKE3_CHUNK_LEN);
    output_t chunk_output = chunk_state_output(&self->chunk);
    uint8_t chunk_cv[32];
    output_chaining_value(&chunk_output, chunk_cv);
    uint64_t total_chunks = counter + 1;
    hasher_push_chunk_cv(self, chunk_cv, total_chunks);
    chunk_state_reset(&self->chunk, self->key, total_chunks);
    input_bytes += BLAKE3_CHUNK_LEN;
    input_len -= BLAKE3_CHUNK_LEN;
  }

  if (input_len > 0) {
    chunk_state_update(&self->chunk, input_bytes, input_len);
  }
}

void blake3_hasher_finalize(const blake3_hasher *self, uint8_t *out,
                            size_t out_len) {
  blake3_hasher_finalize_seek(self, 0, out, out_len);
}

void blake3_hasher_finalize_seek(const blake3_hasher *self, uint64_t seek,
                                 uint8_t *out, size_t out_len) {
  if (out_len == 0) {
    return;
  }

  if (self->cv_stack_len == 0) {
    output_t chunk_output = chunk_state_output(&self->chunk);
    output_root_bytes(&chunk_output, seek, out, out_len);
    return;
  }

  output_t chunk_output = chunk_state_output(&self->chunk);
  uint8_t cv[32];
  output_chaining_value(&chunk_output, cv);

  uint8_t parent_block[BLAKE3_BLOCK_LEN];
  size_t i = (size_t)self->cv_stack_len;
  while (i > 0) {
    i -= 1;
    memcpy(parent_block, &self->cv_stack[i * BLAKE3_OUT_LEN], 32);
    memcpy(parent_block + 32, cv, 32);
    if (i > 0) {
      parent_cv(parent_block, self->key, self->chunk.flags, cv);
    } else {
      output_t o = parent_output(parent_block, self->key, self->chunk.flags);
      output_root_bytes(&o, seek, out, out_len);
      return;
    }
  }
}

void blake3_hasher_reset(blake3_hasher *self) {
  chunk_state_reset(&self->chunk, self->key, 0);
  self->cv_stack_len = 0;
}
