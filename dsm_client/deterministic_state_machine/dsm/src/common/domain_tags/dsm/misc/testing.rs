// SPDX-License-Identifier: MIT OR Apache-2.0

//! DSM namespace tags: domain tags reserved for test, benchmark, and trace
//! tooling. Centralized here so integration tests and the vertical-validation
//! tooling crate reference the same constants instead of duplicating string
//! literals. Never used by production protocol paths.

pub const TAG_DSM_TEST: &str = "DSM/test";
pub const TAG_DSM_TEST_DEVICE: &str = "DSM/test-device";
pub const TAG_DSM_TEST_ENTITY_ID: &str = "DSM/test-entity-id";
pub const TAG_DSM_TEST_ENTROPY: &str = "DSM/test-entropy";
pub const TAG_DSM_TEST_CSPRNG_SEED: &str = "DSM/test-csprng-seed";
pub const TAG_DSM_TEST_CSPRNG_NEXT: &str = "DSM/test-csprng-next";
pub const TAG_DSM_TEST_TIP: &str = "DSM/test-tip";
pub const TAG_DSM_TEST_NEXT_TIP: &str = "DSM/test-next-tip";
pub const TAG_DSM_TEST_COMMIT: &str = "DSM/test-commit";
pub const TAG_DSM_TEST_PARENT: &str = "DSM/test-parent";
pub const TAG_DSM_TEST_CHILD: &str = "DSM/test-child";
pub const TAG_DSM_BENCH: &str = "DSM/bench";
pub const TAG_DSM_TRACE_GENESIS: &str = "DSM/trace-genesis";
pub const TAG_DSM_TRACE_DEVICE: &str = "DSM/trace-device";
pub const TAG_DSM_TAG: &str = "DSM/tag";
pub const TAG_DSM_TAG_A: &str = "DSM/tag-a";
pub const TAG_DSM_TAG_B: &str = "DSM/tag-b";
pub const TAG_DSM_TAG1: &str = "DSM/tag1";
pub const TAG_DSM_TAG2: &str = "DSM/tag2";
