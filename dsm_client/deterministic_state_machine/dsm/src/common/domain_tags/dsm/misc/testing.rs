// SPDX-License-Identifier: MIT OR Apache-2.0

//! DSM namespace tags: domain tags reserved for test, benchmark, and trace
//! tooling. Centralized here so integration tests and the vertical-validation
//! tooling crate reference the same constants instead of duplicating string
//! literals. Never used by production protocol paths.

use crate::crypto::domain::TaggedHashDomain;

pub const TAG_DSM_TEST: TaggedHashDomain<'static> = TaggedHashDomain::from_static(b"DSM/test");
pub const TAG_DSM_TEST_DEVICE: TaggedHashDomain<'static> =
    TaggedHashDomain::from_static(b"DSM/test-device");
pub const TAG_DSM_TEST_ENTITY_ID: TaggedHashDomain<'static> =
    TaggedHashDomain::from_static(b"DSM/test-entity-id");
pub const TAG_DSM_TEST_ENTROPY: TaggedHashDomain<'static> =
    TaggedHashDomain::from_static(b"DSM/test-entropy");
pub const TAG_DSM_TEST_CSPRNG_SEED: TaggedHashDomain<'static> =
    TaggedHashDomain::from_static(b"DSM/test-csprng-seed");
pub const TAG_DSM_TEST_CSPRNG_NEXT: TaggedHashDomain<'static> =
    TaggedHashDomain::from_static(b"DSM/test-csprng-next");
pub const TAG_DSM_TEST_TIP: TaggedHashDomain<'static> =
    TaggedHashDomain::from_static(b"DSM/test-tip");
pub const TAG_DSM_TEST_NEXT_TIP: TaggedHashDomain<'static> =
    TaggedHashDomain::from_static(b"DSM/test-next-tip");
pub const TAG_DSM_TEST_COMMIT: TaggedHashDomain<'static> =
    TaggedHashDomain::from_static(b"DSM/test-commit");
pub const TAG_DSM_TEST_PARENT: TaggedHashDomain<'static> =
    TaggedHashDomain::from_static(b"DSM/test-parent");
pub const TAG_DSM_TEST_CHILD: TaggedHashDomain<'static> =
    TaggedHashDomain::from_static(b"DSM/test-child");
pub const TAG_DSM_BENCH: TaggedHashDomain<'static> = TaggedHashDomain::from_static(b"DSM/bench");
pub const TAG_DSM_TRACE_GENESIS: TaggedHashDomain<'static> =
    TaggedHashDomain::from_static(b"DSM/trace-genesis");
pub const TAG_DSM_TRACE_DEVICE: TaggedHashDomain<'static> =
    TaggedHashDomain::from_static(b"DSM/trace-device");
pub const TAG_DSM_TAG: TaggedHashDomain<'static> = TaggedHashDomain::from_static(b"DSM/tag");
pub const TAG_DSM_TAG_A: TaggedHashDomain<'static> = TaggedHashDomain::from_static(b"DSM/tag-a");
pub const TAG_DSM_TAG_B: TaggedHashDomain<'static> = TaggedHashDomain::from_static(b"DSM/tag-b");
pub const TAG_DSM_TAG1: TaggedHashDomain<'static> = TaggedHashDomain::from_static(b"DSM/tag1");
pub const TAG_DSM_TAG2: TaggedHashDomain<'static> = TaggedHashDomain::from_static(b"DSM/tag2");
