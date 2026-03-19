use crate::serialization::canonical_bytes::CanonicalBytesWriter;

#[test]
fn canonical_writer_is_stable_for_same_inputs() {
    let mut w1 = CanonicalBytesWriter::new();
    w1.push_u32_le(42);
    w1.push_str("hello");
    w1.push_len_prefixed(&[1u8, 2, 3]);

    let mut w2 = CanonicalBytesWriter::new();
    w2.push_u32_le(42);
    w2.push_str("hello");
    w2.push_len_prefixed(&[1u8, 2, 3]);

    assert_eq!(w1.as_slice(), w2.as_slice());
}

#[test]
fn canonical_writer_has_unambiguous_length_prefixing() {
    // Without length prefixes, ["a","bc"] and ["ab","c"] are ambiguous if concatenated.
    let mut w_a = CanonicalBytesWriter::new();
    w_a.push_str("a");
    w_a.push_str("bc");

    let mut w_b = CanonicalBytesWriter::new();
    w_b.push_str("ab");
    w_b.push_str("c");

    assert_ne!(w_a.as_slice(), w_b.as_slice());
}
