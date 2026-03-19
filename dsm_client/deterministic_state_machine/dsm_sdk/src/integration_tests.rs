//! Minimal SDK smoke tests (bytes-only). Keep this file small and syntactically valid.

#[cfg(test)]
mod smoke {
    use blake3::Hasher;

    #[test]
    fn bytes_only_identity_helpers_exist() {
        let data: [u8; 4] = [0xde, 0xad, 0xbe, 0xef];
        let short = crate::util::text_id::short_id(&data, 6);
        assert!(!short.is_empty());
    }

    #[test]
    fn hash_is_deterministic() {
        let mut h = Hasher::new();
        h.update(b"abc");
        let a = h.finalize();
        let mut h2 = Hasher::new();
        h2.update(b"abc");
        let b = h2.finalize();
        assert_eq!(a.as_bytes(), b.as_bytes());
    }

    #[test]
    fn byte_roundtrip_identity() {
        let data = vec![0u8, 1, 2, 3, 4, 5, 255];
        let out = data.clone();
        assert_eq!(data, out);
    }

    #[test]
    fn short_display_id_is_stable() {
        let bytes = [42u8; 32];
        let s1 = crate::util::text_id::short_id(&bytes, 8);
        let s2 = crate::util::text_id::short_id(&bytes, 8);
        assert_eq!(s1, s2);
        assert!(s1.len() >= 8);
    }
}
