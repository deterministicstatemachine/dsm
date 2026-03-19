use dsm_sdk::util::text_id;

fn main() {
    let bytes = vec![
        1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
        26, 27, 28, 29, 30, 31, 32,
    ];
    let b32 = text_id::encode_base32_crockford(&bytes);
    // Strict policy: base32 Crockford only (0-9,A-H,J-K,M-N,P-T,V-Z with substitutions). No dotted-decimal anywhere.
    println!("Bytes: {:?}", bytes);
    println!("Base32: {}", b32);
    assert!(!b32.contains('.'));
}
