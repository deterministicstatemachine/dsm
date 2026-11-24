//! Research build: the verifier's WHIR query table, against the prover's query search with the ring switch's map
//! error counted for two ring-switched claims (`RING_SWITCH_ERROR_NUMERATOR = 4`, `q_keccak`'s and `q_flock`'s). Every
//! table entry the search re-derives at every stacked size and rate: the deployed table keeps every level's error
//! within the 125-bit round-by-round target with the shared map. (Upstream's `whir_query_table_matches_the_search`
//! lives in the experimental prover's tests, which the research build's seventh table does not compile.)
use experimental_pcs::LOG_PACKING;
use experimental_pcs::whir_config::WhirSecurityConfig;

#[test]
fn the_deployed_query_table_holds_with_the_shared_map() {
    let mut entries = 0;
    for rate in verifier::MIN_LOG_INV_RATE..=verifier::MAX_LOG_INV_RATE {
        for log_n in verifier::MIN_STACKED_LOG..=verifier::MAX_STACKED_LOG {
            let config = WhirSecurityConfig::derive_config_with_log_inv_rate(log_n + LOG_PACKING, rate)
                .unwrap_or_else(|e| panic!("rate {rate}, log_n {log_n}: {e}"))
                .to_config()
                .unwrap_or_else(|e| panic!("rate {rate}, log_n {log_n}: {e}"));
            assert_eq!(
                verifier::whir_queries(log_n, rate),
                Some(&config.queries[..]),
                "rate {rate}, log_n {log_n}"
            );
            entries += 1;
        }
    }
    eprintln!("WHIR table: {entries} entries re-derived with the shared map");
}
