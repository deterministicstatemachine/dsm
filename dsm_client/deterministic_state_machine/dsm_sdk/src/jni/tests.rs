#[cfg(test)]
mod tests {
    use crate::network;

    #[test]
    fn env_config_path_once_lock_is_idempotent() {
        // This should never panic and should be safe to call multiple times.
        network::set_env_config_path("/tmp/dsm_env_config_1.toml".to_string());
        network::set_env_config_path("/tmp/dsm_env_config_2.toml".to_string());

        // OnceLock keeps the first value.
        assert_eq!(
            network::get_env_config_path(),
            Some("/tmp/dsm_env_config_1.toml")
        );
    }
}
