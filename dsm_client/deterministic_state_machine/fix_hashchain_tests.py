import re
with open("dsm_sdk/src/sdk/hashchain_sdk.rs", "r") as f:
    c = f.read()

# remove imports if incorrect
c = c.replace("use dsm::core::state_machine::State;", "use dsm::types::device_state::RelationshipChainState;\nuse dsm::types::device_state::OperationRec;")

c = c.replace("fn make_genesis_state() -> State {", "fn make_genesis_state() -> RelationshipChainState {")
c = c.replace("fn make_add_data_state(prev_state: &State", "fn make_add_data_state(prev_state: &RelationshipChainState")
c = c.replace(") -> State {", ") -> RelationshipChainState {")
c = c.replace("let chain = vec![make_genesis_state()];", "let chain = vec![make_genesis_state()];")

# remove ignore
c = c.replace("#[ignore]\n    async fn", "async fn")
c = c.replace("#[ignore]\n    #[tokio::test]", "#[tokio::test]")

with open("dsm_sdk/src/sdk/hashchain_sdk.rs", "w") as f:
    f.write(c)
