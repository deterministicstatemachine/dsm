#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
set -euo pipefail
cd "$(dirname "$0")/.."
export LEAN_PATH="$PWD/target/sphincs-lean:$PWD/lean4"
python3 scripts/sphincs_source_map.py --check
mkdir -p target/sphincs-refinement target/sphincs-lean/Sphincs
lean -DwarningAsError=true -o target/sphincs-lean/Sphincs/Model.olean lean4/Sphincs/Model.lean
lean -DwarningAsError=true -o target/sphincs-lean/Sphincs/Proofs.olean lean4/Sphincs/Proofs.lean
lean -DwarningAsError=true -o target/sphincs-lean/Sphincs/Signer.olean lean4/Sphincs/Signer.lean
lean -DwarningAsError=true -o target/sphincs-lean/Sphincs/SecurityGames.olean lean4/Sphincs/SecurityGames.lean
lean -DwarningAsError=true --run lean4/Sphincs/SecurityGameChecks.lean
lean -DwarningAsError=true -o target/sphincs-lean/Sphincs/SeedHybrid.olean lean4/Sphincs/SeedHybrid.lean
lean -DwarningAsError=true --run lean4/Sphincs/SeedHybridChecks.lean
lean -DwarningAsError=true -o target/sphincs-lean/Sphincs/OracleAgree.olean lean4/Sphincs/OracleAgree.lean
lean -DwarningAsError=true -o target/sphincs-lean/Sphincs/PrfHybrid.olean lean4/Sphincs/PrfHybrid.lean
lean -DwarningAsError=true -o target/sphincs-lean/Sphincs/MsgPrfHybrid.olean lean4/Sphincs/MsgPrfHybrid.lean
lean -DwarningAsError=true -o target/sphincs-lean/Sphincs/AddressInjective.olean lean4/Sphincs/AddressInjective.lean
lean -DwarningAsError=true -o target/sphincs-lean/Sphincs/WrapperInjective.olean lean4/Sphincs/WrapperInjective.lean
lean -DwarningAsError=true -o target/sphincs-lean/Sphincs/RequestLog.olean lean4/Sphincs/RequestLog.lean
lean -DwarningAsError=true -o target/sphincs-lean/Sphincs/AddressRange.olean lean4/Sphincs/AddressRange.lean
lean -DwarningAsError=true -o target/sphincs-lean/Sphincs/TweakUse.olean lean4/Sphincs/TweakUse.lean
lean -DwarningAsError=true -o target/sphincs-lean/Sphincs/Extraction.olean lean4/Sphincs/Extraction.lean
lean -DwarningAsError=true -o target/sphincs-lean/Sphincs/WotsChecksum.olean lean4/Sphincs/WotsChecksum.lean
lean -DwarningAsError=true -o target/sphincs-lean/Sphincs/WotsExtraction.olean lean4/Sphincs/WotsExtraction.lean
lean -DwarningAsError=true -o target/sphincs-lean/Sphincs/XmssExtraction.olean lean4/Sphincs/XmssExtraction.lean
lean -DwarningAsError=true -o target/sphincs-lean/Sphincs/HtExtraction.olean lean4/Sphincs/HtExtraction.lean
lean -DwarningAsError=true -o target/sphincs-lean/Sphincs/ForsExtraction.olean lean4/Sphincs/ForsExtraction.lean
lean -DwarningAsError=true -o target/sphincs-lean/Sphincs/ForgeryExtract.olean lean4/Sphincs/ForgeryExtract.lean
lean -DwarningAsError=true -o target/sphincs-lean/Sphincs/ExtractionRange.olean lean4/Sphincs/ExtractionRange.lean
lean -DwarningAsError=true -o target/sphincs-lean/Sphincs/ExtractionLog.olean lean4/Sphincs/ExtractionLog.lean
lean -DwarningAsError=true -o target/sphincs-lean/Sphincs/LogExtraction.olean lean4/Sphincs/LogExtraction.lean
lean -DwarningAsError=true -o target/sphincs-lean/Sphincs/ForgeryExtractExp.olean lean4/Sphincs/ForgeryExtractExp.lean
lean -DwarningAsError=true -o target/sphincs-lean/Sphincs/EufCmaReduction.olean lean4/Sphincs/EufCmaReduction.lean
lean -DwarningAsError=true -o target/sphincs-lean/Sphincs/MultiKey.olean lean4/Sphincs/MultiKey.lean
lean -DwarningAsError=true --run lean4/Sphincs/MultiKeyChecks.lean
lean -DwarningAsError=true -o target/sphincs-lean/Sphincs/WrapperReduction.olean lean4/Sphincs/WrapperReduction.lean
lean -DwarningAsError=true --run lean4/Sphincs/WrapperReductionChecks.lean
lean -DwarningAsError=true -o target/sphincs-lean/Sphincs/Transcript.olean lean4/Sphincs/Transcript.lean
lean -DwarningAsError=true -o target/sphincs-lean/Sphincs/Blake3.olean lean4/Sphincs/Blake3.lean
lean -DwarningAsError=true lean4/Sphincs/Blake3Proofs.lean
lean -DwarningAsError=true -o target/sphincs-lean/Sphincs/Blake3Vectors.olean lean4/Sphincs/Blake3Vectors.lean
lean -DwarningAsError=true lean4/Sphincs/CrossCheck.lean
DSM_SPHINCS_VECTOR_DIR="$PWD/target/sphincs-refinement" \
  cargo test --locked -p dsm-sphincs refinement_vectors::export_refinement_vectors -- --exact
DSM_SPHINCS_VECTOR_DIR="$PWD/target/sphincs-refinement" \
  cargo test --locked -p dsm --lib crypto::sphincs_refinement_tests::export_wrapper_vectors -- --exact
lean --run lean4/Sphincs/CrossCheck.lean target/sphincs-refinement/*.bin
bash scripts/check_sphincs_blake3.sh target/sphincs-refinement/*.bin
python3 scripts/sphincs_refinement_controls.py
