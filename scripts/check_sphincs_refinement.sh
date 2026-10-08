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
lean -DwarningAsError=true -o target/sphincs-lean/Sphincs/WrapperForgery.olean lean4/Sphincs/WrapperForgery.lean
lean -DwarningAsError=true -o target/sphincs-lean/Sphincs/QueryCost.olean lean4/Sphincs/QueryCost.lean
lean -DwarningAsError=true --run lean4/Sphincs/QueryCostChecks.lean
lean -DwarningAsError=true -o target/sphincs-lean/Sphincs/RomTape.olean lean4/Sphincs/RomTape.lean
lean -DwarningAsError=true -o target/sphincs-lean/Sphincs/RomOracle.olean lean4/Sphincs/RomOracle.lean
lean -DwarningAsError=true -o target/sphincs-lean/Sphincs/RomRoles.olean lean4/Sphincs/RomRoles.lean
lean -DwarningAsError=true -o target/sphincs-lean/Sphincs/RomItsr.olean lean4/Sphincs/RomItsr.lean
lean -DwarningAsError=true -o target/sphincs-lean/Sphincs/RomBound.olean lean4/Sphincs/RomBound.lean
lean -DwarningAsError=true -o target/sphincs-lean/Sphincs/RomCoord.olean lean4/Sphincs/RomCoord.lean
lean -DwarningAsError=true -o target/sphincs-lean/Sphincs/RomSym.olean lean4/Sphincs/RomSym.lean
lean -DwarningAsError=true -o target/sphincs-lean/Sphincs/RomHidden.olean lean4/Sphincs/RomHidden.lean
lean -DwarningAsError=true -o target/sphincs-lean/Sphincs/RomSample.olean lean4/Sphincs/RomSample.lean
lean -DwarningAsError=true -o target/sphincs-lean/Sphincs/RomSim.olean lean4/Sphincs/RomSim.lean
lean -DwarningAsError=true -o target/sphincs-lean/Sphincs/RomSigner.olean lean4/Sphincs/RomSigner.lean
lean -DwarningAsError=true -o target/sphincs-lean/Sphincs/RomGame.olean lean4/Sphincs/RomGame.lean
lean -DwarningAsError=true -o target/sphincs-lean/Sphincs/RomEval.olean lean4/Sphincs/RomEval.lean
lean -DwarningAsError=true -o target/sphincs-lean/Sphincs/RomItsrA.olean lean4/Sphincs/RomItsrA.lean
lean -DwarningAsError=true -o target/sphincs-lean/Sphincs/RomDigest.olean lean4/Sphincs/RomDigest.lean
lean -DwarningAsError=true -o target/sphincs-lean/Sphincs/RomItsrGame.olean lean4/Sphincs/RomItsrGame.lean
lean -DwarningAsError=true -o target/sphincs-lean/Sphincs/RomProv.olean lean4/Sphincs/RomProv.lean
lean -DwarningAsError=true -o target/sphincs-lean/Sphincs/RomPath.olean lean4/Sphincs/RomPath.lean
lean -DwarningAsError=true -o target/sphincs-lean/Sphincs/RomExt.olean lean4/Sphincs/RomExt.lean
lean -DwarningAsError=true -o target/sphincs-lean/Sphincs/RomSecrecy.olean lean4/Sphincs/RomSecrecy.lean
lean -DwarningAsError=true -o target/sphincs-lean/Sphincs/RomSecGame.olean lean4/Sphincs/RomSecGame.lean
lean -DwarningAsError=true -o target/sphincs-lean/Sphincs/RomCover.olean lean4/Sphincs/RomCover.lean
lean -DwarningAsError=true -o target/sphincs-lean/Sphincs/RomFresh.olean lean4/Sphincs/RomFresh.lean
lean -DwarningAsError=true -o target/sphincs-lean/Sphincs/RomStruct.olean lean4/Sphincs/RomStruct.lean
lean -DwarningAsError=true -o target/sphincs-lean/Sphincs/RomPhi.olean lean4/Sphincs/RomPhi.lean
lean -DwarningAsError=true -o target/sphincs-lean/Sphincs/RomColl.olean lean4/Sphincs/RomColl.lean
lean -DwarningAsError=true --run lean4/Sphincs/RomChecks.lean
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
