#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Generate/check source-location evidence; a stale map fails refinement CI."""
import pathlib
import re
import subprocess
import sys
root = pathlib.Path(__file__).resolve().parents[1]
core = 'dsm_client/deterministic_state_machine/dsm/src/'
sdk = 'dsm_client/deterministic_state_machine/dsm_sdk/src/'
model = {
'SphincsVariant':'Variant', 'Params':'Params', 'param_set':'params',
'compute_wots_len2':'Params.len (finite six-variant specialization)',
'sizes':'params / signature_sizes', 'Adrs':'Adrs / be_roundtrip / type_clears',
'set_layer':'Adrs.layer', 'set_tree':'Adrs.tree / be8',
'set_type_and_clear':'Adrs.setType / type_clears', 'set_keypair':'Adrs.keypair',
'keypair':'Adrs.keypair', 'set_chain':'Adrs.chain', 'set_tree_height':'Adrs.chain',
'set_hash':'Adrs.hash', 'set_tree_index':'Adrs.hash', 'tree_index':'Adrs.hash',
'as_bytes':'Adrs.bytes / be_roundtrip / address_width',
'PublicCtx':'deriveKey(thash)', 'SecretCtx':'deriveKey(prf)',
'derive_key':'deriveKey', 'keyed':'keyed', 'thash':'thash', 'prf':'prf',
'prf_msg':'sign (deriveKey(prf-msg) then keyed)', 'h_msg':'hmsg',
'base_2b':'base2b / base2b_digit_bound', 'to_int':'toInt', 'to_byte':'be / be_roundtrip',
'wots_digits':'wotsDigits / wots_digit_count / wots_digit_bound / checksum_width_three',
'chain':'chain / chain_composes / chain_width / wots_generated_digit_recovers',
'wots_sk_adrs':'wotsSign / wotsPkgen', 'wots_compress':'wotsCompress',
'wots_pkgen':'wotsPkgen / wots_pkgen_width', 'wots_sign':'wotsSign', 'wots_pk_from_sig':'wotsPkFromSig',
'xmss_node':'xmssNode / xmss_node_parent / xmss_node_width / xmss_signer_tree_path', 'xmss_sign':'xmssSign', 'xmss_pk_from_sig':'xmssPkFromSig / xmss_authentication_path_recovers_tree',
'next_layer':'nextLayer / next_layer_reconstructs', 'ht_sign':'htSign',
'ht_verify':'htRoot / verification_structure', 'fors_sk_gen':'forsSecret',
'fors_node':'forsNode / fors_node_parent / fors_node_width / fors_signer_tree_path', 'fors_sign':'forsSign', 'fors_pk_from_sig':'forsPkFromSig / fors_authentication_path_recovers_tree',
'Indices':'Indices', 'split_digest':'splitDigest / digest_tree_bounded / digest_leaf_bounded',
'fors_adrs':'verify/sign (FORS address)', 'SphincsKeyPair':'generateKeypair pair of bytes',
'generate_keypair_from_seed':'generateKeypair', 'sign':'sign', 'verify':'verify / verification_structure',
'public_key_bytes':'2*Params.n', 'secret_key_bytes':'4*Params.n', 'signature_bytes':'Params.sigBytes',
'sphincs_sign':'sign(.spx256f)', 'sphincs_verify':'verify(.spx256f)'
}
files = {
'crates/dsm-sphincs/src/lib.rs':model,
core+'crypto/sphincs.rs':{'generate_keypair':'OS entropy boundary; unproved','generate_keypair_from_seed':'generateKeypair','sign':'sign','verify':'verify','sphincs_sign':'sign(.spx256f)','sphincs_verify':'verify(.spx256f)'},
core+'crypto/signatures.rs':{'generate_from_entropy':'entropy normalization; unproved','generate_from_entropy_with_params':'H(DSM/sphincs-seed,entropy) then generateKeypair; unproved','sign':'raw-byte forwarding; unproved','verify':'raw-byte forwarding; unproved','sign_message_with_params':'raw-byte forwarding; unproved','verify_message_with_params':'raw-byte forwarding; unproved'},
core+'crypto/ephemeral_key.rs':{'derive_ephemeral_seed':'ekSeedInput (tested encoding)','derive_ek_cert_hash':'ekCertInput / cert_preimage_binding','sign_ek_cert':'sign(.spx256f) on hash of ekCertInput','verify_ek_cert':'verify(.spx256f) on hash of ekCertInput'},
core+'core/identity/genesis_v2.rs':{'derive_ak_seed':'authority-policy-bound KDF; unproved','derive_device_ak_keypair':'seed-to-AK call path; unproved','derive_devid':'devidInput / devid_preimage_binding','derive_smaster':'master seed KDF; unproved'},
core+'bilateral/identity_binding.rs':{'binding_digest':'identityBindingInput / identity_preimage_binding','verify_kyber_identity_binding':'key width + verify; tested by existing suite, not proved'},
core+'sofi/derive.rs':{'setup_signing_digest':'domainInput + opaque CCB; unproved CCB refinement','precommit_signing_digest':'domainInput + opaque CCB; unproved CCB refinement','fulfillment_signing_digest':'domainInput + opaque CCB; unproved CCB refinement','resolution_claim_signing_digest':'resolutionClaimInput; untested CCB refinement'},
core+'economic/claim.rs':{'signing_digest':'root claim canonical signing digest; unproved'},
core+'economic/claim_envelope.rs':{'sign_economic_root_claim':'claim auth + key binding; unproved'},
core+'economic/successor_evidence.rs':{'substrate_signing_digest':'substrate-bound digest; unproved'},
core+'types/operations.rs':{'signing_bytes':'operation-specific canonical signing bytes; unproved'},
core+'types/receipt_types.rs':{'relationship_finalized_signing_target':'finalized relationship digest; unproved'},
sdk+'jni/unified_protobuf_bridge.rs':{'process_envelope_v3':'JNI → ingress; unproved','dispatch_envelope_via_ingress':'ingress dispatch; unproved','Java_com_dsm_wallet_bridge_UnifiedNativeApi_processEnvelopeV3':'JNI byte-array and unwind boundary; unproved'},
sdk+'handlers/core_bridge_adapters.rs':{'install_app_router_adapter':'router installation; unproved'},
sdk+'sdk/sofi_flow.rs':{},
'crates/dsm-anchor-secure-monitor/src/anchor_glue.rs':{},
'crates/dsm-anchor-pico/src/main.rs':{},
sdk+'bluetooth/anchor_accept.rs':{},
}
rows = ['rust_file\trust_line\trust_symbol\tlean_definition_or_obligation\tgit_blob']
for path, symbols in files.items():
    data = (root/path).read_text()
    blob = subprocess.check_output(['git','hash-object',path],cwd=root,text=True).strip()
    for symbol, lean in symbols.items():
        pattern = r'\b(?:fn|struct|enum)\s+'+re.escape(symbol)+r'\b'
        hit = re.search(pattern,data)
        if hit is None: raise SystemExit(f'missing source symbol {path}::{symbol}')
        line = data[:hit.start()].count('\n')+1
        rows.append(f'{path}\t{line}\t{symbol}\t{lean}\t{blob}')
    if not symbols: rows.append(f'{path}\t1\tmodule boundary\tunproved\t{blob}')
result = '\n'.join(rows)+'\n'
path = root/'specs/requirements/SPHINCS_REFINEMENT_MAP.tsv'
if '--check' in sys.argv:
    if not path.exists() or path.read_text()!=result: raise SystemExit('source map is stale; regenerate and review evidence')
    print(f'source map: {len(rows)-1} source anchors current')
else: path.write_text(result)
# A reproducible reference inventory includes test callers explicitly; it
# does not pretend lexical references are a proof of runtime reachability.
pattern = r'sphincs_(sign|verify)|sphincs::(sign|verify|generate)|SphincsVariant|dsm_sphincs'
call_rows = ['file\tline\tlexical_reference']
for base in [root/'crates',root/'dsm_client/deterministic_state_machine']:
    for file in sorted(base.rglob('*.rs')):
        if 'target' in file.parts: continue
        for line,text in enumerate(file.read_text().splitlines(),1):
            if re.search(pattern,text): call_rows.append(f'{file.relative_to(root)}\t{line}\t{text.strip()}')
call_result='\n'.join(call_rows)+'\n'
call_path=root/'specs/requirements/SPHINCS_CALLERS.tsv'
if '--check' in sys.argv:
    if not call_path.exists() or call_path.read_text()!=call_result: raise SystemExit('caller inventory is stale')
    print(f'caller inventory: {len(call_rows)-1} lexical references current')
else: call_path.write_text(call_result)
