#!/bin/bash
# Which code refuses each Android refusal in oidc-domain-attestation-android's
# acceptance run: for each case, ONE assert in android-key-attestation (or
# statement-signer's Android check) is removed or neutralised in a mutant
# copy, and the named fixture must then be ACCEPTED. A fixture the mutant
# still refuses was refused by something else, and its acceptance case proved
# nothing about that assert.
#
#   scripts/android-key-attestation/mutation-check.sh [fixture-regex]
#
# Needs the synthetic-anchors copy and its fixtures:
#   oidc-domain-attestation-android/scripts/post-build.sh (or its steps 2-3).
# The mechanics are scripts/statement-signer/mutation-check.sh's.
set -u
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CIRCUITS="$(cd "$SCRIPT_DIR/../.." && pwd)"
CASES=$(mktemp)
trap 'rm -f "$CASES"' EXIT
cat > "$CASES" <<'CASES'
replace~        std::ecdsa_secp256r1::verify_signature(key_x, key_y, statement_sig, sha256::digest(statement)),~        true | std::ecdsa_secp256r1::verify_signature(key_x, key_y, statement_sig, sha256::digest(statement)),~stmt_coinbase_replay
replace~        std::ecdsa_secp256r1::verify_signature(key_x, key_y, statement_sig, sha256::digest(statement)),~        true | std::ecdsa_secp256r1::verify_signature(key_x, key_y, statement_sig, sha256::digest(statement)),~stmt_other_key_vouched
replace~        std::ecdsa_secp256r1::verify_signature(key_x, key_y, statement_sig, sha256::digest(statement)),~        true | std::ecdsa_secp256r1::verify_signature(key_x, key_y, statement_sig, sha256::digest(statement)),~stmt_signed_by_other_key
replace~    assert(ncl == P, "Key belongs to another app");~    assert(true, "Key belongs to another app");~other_package
replace~    assert(bytes_at(buf, n + nhl, package), "Key belongs to another app");~    assert(true, "Key belongs to another app");~two_packages
replace~    assert(i + ihl + icl == p_end, "Key belongs to more than one package");~    assert(true, "Key belongs to more than one package");~two_packages
replace~        bytes_at(buf, p_end + dhl + 2, signing_digest),~        true,~debug_signing_certificate
replace~        bytes_at(buf, p_end + dhl, [0x04, 0x20]) & (dcl == 34),~        true,~two_signing_certificates
replace~    assert(buf[b + 2] != 0, "Device bootloader is unlocked");~    assert(true, "Device bootloader is unlocked");~bootloader_unlocked
replace~    assert(buf[b + 5] == 0, "Device boot state is not Verified");~    assert(true, "Device boot state is not Verified");~boot_self_signed
replace~    assert(buf[b + 5] == 0, "Device boot state is not Verified");~    assert(true, "Device boot state is not Verified");~boot_unverified
replace~        (level == SECURITY_LEVEL_TEE) | (level == SECURITY_LEVEL_STRONGBOX),~        true,~software_key
replace~    assert(buf[p + 2] == level, "KeyMint and attestation security levels differ");~    assert(true, "KeyMint and attestation security levels differ");~software_keymint_under_tee
replace~        (origin_count == 1) & bytes_at(buf, origin_at, [0x02, 0x01, 0x00]),~        true,~imported_key
replace~    assert(rot_count == 1, "Key description has no hardware root of trust");~    assert(true, "Key description has no hardware root of trust");~no_root_of_trust
replace~    assert(app_count == 1, "Key description names no single application");~    assert(true, "Key description names no single application");~app_id_twice
replace~    assert(now <= t.not_after, "Certificate has expired at now");~    assert(true, "Certificate has expired at now");~att_expired
replace~    assert(now <= t.not_after, "Certificate has expired at now");~    assert(true, "Certificate has expired at now");~ca3_expired
replace~    assert(t.not_before <= now, "Certificate is not valid yet at now");~    assert(true, "Certificate is not valid yet at now");~att_not_yet_valid
replace~    assert(t.not_before <= now, "Certificate is not valid yet at now");~    assert(true, "Certificate is not valid yet at now");~ca2_not_yet_valid
delete~Attestation key was not remotely provisioned~att_not_remotely_provisioned
delete~Attestation key certificate carries a key description~att_carries_key_description
replace~        verify_intermediate_signature(root_x, root_y, chain.ca2_tbs, chain.ca2_tbs_len, r2, s2),~        true | verify_intermediate_signature(root_x, root_y, chain.ca2_tbs, chain.ca2_tbs_len, r2, s2),~other_root
replace~        verify_intermediate_signature(ca2_x, ca2_y, chain.ca3_tbs, chain.ca3_tbs_len, r3, s3),~        true | verify_intermediate_signature(ca2_x, ca2_y, chain.ca3_tbs, chain.ca3_tbs_len, r3, s3),~ca3_signed_by_other_key
replace~        std::ecdsa_secp256r1::verify_signature(ca3_x, ca3_y, chain.att_sig, att_digest),~        true | std::ecdsa_secp256r1::verify_signature(ca3_x, ca3_y, chain.att_sig, att_digest),~att_signed_by_other_key
replace~        std::ecdsa_secp256r1::verify_signature(att_x, att_y, chain.leaf_sig, leaf_digest),~        true | std::ecdsa_secp256r1::verify_signature(att_x, att_y, chain.leaf_sig, leaf_digest),~leaf_signed_by_other_key
CASES
"$CIRCUITS/scripts/statement-signer/mutation-check.sh" oidc-domain-attestation-android "$CASES" "${1:-}"
