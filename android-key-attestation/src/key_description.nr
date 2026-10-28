// The key attestation extension (1.3.6.1.4.1.11129.2.1.17) of the leaf
// certificate: what the device's KeyMint says about the key.
//
// Schema (source.android.com/docs/security/features/keystore/attestation):
//   KeyDescription ::= SEQUENCE {
//     attestationVersion INTEGER, attestationSecurityLevel SecurityLevel,
//     keyMintVersion INTEGER, keyMintSecurityLevel SecurityLevel,
//     attestationChallenge OCTET STRING, uniqueId OCTET STRING,
//     softwareEnforced AuthorizationList, hardwareEnforced AuthorizationList }
//   SecurityLevel ::= ENUMERATED { Software (0), TrustedEnvironment (1), StrongBox (2) }
//   RootOfTrust ::= SEQUENCE { verifiedBootKey OCTET STRING, deviceLocked BOOLEAN,
//     verifiedBootState ENUMERATED { Verified (0), SelfSigned (1), Unverified (2),
//     Failed (3) }, verifiedBootHash OCTET STRING }
//   AttestationApplicationId ::= SEQUENCE { package_infos SET OF
//     AttestationPackageInfo, signature_digests SET OF OCTET STRING }
//   AttestationPackageInfo ::= SEQUENCE { package_name OCTET STRING, version INTEGER }
//
// WHAT IS REQUIRED, and what each stands in for. zkPassport's Android
// FaceMatch circuit reads only the package name here and gets the rest from a
// Play Integrity token (appRecognitionVerdict PLAY_RECOGNIZED, device verdict
// MEETS_DEVICE_INTEGRITY). This circuit has no Play Integrity token, so it
// asks the key attestation itself, as Google's verification guide does:
//   - attestationSecurityLevel and keyMintSecurityLevel are both
//     TrustedEnvironment or both StrongBox: the key is in secure hardware,
//     not a software keystore;
//   - softwareEnforced [709] attestationApplicationId names exactly one
//     package, ours, and exactly one signing-certificate SHA-256, Play's app
//     signing certificate for it: a sideloaded or re-signed copy (including
//     every debug build) is refused, the job PLAY_RECOGNIZED does there;
//   - hardwareEnforced [704] rootOfTrust: deviceLocked TRUE and
//     verifiedBootState Verified -- an unlocked bootloader or a modified OS
//     could drive the app's key to sign anything, the job
//     MEETS_DEVICE_INTEGRITY does there;
//   - hardwareEnforced [702] origin GENERATED (0): the key was made inside
//     KeyMint, not imported (zkPassport lists this as a TODO).
// attestationChallenge is not read: the statement is bound by the key's own
// signature over it, as in zkPassport, not by the challenge.
//
// [709] is filled in by the Android framework (keystore) and sits in
// softwareEnforced; [702] and [704] come from KeyMint and sit in
// hardwareEnforced. Each must appear exactly once in its list.

use crate::cert::context_element;
use app_attest::der::{bytes_at, der_element};

/// At most this many entries per AuthorizationList. Real leaves carry up to
/// about 15 in hardwareEnforced (tegu, Android 16).
global MAX_AUTH_ENTRIES: u32 = 24;

global TAG_ORIGIN: u32 = 702;
global TAG_ROOT_OF_TRUST: u32 = 704;
global TAG_APPLICATION_ID: u32 = 709;

pub global SECURITY_LEVEL_TEE: u8 = 1;
pub global SECURITY_LEVEL_STRONGBOX: u8 = 2;

/// (count, content start, content length) of entry `tag` in the
/// AuthorizationList whose content is [start, end).
fn find_entry<let N: u32>(buf: [u8; N], start: u32, end: u32, tag: u32) -> (u32, u32, u32) {
    let mut pos = start;
    let mut count: u32 = 0;
    let mut at: u32 = 0;
    let mut len: u32 = 0;
    for _ in 0..MAX_AUTH_ENTRIES {
        if pos < end {
            let (number, hl, cl) = context_element(buf, pos);
            if number == tag {
                count += 1;
                at = pos + hl;
                len = cl;
            }
            pos += hl + cl;
        }
    }
    assert(pos == end, "Authorization list has more entries than the circuit walks");
    (count, at, len)
}

/// [709]: OCTET STRING { SEQUENCE { SET { SEQUENCE { OCTET STRING package,
/// INTEGER version } }, SET { OCTET STRING digest } } }, with one package
/// and one digest, both ours.
fn check_application_id<let N: u32, let P: u32>(
    buf: [u8; N],
    at: u32,
    len: u32,
    package: [u8; P],
    signing_digest: [u8; 32],
) {
    let end = at + len;
    let (ohl, ocl) = der_element(buf, at, 0x04);
    assert(at + ohl + ocl == end, "Application id length mismatch");
    let s = at + ohl;
    let (shl, scl) = der_element(buf, s, 0x30);
    assert(s + shl + scl == end, "Application id length mismatch");

    // package_infos: exactly one AttestationPackageInfo
    let p = s + shl;
    let (phl, pcl) = der_element(buf, p, 0x31);
    let p_end = p + phl + pcl;
    let i = p + phl;
    let (ihl, icl) = der_element(buf, i, 0x30);
    assert(i + ihl + icl == p_end, "Key belongs to more than one package");
    let n = i + ihl;
    let (nhl, ncl) = der_element(buf, n, 0x04);
    assert(ncl == P, "Key belongs to another app");
    assert(bytes_at(buf, n + nhl, package), "Key belongs to another app");
    let v = n + nhl + ncl;
    let (vhl, vcl) = der_element(buf, v, 0x02);
    assert(v + vhl + vcl == p_end, "Application id length mismatch");

    // signature_digests: exactly one SHA-256
    let (dhl, dcl) = der_element(buf, p_end, 0x31);
    assert(p_end + dhl + dcl == end, "Application id length mismatch");
    assert(
        bytes_at(buf, p_end + dhl, [0x04, 0x20]) & (dcl == 34),
        "App is not signed with exactly one certificate",
    );
    assert(
        bytes_at(buf, p_end + dhl + 2, signing_digest),
        "App is signed with another certificate",
    );
}

/// [704]: SEQUENCE { OCTET STRING key, BOOLEAN locked, ENUMERATED state, ... }.
fn check_root_of_trust<let N: u32>(buf: [u8; N], at: u32, len: u32) {
    let (shl, scl) = der_element(buf, at, 0x30);
    assert(at + shl + scl == at + len, "Root of trust length mismatch");
    let k = at + shl;
    let (khl, kcl) = der_element(buf, k, 0x04);
    let b = k + khl + kcl;
    // deviceLocked and verifiedBootState must lie inside the RootOfTrust.
    assert(b + 6 <= at + len, "Root of trust length mismatch");
    // DER encodes TRUE as FF; any other non-zero byte is BER, also TRUE.
    assert(bytes_at(buf, b, [0x01, 0x01]), "Root of trust has no deviceLocked");
    assert(buf[b + 2] != 0, "Device bootloader is unlocked");
    assert(bytes_at(buf, b + 3, [0x0a, 0x01]), "Root of trust has no verifiedBootState");
    assert(buf[b + 5] == 0, "Device boot state is not Verified");
}

/// What the KeyDescription said, for the caller.
pub struct KeyDescription {
    pub security_level: u8,
}

/// Check the KeyDescription in `buf[at .. at + len)` (the extension's value).
pub fn check_key_description<let N: u32, let P: u32>(
    buf: [u8; N],
    at: u32,
    len: u32,
    package: [u8; P],
    signing_digest: [u8; 32],
) -> KeyDescription {
    let (khl, kcl) = der_element(buf, at, 0x30);
    assert(khl + kcl == len, "Key description length mismatch");
    let mut p = at + khl;

    let (h1, c1) = der_element(buf, p, 0x02); // attestationVersion
    p += h1 + c1;
    assert(bytes_at(buf, p, [0x0a, 0x01]), "Attestation security level is not one byte");
    let level = buf[p + 2];
    assert(
        (level == SECURITY_LEVEL_TEE) | (level == SECURITY_LEVEL_STRONGBOX),
        "Key is not in secure hardware",
    );
    p += 3;
    let (h2, c2) = der_element(buf, p, 0x02); // keyMintVersion
    p += h2 + c2;
    assert(bytes_at(buf, p, [0x0a, 0x01]), "KeyMint security level is not one byte");
    assert(buf[p + 2] == level, "KeyMint and attestation security levels differ");
    p += 3;
    let (h3, c3) = der_element(buf, p, 0x04); // attestationChallenge
    p += h3 + c3;
    let (h4, c4) = der_element(buf, p, 0x04); // uniqueId
    p += h4 + c4;

    let (shl, scl) = der_element(buf, p, 0x30); // softwareEnforced
    let sw_start = p + shl;
    let sw_end = sw_start + scl;
    p = sw_end;
    let (hhl, hcl) = der_element(buf, p, 0x30); // hardwareEnforced
    let hw_start = p + hhl;
    let hw_end = hw_start + hcl;
    assert(hw_end == at + len, "Key description has fields after hardwareEnforced");

    let (app_count, app_at, app_len) = find_entry(buf, sw_start, sw_end, TAG_APPLICATION_ID);
    assert(app_count == 1, "Key description names no single application");
    check_application_id(buf, app_at, app_len, package, signing_digest);

    let (rot_count, rot_at, rot_len) = find_entry(buf, hw_start, hw_end, TAG_ROOT_OF_TRUST);
    assert(rot_count == 1, "Key description has no hardware root of trust");
    check_root_of_trust(buf, rot_at, rot_len);

    let (origin_count, origin_at, _) = find_entry(buf, hw_start, hw_end, TAG_ORIGIN);
    assert(
        (origin_count == 1) & bytes_at(buf, origin_at, [0x02, 0x01, 0x00]),
        "Key was not generated in secure hardware",
    );

    KeyDescription { security_level: level }
}
