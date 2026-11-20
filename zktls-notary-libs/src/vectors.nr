// Generated test vectors. Fake values only.
// <NAME>_C  = SHA-256(body || BLINDER), the whole body.
// <NAME>_P<n>_C = SHA-256(body[0..n] || BLINDER), a prefix commitment.
// Computed outside the circuit.

pub global BLINDER: [u8; 16] =
    [160, 161, 162, 163, 164, 165, 166, 167, 168, 169, 170, 171, 172, 173, 174, 175];

pub global OIDC_ADULT: str<191> = r#"{"sub":"4012345678","nickname":"테스트","picture":"https://k.kakaocdn.net/dn/abc/img_640x640.jpg","email":"user@example.com","email_verified":true,"gender":"male","birthdate":"1990-05-17"}"#;
pub global OIDC_ADULT_C: [u8; 32] = [
    249, 27, 45, 132, 21, 46, 10, 186, 230, 224, 3, 72, 95, 102, 82, 75, 75, 226, 180, 185, 134, 19,
    250, 243, 177, 200, 54, 6, 89, 236, 42, 145,
];
pub global OIDC_ADULT_SUB: u32 = 8;
pub global OIDC_ADULT_BIRTHDATE: u32 = 179;
pub global OIDC_ADULT_GENDER: u32 = 160;
pub global OIDC_ADULT_EMAIL_VERIFIED: u32 = 145;

pub global OIDC_YEARONLY: str<185> = r#"{"sub":"4012345678","nickname":"테스트","picture":"https://k.kakaocdn.net/dn/abc/img_640x640.jpg","email":"user@example.com","email_verified":true,"gender":"male","birthdate":"1990"}"#;
pub global OIDC_YEARONLY_C: [u8; 32] = [
    187, 90, 111, 86, 6, 229, 111, 190, 200, 69, 111, 193, 8, 9, 209, 202, 177, 56, 99, 12, 102, 99,
    27, 205, 188, 80, 95, 79, 74, 220, 22, 120,
];
pub global OIDC_YEARONLY_SUB: u32 = 8;
pub global OIDC_YEARONLY_BIRTHDATE: u32 = 179;
pub global OIDC_YEARONLY_GENDER: u32 = 160;
pub global OIDC_YEARONLY_EMAIL_VERIFIED: u32 = 145;

pub global OIDC_MINOR: str<191> = r#"{"sub":"4012345678","nickname":"테스트","picture":"https://k.kakaocdn.net/dn/abc/img_640x640.jpg","email":"user@example.com","email_verified":true,"gender":"male","birthdate":"2010-05-17"}"#;
pub global OIDC_MINOR_C: [u8; 32] = [
    32, 145, 145, 144, 75, 3, 132, 237, 254, 247, 132, 88, 214, 121, 124, 106, 163, 209, 131, 251,
    131, 169, 253, 23, 177, 151, 73, 14, 224, 214, 186, 239,
];
pub global OIDC_MINOR_SUB: u32 = 8;
pub global OIDC_MINOR_BIRTHDATE: u32 = 179;
pub global OIDC_MINOR_GENDER: u32 = 160;
pub global OIDC_MINOR_EMAIL_VERIFIED: u32 = 145;

pub global OIDC_ZEROYEAR: str<191> = r#"{"sub":"4012345678","nickname":"테스트","picture":"https://k.kakaocdn.net/dn/abc/img_640x640.jpg","email":"user@example.com","email_verified":true,"gender":"male","birthdate":"0000-11-30"}"#;
pub global OIDC_ZEROYEAR_C: [u8; 32] = [
    95, 227, 111, 142, 23, 25, 25, 248, 180, 12, 221, 229, 67, 6, 76, 96, 53, 208, 197, 254, 132,
    160, 23, 173, 113, 224, 3, 217, 197, 63, 25, 235,
];
pub global OIDC_ZEROYEAR_SUB: u32 = 8;
pub global OIDC_ZEROYEAR_BIRTHDATE: u32 = 179;
pub global OIDC_ZEROYEAR_GENDER: u32 = 160;
pub global OIDC_ZEROYEAR_EMAIL_VERIFIED: u32 = 145;

pub global OIDC_EXACT19: str<191> = r#"{"sub":"4012345678","nickname":"테스트","picture":"https://k.kakaocdn.net/dn/abc/img_640x640.jpg","email":"user@example.com","email_verified":true,"gender":"male","birthdate":"2007-11-16"}"#;
pub global OIDC_EXACT19_C: [u8; 32] = [
    197, 255, 194, 8, 168, 80, 101, 26, 11, 55, 70, 193, 33, 66, 229, 152, 125, 231, 44, 219, 106,
    253, 93, 79, 239, 3, 167, 64, 67, 63, 66, 137,
];
pub global OIDC_EXACT19_SUB: u32 = 8;
pub global OIDC_EXACT19_BIRTHDATE: u32 = 179;
pub global OIDC_EXACT19_GENDER: u32 = 160;
pub global OIDC_EXACT19_EMAIL_VERIFIED: u32 = 145;

pub global OIDC_DAYSHORT: str<191> = r#"{"sub":"4012345678","nickname":"테스트","picture":"https://k.kakaocdn.net/dn/abc/img_640x640.jpg","email":"user@example.com","email_verified":true,"gender":"male","birthdate":"2007-11-17"}"#;
pub global OIDC_DAYSHORT_C: [u8; 32] = [
    61, 245, 175, 51, 170, 141, 235, 92, 153, 25, 89, 5, 186, 184, 174, 86, 37, 87, 51, 13, 80, 252,
    61, 168, 11, 249, 79, 28, 101, 129, 108, 157,
];
pub global OIDC_DAYSHORT_SUB: u32 = 8;
pub global OIDC_DAYSHORT_BIRTHDATE: u32 = 179;
pub global OIDC_DAYSHORT_GENDER: u32 = 160;
pub global OIDC_DAYSHORT_EMAIL_VERIFIED: u32 = 145;

pub global OIDC_NICKATTACK: str<212> = r#"{"sub":"4012345678","nickname":"x\",\"birthdate\":\"1990-01-01","picture":"https://k.kakaocdn.net/dn/abc/img_640x640.jpg","email":"user@example.com","email_verified":true,"gender":"male","birthdate":"2010-01-01"}"#;
pub global OIDC_NICKATTACK_C: [u8; 32] = [
    106, 165, 31, 38, 32, 44, 27, 172, 100, 40, 98, 173, 75, 201, 194, 138, 120, 118, 190, 243, 36,
    227, 4, 110, 212, 228, 167, 95, 148, 209, 42, 72,
];
pub global OIDC_NICKATTACK_SUB: u32 = 8;
pub global OIDC_NICKATTACK_BIRTHDATE: u32 = 200;
pub global OIDC_NICKATTACK_GENDER: u32 = 181;
pub global OIDC_NICKATTACK_EMAIL_VERIFIED: u32 = 166;
pub global OIDC_NICKATTACK_FAKE: u32 = 50;

pub global OIDC_NESTED: str<228> = r#"{"sub":"4012345678","nickname":"테스트","picture":"https://k.kakaocdn.net/dn/abc/img_640x640.jpg","email":"user@example.com","email_verified":true,"gender":"male","profile":{"birthdate":"1990-05-17"},"birthdate":"2010-05-17"}"#;
pub global OIDC_NESTED_C: [u8; 32] = [
    157, 9, 41, 235, 85, 1, 114, 26, 226, 55, 12, 32, 172, 30, 140, 205, 173, 238, 234, 71, 70, 239,
    28, 238, 181, 36, 166, 165, 162, 68, 68, 2,
];
pub global OIDC_NESTED_SUB: u32 = 8;
pub global OIDC_NESTED_BIRTHDATE: u32 = 216;
pub global OIDC_NESTED_GENDER: u32 = 160;
pub global OIDC_NESTED_EMAIL_VERIFIED: u32 = 145;
pub global OIDC_NESTED_FAKE: u32 = 190;

pub global OIDC_BRACKETS: str<188> = r#"{"sub":"4012345678","nickname":"a}]{[b","picture":"https://k.kakaocdn.net/dn/abc/img_640x640.jpg","email":"user@example.com","email_verified":true,"gender":"male","birthdate":"1990-05-17"}"#;
pub global OIDC_BRACKETS_C: [u8; 32] = [
    58, 125, 145, 231, 39, 244, 139, 23, 81, 117, 100, 89, 117, 143, 72, 97, 49, 81, 33, 173, 77,
    52, 174, 240, 26, 0, 33, 202, 86, 38, 236, 72,
];
pub global OIDC_BRACKETS_SUB: u32 = 8;
pub global OIDC_BRACKETS_BIRTHDATE: u32 = 176;
pub global OIDC_BRACKETS_GENDER: u32 = 157;
pub global OIDC_BRACKETS_EMAIL_VERIFIED: u32 = 142;

pub global OIDC_FEMALE: str<193> = r#"{"sub":"4012345678","nickname":"테스트","picture":"https://k.kakaocdn.net/dn/abc/img_640x640.jpg","email":"user@example.com","email_verified":true,"gender":"female","birthdate":"1990-05-17"}"#;
pub global OIDC_FEMALE_C: [u8; 32] = [
    219, 250, 213, 62, 165, 177, 210, 8, 110, 14, 97, 245, 200, 92, 221, 34, 253, 215, 114, 108,
    187, 242, 98, 50, 125, 112, 30, 43, 248, 188, 62, 76,
];
pub global OIDC_FEMALE_SUB: u32 = 8;
pub global OIDC_FEMALE_BIRTHDATE: u32 = 181;
pub global OIDC_FEMALE_GENDER: u32 = 160;
pub global OIDC_FEMALE_EMAIL_VERIFIED: u32 = 145;

pub global OIDC_UNVERIFIED: str<192> = r#"{"sub":"4012345678","nickname":"테스트","picture":"https://k.kakaocdn.net/dn/abc/img_640x640.jpg","email":"user@example.com","email_verified":false,"gender":"male","birthdate":"1990-05-17"}"#;
pub global OIDC_UNVERIFIED_C: [u8; 32] = [
    236, 207, 143, 209, 108, 57, 207, 125, 7, 6, 47, 224, 49, 2, 111, 75, 181, 136, 27, 214, 120,
    243, 140, 160, 4, 205, 113, 13, 140, 161, 69, 42,
];
pub global OIDC_UNVERIFIED_SUB: u32 = 8;
pub global OIDC_UNVERIFIED_BIRTHDATE: u32 = 180;
pub global OIDC_UNVERIFIED_GENDER: u32 = 161;
pub global OIDC_UNVERIFIED_EMAIL_VERIFIED: u32 = 145;

pub global ME_30: str<877> = r#"{"id":1234567890,"connected_at":"2025-01-01T00:00:00Z","properties":{"nickname":"테스트","profile_image":"https://k.kakaocdn.net/dn/abc/img_640x640.jpg","thumbnail_image":"https://k.kakaocdn.net/dn/abc/img_640x640.jpg"},"kakao_account":{"profile_needs_agreement":false,"profile":{"nickname":"테스트","thumbnail_image_url":"https://k.kakaocdn.net/dn/abc/img_640x640.jpg","profile_image_url":"https://k.kakaocdn.net/dn/abc/img_640x640.jpg","is_default_image":false,"is_default_nickname":false},"has_email":true,"email_needs_agreement":false,"is_email_valid":true,"is_email_verified":true,"email":"user@example.com","has_age_range":true,"age_range_needs_agreement":false,"age_range":"30~39","has_birthday":true,"birthday_needs_agreement":false,"birthday":"1130","birthday_type":"SOLAR","is_leap_month":false,"has_gender":true,"gender_needs_agreement":false,"gender":"male"}}"#;
pub global ME_30_C: [u8; 32] = [
    136, 241, 97, 190, 243, 115, 83, 103, 251, 199, 63, 49, 117, 121, 125, 103, 131, 42, 56, 77, 95,
    47, 248, 79, 177, 189, 116, 253, 167, 193, 140, 31,
];
pub global ME_30_ID: u32 = 6;
pub global ME_30_KA: u32 = 223;
pub global ME_30_PROPS: u32 = 55;
pub global ME_30_AGE_RANGE: u32 = 687;

pub global ME_15: str<877> = r#"{"id":1234567890,"connected_at":"2025-01-01T00:00:00Z","properties":{"nickname":"테스트","profile_image":"https://k.kakaocdn.net/dn/abc/img_640x640.jpg","thumbnail_image":"https://k.kakaocdn.net/dn/abc/img_640x640.jpg"},"kakao_account":{"profile_needs_agreement":false,"profile":{"nickname":"테스트","thumbnail_image_url":"https://k.kakaocdn.net/dn/abc/img_640x640.jpg","profile_image_url":"https://k.kakaocdn.net/dn/abc/img_640x640.jpg","is_default_image":false,"is_default_nickname":false},"has_email":true,"email_needs_agreement":false,"is_email_valid":true,"is_email_verified":true,"email":"user@example.com","has_age_range":true,"age_range_needs_agreement":false,"age_range":"15~19","has_birthday":true,"birthday_needs_agreement":false,"birthday":"1130","birthday_type":"SOLAR","is_leap_month":false,"has_gender":true,"gender_needs_agreement":false,"gender":"male"}}"#;
pub global ME_15_C: [u8; 32] = [
    240, 169, 39, 42, 207, 161, 109, 208, 123, 160, 52, 31, 191, 240, 96, 129, 28, 88, 170, 209,
    204, 21, 121, 88, 159, 149, 13, 41, 160, 23, 186, 40,
];
pub global ME_15_ID: u32 = 6;
pub global ME_15_KA: u32 = 223;
pub global ME_15_PROPS: u32 = 55;
pub global ME_15_AGE_RANGE: u32 = 687;

pub global ME_90: str<875> = r#"{"id":1234567890,"connected_at":"2025-01-01T00:00:00Z","properties":{"nickname":"테스트","profile_image":"https://k.kakaocdn.net/dn/abc/img_640x640.jpg","thumbnail_image":"https://k.kakaocdn.net/dn/abc/img_640x640.jpg"},"kakao_account":{"profile_needs_agreement":false,"profile":{"nickname":"테스트","thumbnail_image_url":"https://k.kakaocdn.net/dn/abc/img_640x640.jpg","profile_image_url":"https://k.kakaocdn.net/dn/abc/img_640x640.jpg","is_default_image":false,"is_default_nickname":false},"has_email":true,"email_needs_agreement":false,"is_email_valid":true,"is_email_verified":true,"email":"user@example.com","has_age_range":true,"age_range_needs_agreement":false,"age_range":"90~","has_birthday":true,"birthday_needs_agreement":false,"birthday":"1130","birthday_type":"SOLAR","is_leap_month":false,"has_gender":true,"gender_needs_agreement":false,"gender":"male"}}"#;
pub global ME_90_C: [u8; 32] = [
    35, 20, 161, 68, 53, 61, 209, 92, 125, 32, 27, 73, 179, 18, 216, 87, 126, 204, 29, 19, 19, 221,
    200, 168, 95, 244, 112, 82, 136, 184, 210, 94,
];
pub global ME_90_ID: u32 = 6;
pub global ME_90_KA: u32 = 223;
pub global ME_90_PROPS: u32 = 55;
pub global ME_90_AGE_RANGE: u32 = 687;

pub global ME_NOTILDE: str<874> = r#"{"id":1234567890,"connected_at":"2025-01-01T00:00:00Z","properties":{"nickname":"테스트","profile_image":"https://k.kakaocdn.net/dn/abc/img_640x640.jpg","thumbnail_image":"https://k.kakaocdn.net/dn/abc/img_640x640.jpg"},"kakao_account":{"profile_needs_agreement":false,"profile":{"nickname":"테스트","thumbnail_image_url":"https://k.kakaocdn.net/dn/abc/img_640x640.jpg","profile_image_url":"https://k.kakaocdn.net/dn/abc/img_640x640.jpg","is_default_image":false,"is_default_nickname":false},"has_email":true,"email_needs_agreement":false,"is_email_valid":true,"is_email_verified":true,"email":"user@example.com","has_age_range":true,"age_range_needs_agreement":false,"age_range":"30","has_birthday":true,"birthday_needs_agreement":false,"birthday":"1130","birthday_type":"SOLAR","is_leap_month":false,"has_gender":true,"gender_needs_agreement":false,"gender":"male"}}"#;
pub global ME_NOTILDE_C: [u8; 32] = [
    151, 69, 234, 110, 81, 223, 86, 27, 213, 178, 135, 65, 151, 105, 176, 181, 15, 32, 98, 146, 45,
    223, 66, 118, 215, 8, 58, 185, 242, 211, 176, 57,
];
pub global ME_NOTILDE_ID: u32 = 6;
pub global ME_NOTILDE_KA: u32 = 223;
pub global ME_NOTILDE_PROPS: u32 = 55;
pub global ME_NOTILDE_AGE_RANGE: u32 = 687;

pub global ME_NICKATTACK: str<893> = r#"{"id":1234567890,"connected_at":"2025-01-01T00:00:00Z","properties":{"nickname":"x\",\"age_range\":\"30~39","profile_image":"https://k.kakaocdn.net/dn/abc/img_640x640.jpg","thumbnail_image":"https://k.kakaocdn.net/dn/abc/img_640x640.jpg"},"kakao_account":{"profile_needs_agreement":false,"profile":{"nickname":"테스트","thumbnail_image_url":"https://k.kakaocdn.net/dn/abc/img_640x640.jpg","profile_image_url":"https://k.kakaocdn.net/dn/abc/img_640x640.jpg","is_default_image":false,"is_default_nickname":false},"has_email":true,"email_needs_agreement":false,"is_email_valid":true,"is_email_verified":true,"email":"user@example.com","has_age_range":true,"age_range_needs_agreement":false,"age_range":"15~19","has_birthday":true,"birthday_needs_agreement":false,"birthday":"1130","birthday_type":"SOLAR","is_leap_month":false,"has_gender":true,"gender_needs_agreement":false,"gender":"male"}}"#;
pub global ME_NICKATTACK_C: [u8; 32] = [
    68, 129, 14, 204, 63, 187, 138, 223, 126, 95, 70, 162, 43, 137, 157, 138, 74, 31, 220, 44, 73,
    209, 125, 18, 196, 150, 231, 15, 153, 51, 173, 155,
];
pub global ME_NICKATTACK_ID: u32 = 6;
pub global ME_NICKATTACK_KA: u32 = 239;
pub global ME_NICKATTACK_PROPS: u32 = 55;
pub global ME_NICKATTACK_AGE_RANGE: u32 = 703;
pub global ME_NICKATTACK_FAKE: u32 = 99;

pub global ME_FORGED_PROPS: str<897> = r#"{"id":1234567890,"connected_at":"2025-01-01T00:00:00Z","properties":{"nickname":"테스트","profile_image":"https://k.kakaocdn.net/dn/abc/img_640x640.jpg","thumbnail_image":"https://k.kakaocdn.net/dn/abc/img_640x640.jpg","age_range":"30~39"},"kakao_account":{"profile_needs_agreement":false,"profile":{"nickname":"테스트","thumbnail_image_url":"https://k.kakaocdn.net/dn/abc/img_640x640.jpg","profile_image_url":"https://k.kakaocdn.net/dn/abc/img_640x640.jpg","is_default_image":false,"is_default_nickname":false},"has_email":true,"email_needs_agreement":false,"is_email_valid":true,"is_email_verified":true,"email":"user@example.com","has_age_range":true,"age_range_needs_agreement":false,"age_range":"15~19","has_birthday":true,"birthday_needs_agreement":false,"birthday":"1130","birthday_type":"SOLAR","is_leap_month":false,"has_gender":true,"gender_needs_agreement":false,"gender":"male"}}"#;
pub global ME_FORGED_PROPS_C: [u8; 32] = [
    136, 180, 99, 192, 236, 217, 124, 230, 100, 68, 92, 21, 178, 252, 171, 181, 35, 87, 139, 84, 27,
    34, 49, 28, 230, 243, 124, 249, 247, 224, 1, 202,
];
pub global ME_FORGED_PROPS_ID: u32 = 6;
pub global ME_FORGED_PROPS_KA: u32 = 243;
pub global ME_FORGED_PROPS_PROPS: u32 = 55;
pub global ME_FORGED_PROPS_AGE_RANGE: u32 = 707;
pub global ME_FORGED_PROPS_FAKE: u32 = 235;

pub global ME_FORGED_TOP: str<897> = r#"{"id":1234567890,"connected_at":"2025-01-01T00:00:00Z","age_range":"30~39","properties":{"nickname":"테스트","profile_image":"https://k.kakaocdn.net/dn/abc/img_640x640.jpg","thumbnail_image":"https://k.kakaocdn.net/dn/abc/img_640x640.jpg"},"kakao_account":{"profile_needs_agreement":false,"profile":{"nickname":"테스트","thumbnail_image_url":"https://k.kakaocdn.net/dn/abc/img_640x640.jpg","profile_image_url":"https://k.kakaocdn.net/dn/abc/img_640x640.jpg","is_default_image":false,"is_default_nickname":false},"has_email":true,"email_needs_agreement":false,"is_email_valid":true,"is_email_verified":true,"email":"user@example.com","has_age_range":true,"age_range_needs_agreement":false,"age_range":"15~19","has_birthday":true,"birthday_needs_agreement":false,"birthday":"1130","birthday_type":"SOLAR","is_leap_month":false,"has_gender":true,"gender_needs_agreement":false,"gender":"male"}}"#;
pub global ME_FORGED_TOP_C: [u8; 32] = [
    53, 83, 19, 14, 91, 59, 102, 219, 185, 44, 102, 200, 134, 61, 112, 226, 208, 129, 172, 109, 190,
    134, 220, 219, 200, 52, 212, 167, 227, 50, 245, 40,
];
pub global ME_FORGED_TOP_ID: u32 = 6;
pub global ME_FORGED_TOP_KA: u32 = 243;
pub global ME_FORGED_TOP_PROPS: u32 = 75;
pub global ME_FORGED_TOP_AGE_RANGE: u32 = 707;
pub global ME_FORGED_TOP_FAKE: u32 = 68;

pub global ME_LONG: str<1668> = r#"{"id":1234567890,"connected_at":"2025-01-01T00:00:00Z","properties":{"nickname":"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx","profile_image":"https://k.kakaocdn.net/dn/abc/img_640x640.jpg","thumbnail_image":"https://k.kakaocdn.net/dn/abc/img_640x640.jpg"},"kakao_account":{"profile_needs_agreement":false,"profile":{"nickname":"테스트","thumbnail_image_url":"https://k.kakaocdn.net/dn/abc/img_640x640.jpg","profile_image_url":"https://k.kakaocdn.net/dn/abc/img_640x640.jpg","is_default_image":false,"is_default_nickname":false},"has_email":true,"email_needs_agreement":false,"is_email_valid":true,"is_email_verified":true,"email":"user@example.com","has_age_range":true,"age_range_needs_agreement":false,"age_range":"30~39","has_birthday":true,"birthday_needs_agreement":false,"birthday":"1130","birthday_type":"SOLAR","is_leap_month":false,"has_gender":true,"gender_needs_agreement":false,"gender":"male"}}"#;
pub global ME_LONG_C: [u8; 32] = [
    166, 144, 227, 96, 150, 18, 226, 84, 191, 161, 191, 137, 238, 90, 228, 67, 88, 2, 143, 160, 77,
    204, 124, 42, 10, 67, 59, 252, 29, 81, 183, 78,
];
pub global ME_LONG_P1024_C: [u8; 32] = [
    158, 9, 205, 48, 152, 128, 150, 14, 238, 208, 238, 110, 234, 0, 159, 206, 215, 29, 197, 111, 94,
    64, 184, 7, 15, 117, 173, 195, 11, 215, 45, 78,
];
pub global ME_LONG_ID: u32 = 6;
pub global ME_LONG_KA: u32 = 1014;
pub global ME_LONG_PROPS: u32 = 55;
pub global ME_LONG_AGE_RANGE: u32 = 1478;

pub global OIDC_TAIL: str<1199> = r#"{"sub":"4012345678","nickname":"테스트","picture":"https://k.kakaocdn.net/dn/abc/img_640x640.jpg","email":"user@example.com","email_verified":true,"gender":"male","birthdate":"1990-05-17","zz":"yyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy"}"#;
pub global OIDC_TAIL_C: [u8; 32] = [
    202, 169, 243, 17, 149, 74, 77, 3, 180, 180, 247, 168, 30, 73, 176, 103, 135, 38, 61, 179, 15,
    166, 95, 251, 94, 130, 118, 15, 209, 203, 59, 120,
];
pub global OIDC_TAIL_P1024_C: [u8; 32] = [
    134, 92, 189, 37, 93, 131, 170, 103, 40, 32, 143, 250, 93, 60, 82, 142, 172, 119, 237, 237, 194,
    110, 125, 208, 47, 8, 230, 23, 73, 179, 82, 81,
];
pub global OIDC_TAIL_SUB: u32 = 8;
pub global OIDC_TAIL_BIRTHDATE: u32 = 179;
pub global OIDC_TAIL_GENDER: u32 = 160;
pub global OIDC_TAIL_EMAIL_VERIFIED: u32 = 145;

// OIDC_ADULT cut so that EMAIL_VERIFIED ends at the last prefix byte.
pub global CUT_LITERAL_N: u32 = 149;
pub global CUT_LITERAL_C: [u8; 32] = [
    31, 62, 53, 2, 150, 175, 59, 151, 195, 234, 69, 199, 189, 137, 176, 212, 133, 172, 92, 243, 118,
    230, 177, 129, 140, 31, 175, 47, 159, 206, 153, 240,
];

// OIDC_ADULT cut so that BIRTHDATE ends at the last prefix byte.
pub global CUT_STRING_N: u32 = 189;
pub global CUT_STRING_C: [u8; 32] = [
    133, 210, 21, 127, 78, 5, 145, 166, 48, 67, 137, 241, 234, 133, 222, 10, 88, 122, 103, 222, 216,
    58, 86, 213, 57, 92, 182, 231, 129, 156, 189, 47,
];

// OIDC_UNVERIFIED cut so that EMAIL_VERIFIED ends at the last prefix byte.
pub global CUT_INSIDE_FALSE_N: u32 = 149;
pub global CUT_INSIDE_FALSE_C: [u8; 32] = [
    231, 75, 229, 209, 32, 80, 179, 51, 231, 218, 172, 1, 220, 220, 191, 122, 69, 106, 184, 151, 34,
    217, 179, 149, 242, 202, 130, 59, 125, 13, 113, 56,
];
