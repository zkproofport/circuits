// Generated test vectors for general JSON paths. Fake values only.
// <NAME>_C = SHA-256(body || BLINDER) of the whole body; <NAME>_<M> = first byte of value M
// (after the opening quote for a string). Computed outside the circuit by a generator script.

pub global DEEP: str<261> = "{\"data\":{\"login\":\"depth2\",\"items\":[{\"id\":1,\"owner\":{\"login\":\"alice\",\"type\":\"User\"},\"login\":\"itemlogin\"},{\"id\":2,\"owner\":{\"login\":\"zkproofport\",\"type\":\"Organization\"}}],\"other\":{\"owner\":{\"login\":\"sibling\"}},\"archived\":[{\"owner\":{\"login\":\"archivedorg\"}}]},\"id\":7}";
pub global DEEP_C: [u8; 32] = [65, 24, 158, 145, 195, 43, 4, 121, 79, 117, 130, 115, 90, 72, 63, 189, 139, 160, 135, 198, 125, 133, 229, 200, 145, 49, 89, 52, 161, 188, 29, 4];
pub global DEEP_ZKP: u32 = 130;
pub global DEEP_ALICE: u32 = 61;
pub global DEEP_DEPTH2: u32 = 18;
pub global DEEP_ITEMLOGIN: u32 = 92;
pub global DEEP_SIBLING: u32 = 195;
pub global DEEP_ARCHIVED: u32 = 237;
pub global DEEP_ID: u32 = 259;
pub global DEEP_TYPE: u32 = 151;

pub global DEEP_PRETTY: str<526> = "{\n  \"data\": {\n    \"login\": \"depth2\",\n    \"items\": [\n      {\n        \"id\": 1,\n        \"owner\": {\n          \"login\": \"alice\",\n          \"type\": \"User\"\n        },\n        \"login\": \"itemlogin\"\n      },\n      {\n        \"id\": 2,\n        \"owner\": {\n          \"login\": \"zkproofport\",\n          \"type\": \"Organization\"\n        }\n      }\n    ],\n    \"other\": {\n      \"owner\": {\n        \"login\": \"sibling\"\n      }\n    },\n    \"archived\": [\n      {\n        \"owner\": {\n          \"login\": \"archivedorg\"\n        }\n      }\n    ]\n  },\n  \"id\": 7\n}";
pub global DEEP_PRETTY_C: [u8; 32] = [20, 115, 210, 227, 77, 10, 2, 20, 181, 96, 231, 221, 178, 233, 13, 89, 211, 128, 173, 43, 165, 84, 59, 65, 7, 61, 158, 143, 96, 53, 148, 239];
pub global DEEP_PRETTY_ZKP: u32 = 262;
pub global DEEP_PRETTY_ID: u32 = 523;

pub global NESTED: str<67> = "{\"a\":[{\"b\":[{\"c\":\"x1\"},{\"c\":\"x2\"}]},{\"b\":[{\"c\":\"target\"}]}],\"id\":9}";
pub global NESTED_C: [u8; 32] = [166, 144, 169, 176, 23, 230, 78, 52, 252, 63, 178, 96, 129, 235, 48, 191, 78, 105, 174, 44, 239, 90, 52, 12, 140, 251, 246, 105, 252, 202, 107, 202];
pub global NESTED_TARGET: u32 = 48;
pub global NESTED_X1: u32 = 18;
pub global NESTED_ID: u32 = 65;

pub global EIGHT: str<74> = "{\"k1\":{\"k2\":{\"k3\":{\"k4\":{\"k5\":{\"k6\":{\"k7\":{\"k8\":\"deepvalue\"}}}}}}},\"id\":3}";
pub global EIGHT_C: [u8; 32] = [119, 227, 159, 52, 29, 152, 67, 60, 151, 168, 75, 191, 224, 136, 203, 191, 208, 5, 158, 189, 235, 185, 235, 233, 177, 43, 46, 89, 99, 120, 103, 223];
pub global EIGHT_VAL: u32 = 49;
pub global EIGHT_ID: u32 = 72;

pub global FAKE: str<251> = "{\"note\":\"x\\\",\\\"data\\\":{\\\"items\\\":[{\\\"owner\\\":{\\\"login\\\":\\\"zkproofport\\\"}}]},\\\"y\\\":\\\"\",\"data\":{\"memo\":\"q\\\\\\\",\\\\\\\"items\\\\\\\":[{\\\\\\\"owner\\\\\\\":{\\\\\\\"login\\\\\\\":\\\\\\\"zkproofport\",\"items\":[{\"owner\":{\"bio\":\"\\\"login\\\":\\\"zkproofport\\\"\",\"login\":\"honest\"}}]},\"id\":5}";
pub global FAKE_C: [u8; 32] = [243, 148, 243, 16, 64, 105, 103, 173, 60, 119, 109, 14, 139, 22, 115, 71, 155, 116, 180, 50, 17, 63, 101, 130, 66, 76, 68, 233, 221, 38, 187, 46];
pub global FAKE_HONEST: u32 = 232;
pub global FAKE_ID: u32 = 249;

pub global ARR: str<53> = "{\"tags\":[\"alpha\",\"beta\",\"kr\"],\"nums\":[3,41,5],\"id\":8}";
pub global ARR_C: [u8; 32] = [226, 239, 168, 2, 54, 245, 61, 4, 227, 174, 159, 135, 209, 63, 130, 196, 61, 87, 44, 234, 251, 141, 22, 47, 193, 64, 134, 27, 190, 34, 151, 53];
pub global ARR_KR: u32 = 25;
pub global ARR_N41: u32 = 40;
pub global ARR_ID: u32 = 51;

pub global TOODEEP: str<79> = "{\"id\":1,\"x\":[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]}";
pub global TOODEEP_C: [u8; 32] = [202, 186, 64, 171, 180, 33, 83, 177, 227, 229, 50, 52, 65, 29, 153, 235, 1, 126, 64, 198, 118, 6, 204, 35, 54, 10, 14, 3, 165, 233, 105, 50];
pub global TOODEEP_ID: u32 = 6;

pub global WS_OBJ: str<40> = "\n  	{\"data\":{\"mileage\":1200},\"id\":4} \n\n";
pub global WS_OBJ_C: [u8; 32] = [220, 94, 36, 244, 208, 175, 106, 175, 145, 234, 30, 203, 190, 246, 237, 204, 203, 120, 6, 252, 152, 90, 55, 166, 15, 75, 60, 235, 106, 18, 95, 253];
pub global WS_OBJ_MILEAGE: u32 = 24;
pub global WS_OBJ_ID: u32 = 35;

pub global WS_ARR: str<45> = "\n [{\"login\":\"acme\"},{\"login\":\"zkproofport\"}]\n";
pub global WS_ARR_C: [u8; 32] = [90, 153, 239, 107, 108, 58, 122, 236, 59, 35, 97, 70, 88, 167, 90, 93, 163, 30, 74, 245, 71, 36, 148, 61, 197, 158, 98, 120, 196, 210, 80, 179];
pub global WS_ARR_ZKP: u32 = 30;

pub global ARR_ARR: str<30> = "[[{\"c\":\"x\"}],[{\"c\":\"target\"}]]";
pub global ARR_ARR_C: [u8; 32] = [41, 1, 151, 174, 14, 77, 119, 239, 156, 92, 175, 8, 131, 212, 99, 226, 239, 120, 4, 155, 82, 247, 208, 36, 135, 119, 89, 146, 195, 14, 115, 243];
pub global ARR_ARR_TARGET: u32 = 20;

pub global BOM_OBJ: str<19> = "﻿{\"id\":4,\"k\":\"v\"}";
pub global BOM_OBJ_C: [u8; 32] = [18, 132, 5, 87, 98, 171, 159, 185, 13, 48, 33, 14, 234, 166, 38, 165, 171, 150, 207, 137, 180, 34, 14, 27, 214, 233, 190, 133, 187, 62, 169, 135];
pub global BOM_OBJ_V: u32 = 16;
pub global BOM_OBJ_ID: u32 = 9;

pub global GARBAGE: str<17> = "x{\"id\":4,\"k\":\"v\"}";
pub global GARBAGE_C: [u8; 32] = [209, 188, 187, 47, 182, 243, 146, 97, 6, 127, 154, 180, 186, 157, 156, 150, 44, 139, 182, 45, 95, 146, 233, 215, 160, 247, 154, 175, 145, 184, 15, 131];
pub global GARBAGE_V: u32 = 14;
pub global GARBAGE_ID: u32 = 7;

pub global TWO_ROOTS: str<25> = "{\"id\":4,\"k\":\"v\"}{\"k\":\"w\"}";
pub global TWO_ROOTS_C: [u8; 32] = [55, 174, 236, 146, 201, 92, 33, 183, 224, 161, 247, 169, 215, 69, 109, 100, 97, 252, 135, 119, 51, 203, 132, 179, 72, 191, 1, 198, 232, 233, 105, 81];
pub global TWO_ROOTS_V: u32 = 13;
pub global TWO_ROOTS_ID: u32 = 6;

pub global TRAIL_X: str<18> = "{\"id\":4,\"k\":\"v\"} x";
pub global TRAIL_X_C: [u8; 32] = [108, 197, 137, 51, 58, 132, 98, 140, 240, 225, 170, 93, 11, 245, 37, 54, 183, 141, 18, 163, 119, 142, 72, 29, 159, 197, 251, 70, 143, 84, 136, 110];
pub global TRAIL_X_V: u32 = 13;
pub global TRAIL_X_ID: u32 = 6;

pub global CUT_ARR: str<41> = "[{\"login\":\"acme\"},{\"login\":\"zkproofport\"}";
pub global CUT_ARR_C: [u8; 32] = [192, 121, 124, 246, 125, 116, 223, 82, 144, 73, 69, 225, 17, 89, 101, 194, 236, 198, 4, 243, 44, 171, 20, 161, 71, 251, 76, 41, 53, 100, 41, 15];
pub global CUT_ARR_ZKP: u32 = 28;

pub global SCALAR: str<4> = "true";
pub global SCALAR_C: [u8; 32] = [236, 136, 254, 119, 151, 17, 30, 182, 30, 139, 243, 85, 187, 193, 102, 160, 70, 130, 249, 35, 156, 93, 95, 210, 206, 237, 195, 41, 92, 225, 67, 188];

pub global G_OBJ: str<42> = "{\"a\":\"x\",\"b\":7,\"s\":\"zk\\\"q\",\"t\":\"v\",\"n\":41}";
pub global G_OBJ_C: [u8; 32] = [90, 6, 18, 184, 253, 96, 64, 154, 251, 248, 69, 90, 154, 102, 234, 141, 102, 234, 132, 224, 6, 146, 127, 213, 171, 113, 44, 131, 95, 209, 109, 29];
pub global G_OBJ_A: u32 = 6;
pub global G_OBJ_B: u32 = 13;
pub global G_OBJ_T: u32 = 32;
pub global G_OBJ_N: u32 = 39;
pub global G_OBJ_S: u32 = 20;

pub global G_ROOTARR: str<23> = "[\"login\":\"zkproofport\"]";
pub global G_ROOTARR_C: [u8; 32] = [194, 251, 154, 80, 60, 138, 228, 75, 123, 245, 219, 176, 159, 31, 7, 27, 92, 94, 77, 218, 214, 244, 10, 113, 86, 141, 114, 243, 232, 64, 156, 162];
pub global G_ROOTARR_ZKP: u32 = 10;

pub global G_ARRS: str<17> = "[\"ab\",\"c\",[1,23]]";
pub global G_ARRS_C: [u8; 32] = [52, 182, 236, 17, 165, 187, 32, 183, 186, 123, 85, 89, 232, 161, 88, 46, 139, 190, 10, 122, 71, 31, 212, 81, 176, 156, 237, 168, 229, 215, 101, 39];
pub global G_ARRS_AB: u32 = 2;
pub global G_ARRS_N23: u32 = 13;

pub global G_COMMA: str<11> = "{\"c\":\"a,b\"}";
pub global G_COMMA_C: [u8; 32] = [140, 111, 17, 200, 81, 115, 57, 237, 2, 99, 214, 35, 101, 227, 105, 75, 251, 73, 30, 39, 130, 227, 28, 21, 38, 114, 11, 25, 159, 85, 29, 91];
pub global G_COMMA_V: u32 = 6;

pub global G_OPS: str<273> = "{\"r2\":\"30~~39\",\"rx\":\"3a~39\",\"r4\":\"1000~\",\"d1\":\"1990-01-0\",\"dz\":\"0000-01-01\",\"dm\":\"2020-13-01\",\"dd\":\"2020-01-32\",\"b1\":\"19900101\",\"bfut\":\"2030-01-01\",\"bm\":\"1990-13-01\",\"bd\":\"1990-01-32\",\"bdash\":\"1990/01/01\",\"bfirst\":\"2026-12-01\",\"nlong\":1234567890123456789,\"nx\":\"12a\",\"n\":41}";
pub global G_OPS_C: [u8; 32] = [245, 107, 204, 96, 93, 198, 2, 96, 26, 21, 138, 236, 26, 107, 5, 242, 115, 166, 214, 242, 4, 57, 161, 207, 50, 167, 142, 147, 176, 194, 105, 194];
pub global G_OPS_R2: u32 = 7;
pub global G_OPS_RX: u32 = 21;
pub global G_OPS_R4: u32 = 34;
pub global G_OPS_D1: u32 = 47;
pub global G_OPS_DZ: u32 = 64;
pub global G_OPS_DM: u32 = 82;
pub global G_OPS_DD: u32 = 100;
pub global G_OPS_B1: u32 = 118;
pub global G_OPS_BFUT: u32 = 136;
pub global G_OPS_BM: u32 = 154;
pub global G_OPS_BD: u32 = 172;
pub global G_OPS_BDASH: u32 = 193;
pub global G_OPS_BFIRST: u32 = 215;
pub global G_OPS_NLONG: u32 = 235;
pub global G_OPS_NX: u32 = 261;
pub global G_OPS_N: u32 = 270;

pub global G_BLANK: str<3> = "   ";
pub global G_BLANK_C: [u8; 32] = [23, 198, 104, 208, 16, 184, 108, 61, 113, 184, 29, 35, 99, 16, 73, 159, 181, 115, 3, 137, 133, 202, 86, 57, 209, 149, 101, 147, 89, 54, 128, 192];

pub global MISMATCH: str<24> = "{\"id\":4,\"k\":\"v\",\"x\":[1}}";
pub global MISMATCH_C: [u8; 32] = [194, 210, 120, 128, 121, 122, 98, 150, 238, 246, 246, 93, 229, 154, 216, 186, 142, 65, 126, 104, 121, 78, 37, 58, 231, 36, 47, 35, 0, 217, 180, 20];
pub global MISMATCH_V: u32 = 13;
pub global MISMATCH_ID: u32 = 6;

pub global FAKE_F1: u32 = 58;
pub global FAKE_F2: u32 = 157;
pub global FAKE_F3: u32 = 208;
