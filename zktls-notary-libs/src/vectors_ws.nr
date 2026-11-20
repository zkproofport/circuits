// Generated test vectors for whitespace and array bodies. Fake values only.
// <NAME>_C = SHA-256(body || BLINDER) of the whole body.
// <NAME>_<M>_K = quote opening member M's key, _V = first value byte, _L = value length.
// <NAME>_<M>_O = brace opening the object that is M's value (a parent member).
// Computed outside the circuit.

pub global G_GMAIL: str<165> = "{\n  \"sub\": \"109876543210987654321\",\n  \"picture\": \"https://lh3.googleusercontent.com/a/ACg8ocK\\u003ds96-c\",\n  \"email\": \"someone@gmail.com\",\n  \"email_verified\": true\n}";
pub global G_GMAIL_C: [u8; 32] = [18, 18, 192, 250, 7, 188, 216, 59, 81, 198, 153, 135, 154, 46, 219, 239, 12, 45, 47, 199, 89, 149, 171, 233, 70, 223, 47, 41, 107, 136, 109, 54];
pub global G_GMAIL_SUB_K: u32 = 4;
pub global G_GMAIL_SUB_V: u32 = 12;
pub global G_GMAIL_SUB_L: u32 = 21;
pub global G_GMAIL_SUB_O: u32 = 11;
pub global G_GMAIL_EMAIL_K: u32 = 109;
pub global G_GMAIL_EMAIL_V: u32 = 119;
pub global G_GMAIL_EMAIL_L: u32 = 17;
pub global G_GMAIL_EMAIL_O: u32 = 118;
pub global G_GMAIL_EV_K: u32 = 141;
pub global G_GMAIL_EV_V: u32 = 159;
pub global G_GMAIL_EV_L: u32 = 4;
pub global G_GMAIL_EV_O: u32 = 159;

pub global G_WS: str<190> = "{\n  \"sub\": \"109876543210987654321\",\n  \"picture\": \"https://lh3.googleusercontent.com/a/ACg8ocK\\u003ds96-c\",\n  \"email\": \"someone@example.com\",\n  \"email_verified\": true,\n  \"hd\": \"example.com\"\n}";
pub global G_WS_C: [u8; 32] = [55, 175, 13, 187, 13, 226, 248, 87, 13, 214, 198, 89, 74, 73, 34, 196, 125, 41, 70, 209, 63, 62, 55, 240, 105, 211, 176, 20, 81, 146, 253, 126];
pub global G_WS_SUB_K: u32 = 4;
pub global G_WS_SUB_V: u32 = 12;
pub global G_WS_SUB_L: u32 = 21;
pub global G_WS_SUB_O: u32 = 11;
pub global G_WS_EMAIL_K: u32 = 109;
pub global G_WS_EMAIL_V: u32 = 119;
pub global G_WS_EMAIL_L: u32 = 19;
pub global G_WS_EMAIL_O: u32 = 118;
pub global G_WS_EV_K: u32 = 143;
pub global G_WS_EV_V: u32 = 161;
pub global G_WS_EV_L: u32 = 4;
pub global G_WS_EV_O: u32 = 161;
pub global G_WS_HD_K: u32 = 169;
pub global G_WS_HD_V: u32 = 176;
pub global G_WS_HD_L: u32 = 11;
pub global G_WS_HD_O: u32 = 175;

pub global G_FALSE: str<95> = "{\n  \"sub\": \"109876543210987654321\",\n  \"email\": \"someone@gmail.com\",\n  \"email_verified\": false\n}";
pub global G_FALSE_C: [u8; 32] = [17, 169, 146, 32, 92, 142, 124, 31, 50, 76, 121, 202, 180, 245, 207, 38, 39, 112, 197, 27, 15, 31, 17, 237, 10, 174, 12, 155, 223, 150, 230, 28];
pub global G_FALSE_SUB_K: u32 = 4;
pub global G_FALSE_SUB_V: u32 = 12;
pub global G_FALSE_SUB_L: u32 = 21;
pub global G_FALSE_SUB_O: u32 = 11;
pub global G_FALSE_EV_K: u32 = 70;
pub global G_FALSE_EV_V: u32 = 88;
pub global G_FALSE_EV_L: u32 = 5;
pub global G_FALSE_EV_O: u32 = 88;

pub global G_ARRSEP: str<111> = "{\n  \"sub\": \"109876543210987654321\",\n  \"aliases\": [\"email\" , \"evil@gmail.com\"],\n  \"email\": \"someone@other.com\"\n}";
pub global G_ARRSEP_C: [u8; 32] = [62, 196, 112, 69, 110, 196, 124, 82, 8, 63, 55, 100, 21, 165, 144, 136, 176, 237, 75, 197, 166, 15, 251, 72, 36, 126, 124, 251, 82, 82, 190, 149];
pub global G_ARRSEP_SUB_K: u32 = 4;
pub global G_ARRSEP_SUB_V: u32 = 12;
pub global G_ARRSEP_SUB_L: u32 = 21;
pub global G_ARRSEP_SUB_O: u32 = 11;
pub global G_ARRSEP_FAKE_K: u32 = 50;
pub global G_ARRSEP_FAKE_V: u32 = 58;
pub global G_ARRSEP_FAKE_L: u32 = 0;
pub global G_ARRSEP_FAKE_O: u32 = 58;
pub global G_ARRSEP_EMAIL_K: u32 = 81;
pub global G_ARRSEP_EMAIL_V: u32 = 91;
pub global G_ARRSEP_EMAIL_L: u32 = 17;
pub global G_ARRSEP_EMAIL_O: u32 = 90;

pub global G_ARRSEP_EVIL_V: u32 = 61;
pub global G_ARRSEP_EVIL_L: u32 = 14;

pub global G_WIDE: str<71> = "{\"sub\": \"109876543210987654321\", \"email\":          \"someone@gmail.com\"}";
pub global G_WIDE_C: [u8; 32] = [69, 191, 220, 175, 213, 53, 10, 88, 19, 91, 160, 28, 62, 170, 209, 225, 93, 6, 146, 223, 106, 13, 223, 7, 142, 187, 229, 186, 228, 166, 212, 113];
pub global G_WIDE_SUB_K: u32 = 1;
pub global G_WIDE_SUB_V: u32 = 9;
pub global G_WIDE_SUB_L: u32 = 21;
pub global G_WIDE_SUB_O: u32 = 8;
pub global G_WIDE_EMAIL_K: u32 = 33;
pub global G_WIDE_EMAIL_V: u32 = 52;
pub global G_WIDE_EMAIL_L: u32 = 17;
pub global G_WIDE_EMAIL_O: u32 = 51;

pub global GH_USER: str<233> = "{\"login\":\"octo\",\"id\":1234567,\"node_id\":\"MDQ6VXNlcjE=\",\"type\":\"User\",\"site_admin\":false,\"name\":\"Oc\",\"company\":null,\"public_repos\":12,\"followers\":42,\"following\":3,\"created_at\":\"2014-05-01T12:34:56Z\",\"updated_at\":\"2026-11-01T00:00:00Z\"}";
pub global GH_USER_C: [u8; 32] = [121, 236, 20, 96, 158, 97, 201, 127, 88, 72, 66, 32, 240, 134, 111, 144, 243, 38, 39, 89, 44, 80, 163, 100, 38, 1, 20, 209, 255, 131, 7, 250];
pub global GH_USER_ID_K: u32 = 16;
pub global GH_USER_ID_V: u32 = 21;
pub global GH_USER_ID_L: u32 = 7;
pub global GH_USER_ID_O: u32 = 21;
pub global GH_USER_FOLLOWERS_K: u32 = 132;
pub global GH_USER_FOLLOWERS_V: u32 = 144;
pub global GH_USER_FOLLOWERS_L: u32 = 2;
pub global GH_USER_FOLLOWERS_O: u32 = 144;
pub global GH_USER_CREATED_K: u32 = 161;
pub global GH_USER_CREATED_V: u32 = 175;
pub global GH_USER_CREATED_L: u32 = 20;
pub global GH_USER_CREATED_O: u32 = 174;

pub global GH_ORGS: str<185> = "[{\"login\":\"acme\",\"id\":101,\"url\":\"https://api.github.com/orgs/acme\",\"description\":\"\"},{\"login\":\"zkproofport\",\"id\":202,\"url\":\"https://api.github.com/orgs/zkproofport\",\"description\":\"zk\"}]";
pub global GH_ORGS_C: [u8; 32] = [240, 237, 252, 150, 135, 217, 228, 93, 218, 235, 144, 101, 50, 163, 206, 60, 68, 126, 249, 186, 186, 193, 197, 123, 170, 132, 174, 180, 49, 103, 171, 226];
pub global GH_ORGS_ACME_K: u32 = 2;
pub global GH_ORGS_ACME_V: u32 = 11;
pub global GH_ORGS_ACME_L: u32 = 4;
pub global GH_ORGS_ACME_O: u32 = 10;
pub global GH_ORGS_ZKP_K: u32 = 86;
pub global GH_ORGS_ZKP_V: u32 = 95;
pub global GH_ORGS_ZKP_L: u32 = 11;
pub global GH_ORGS_ZKP_O: u32 = 94;

pub global GH_NESTED: str<58> = "[{\"login\":\"other\",\"id\":7,\"owner\":{\"login\":\"zkproofport\"}}]";
pub global GH_NESTED_C: [u8; 32] = [196, 14, 183, 198, 147, 164, 73, 186, 162, 105, 223, 205, 248, 247, 52, 249, 127, 167, 96, 210, 255, 202, 252, 103, 131, 84, 132, 161, 242, 0, 2, 47];
pub global GH_NESTED_OUTER_K: u32 = 2;
pub global GH_NESTED_OUTER_V: u32 = 11;
pub global GH_NESTED_OUTER_L: u32 = 5;
pub global GH_NESTED_OUTER_O: u32 = 10;
pub global GH_NESTED_INNER_K: u32 = 34;
pub global GH_NESTED_INNER_V: u32 = 43;
pub global GH_NESTED_INNER_L: u32 = 11;
pub global GH_NESTED_INNER_O: u32 = 42;

pub global GH_INNERARR: str<53> = "[{\"teams\":[{\"login\":\"zkproofport\"}],\"login\":\"other\"}]";
pub global GH_INNERARR_C: [u8; 32] = [55, 122, 201, 151, 210, 9, 160, 245, 200, 93, 229, 127, 103, 98, 138, 174, 132, 176, 114, 16, 138, 220, 30, 133, 36, 251, 246, 220, 181, 209, 248, 132];
pub global GH_INNERARR_INNER_K: u32 = 12;
pub global GH_INNERARR_INNER_V: u32 = 21;
pub global GH_INNERARR_INNER_L: u32 = 11;
pub global GH_INNERARR_INNER_O: u32 = 20;
pub global GH_INNERARR_OUTER_K: u32 = 36;
pub global GH_INNERARR_OUTER_V: u32 = 45;
pub global GH_INNERARR_OUTER_L: u32 = 5;
pub global GH_INNERARR_OUTER_O: u32 = 44;

pub global GH_OBJARR: str<41> = "{\"orgs\":[{\"login\":\"zkproofport\"}],\"id\":5}";
pub global GH_OBJARR_C: [u8; 32] = [230, 219, 15, 34, 36, 11, 35, 81, 47, 93, 45, 215, 121, 30, 251, 102, 155, 123, 211, 146, 154, 225, 232, 208, 168, 68, 104, 92, 81, 165, 14, 84];
pub global GH_OBJARR_LOGIN_K: u32 = 10;
pub global GH_OBJARR_LOGIN_V: u32 = 19;
pub global GH_OBJARR_LOGIN_L: u32 = 11;
pub global GH_OBJARR_LOGIN_O: u32 = 18;
pub global GH_OBJARR_ID_K: u32 = 34;
pub global GH_OBJARR_ID_V: u32 = 39;
pub global GH_OBJARR_ID_L: u32 = 1;
pub global GH_OBJARR_ID_O: u32 = 39;

pub global GH_ORGS_PRETTY: str<53> = "[\n  {\n    \"login\": \"zkproofport\",\n    \"id\": 202\n  }\n]";
pub global GH_ORGS_PRETTY_C: [u8; 32] = [211, 213, 189, 67, 66, 141, 62, 34, 249, 103, 230, 179, 234, 165, 253, 2, 218, 14, 226, 183, 161, 136, 118, 6, 66, 106, 98, 46, 175, 149, 247, 9];
pub global GH_ORGS_PRETTY_ZKP_K: u32 = 10;
pub global GH_ORGS_PRETTY_ZKP_V: u32 = 20;
pub global GH_ORGS_PRETTY_ZKP_L: u32 = 11;
pub global GH_ORGS_PRETTY_ZKP_O: u32 = 19;

pub global BAD_NOCOLON: str<55> = "{\"sub\": \"109876543210987654321\", \"email\" \"x@gmail.com\"}";
pub global BAD_NOCOLON_C: [u8; 32] = [104, 9, 101, 111, 240, 195, 78, 59, 159, 44, 114, 68, 197, 32, 176, 1, 88, 55, 189, 231, 34, 23, 122, 118, 89, 218, 224, 128, 92, 189, 24, 96];
pub global BAD_NOCOLON_SUB_K: u32 = 1;
pub global BAD_NOCOLON_SUB_V: u32 = 9;
pub global BAD_NOCOLON_SUB_L: u32 = 21;
pub global BAD_NOCOLON_EMAIL_K: u32 = 33;
pub global BAD_NOCOLON_EMAIL_V: u32 = 42;
pub global BAD_NOCOLON_EMAIL_L: u32 = 11;

pub global BAD_COMMA: str<58> = "{\"sub\": \"109876543210987654321\", \"email\": , \"x@gmail.com\"}";
pub global BAD_COMMA_C: [u8; 32] = [217, 120, 174, 67, 216, 184, 99, 87, 175, 159, 221, 116, 41, 102, 94, 184, 29, 119, 169, 138, 22, 171, 250, 28, 194, 233, 208, 203, 112, 146, 169, 90];
pub global BAD_COMMA_SUB_K: u32 = 1;
pub global BAD_COMMA_SUB_V: u32 = 9;
pub global BAD_COMMA_SUB_L: u32 = 21;
pub global BAD_COMMA_EMAIL_K: u32 = 33;
pub global BAD_COMMA_EMAIL_V: u32 = 45;
pub global BAD_COMMA_EMAIL_L: u32 = 11;

pub global BAD_ARRELEM: str<25> = "[[\"login\":\"zkproofport\"]]";
pub global BAD_ARRELEM_C: [u8; 32] = [11, 6, 88, 186, 21, 153, 86, 127, 150, 56, 113, 153, 162, 66, 243, 200, 56, 180, 14, 161, 242, 146, 73, 136, 254, 246, 26, 76, 127, 69, 149, 252];
pub global BAD_ARRELEM_LOGIN_K: u32 = 2;
pub global BAD_ARRELEM_LOGIN_V: u32 = 11;
pub global BAD_ARRELEM_LOGIN_L: u32 = 11;
