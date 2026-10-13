// A signed transaction of either shape a wallet sends: legacy (EIP-155,
// type 0) or EIP-1559 (type 2).
//
// Why both. `eip1559_tx_parser` reads type 2 only, which is all an issuer's
// server sends. A transaction the USER sends is shaped by whatever wallet they
// use: of 60 GIWA Sepolia Dojang Playground issuances checked on 2026-10-14,
// 44 were legacy and 16 were type 2. A circuit that read one shape would
// refuse most people for a reason that has nothing to do with them.
//
// What this checks, beyond locating fields:
//   - the type byte is 0x02, or the first byte opens an RLP list (legacy).
//     Type 1 and type 3 are refused rather than misread.
//   - the field count is 9 (legacy) or 12 (type 2), and the list ends exactly
//     at `tx_length`, so trailing bytes cannot ride along.
//   - the chain: the type-2 chainId field, or the legacy EIP-155 `v`, must
//     name `chain_id`. A pre-EIP-155 legacy tx carries no chain and is refused.
//   - r and s are left-padded to 32 bytes. RLP drops leading zero bytes, so
//     roughly one signature in 128 has a shorter r or s; asserting a length of
//     32 would refuse that person at random.
//
// The unsigned hash is rebuilt with a correct RLP list header for the
// unsigned payload's own length. Patching the signed header's length byte in
// place is only right while both payloads exceed 55 bytes; a self-issued
// transaction with 4 bytes of calldata is close to that line.

use dep::keccak256::keccak256;
use crate::rlp;

pub global MAX_TX_LEN: u32 = 300;

pub struct SignedTx {
    pub unsigned_hash: [u8; 32],
    /// r ++ s, each left-padded to 32 bytes.
    pub signature: [u8; 64],
    pub to: [u8; 20],
    pub data_length: u32,
    /// The first four bytes of calldata. Zero when data is shorter.
    pub selector: [u8; 4],
}

/// Big-endian integer of `len` bytes starting at `offset`.
fn read_uint<let N: u32>(bytes: [u8; N], offset: u32, len: u32) -> u64 {
    assert(len <= 8, "Integer field longer than 8 bytes");
    let mut out: u64 = 0;
    for i in 0..8 {
        if i < len {
            out = out * 256 + (bytes[offset + i] as u64);
        }
    }
    out
}

/// A 32-byte scalar from an RLP string of up to 32 bytes, left-padded.
fn read_scalar<let N: u32>(bytes: [u8; N], offset: u32, len: u32) -> [u8; 32] {
    assert(len <= 32, "Signature scalar longer than 32 bytes");
    assert(len > 0, "Signature scalar is empty");
    let pad = 32 - len;
    let mut out: [u8; 32] = [0; 32];
    for i in 0..32 {
        if i >= pad {
            out[i] = bytes[offset + i - pad];
        }
    }
    out
}

/// RLP encoding of an unsigned integer, as (bytes, length). Values below 0x80
/// are their own encoding; zero is the empty string 0x80.
fn rlp_uint(value: u64) -> ([u8; 9], u32) {
    let mut be: [u8; 8] = [0; 8];
    let mut v = value;
    for i in 0..8 {
        be[7 - i] = (v % 256) as u8;
        v = v / 256;
    }
    let mut significant: u32 = 0;
    for i in 0..8 {
        if (significant == 0) & (be[i] != 0) {
            significant = 8 - i;
        }
    }
    let mut out: [u8; 9] = [0; 9];
    let mut len: u32 = 0;
    if value == 0 {
        out[0] = 0x80;
        len = 1;
    } else if value < 0x80 {
        out[0] = value as u8;
        len = 1;
    } else {
        out[0] = 0x80 + significant as u8;
        for i in 0..8 {
            if i < significant {
                out[1 + i] = be[8 - significant + i];
            }
        }
        len = 1 + significant;
    }
    (out, len)
}

pub fn parse_signed_tx(raw: [u8; MAX_TX_LEN], tx_length: u32, chain_id: u64) -> SignedTx {
    assert(tx_length <= MAX_TX_LEN, "Transaction longer than the input buffer");
    let first = raw[0];
    let typed = first == 0x02;
    assert(typed | (first >= 0xc0), "Unsupported transaction type: only legacy and EIP-1559 are accepted");
    let shift: u32 = if typed { 1 } else { 0 };

    // The RLP list, with the type byte (if any) removed.
    let mut body: [u8; MAX_TX_LEN] = [0; MAX_TX_LEN];
    for i in 0..MAX_TX_LEN {
        if i + shift < MAX_TX_LEN {
            body[i] = raw[i + shift];
        }
    }

    let header = rlp::decode_len(body);
    assert(header.data_type == 1, "Transaction is not an RLP list");
    assert(shift + header.offset + header.length == tx_length, "tx_length does not match the RLP list");

    let list: rlp::RLP_List<12> = rlp::decode1(body);

    // Field positions per shape.
    //   legacy: nonce gasPrice gas to value data | v r s
    //   type 2: chainId nonce maxPrio maxFee gas to value data accessList | v r s
    let (f_to, f_data, f_last_unsigned, f_v, f_r, f_s) =
        if typed { (5, 7, 8, 9, 10, 11) } else { (3, 5, 5, 6, 7, 8) };
    let expected_fields: u32 = if typed { 12 } else { 9 };
    assert(list.num_fields == expected_fields, "Wrong number of transaction fields");

    for i in 0..12 {
        if (i != f_last_unsigned) | !typed {
            if i < expected_fields {
                assert(list.data_type[i] == 0, "Unexpected list inside a transaction field");
            }
        }
    }

    // ---- the chain this transaction is bound to
    let v = read_uint(body, list.offset[f_v], list.length[f_v]);
    if typed {
        let tx_chain = read_uint(body, list.offset[0], list.length[0]);
        assert(tx_chain == chain_id, "Transaction is for another chain");
        assert(v <= 1, "Invalid y-parity");
    } else {
        assert((v == chain_id * 2 + 35) | (v == chain_id * 2 + 36), "Legacy transaction is not EIP-155 for this chain");
    }

    // ---- unsigned payload: the fields up to the signature, plus, for legacy,
    //      EIP-155's (chainId, 0, 0)
    let fields_start = header.offset;
    let fields_end = list.offset[f_last_unsigned] + list.length[f_last_unsigned];
    let fields_len = fields_end - fields_start;

    let (chain_rlp, chain_rlp_len) = rlp_uint(chain_id);
    let mut suffix: [u8; 11] = [0; 11];
    for i in 0..9 {
        suffix[i] = chain_rlp[i];
    }
    suffix[chain_rlp_len] = 0x80;
    suffix[chain_rlp_len + 1] = 0x80;
    let suffix_len: u32 = if typed { 0 } else { chain_rlp_len + 2 };

    let payload_len = fields_len + suffix_len;
    assert(payload_len < 256, "Unsigned payload too long");
    let short = payload_len < 56;
    let header_len: u32 = if short { 1 } else { 2 };
    let mut list_header: [u8; 2] = [0; 2];
    if short {
        list_header[0] = 0xc0 + payload_len as u8;
    } else {
        list_header[0] = 0xf8;
        list_header[1] = payload_len as u8;
    }

    let prefix_len = shift + header_len;
    let total = prefix_len + payload_len;
    let mut preimage: [u8; MAX_TX_LEN] = [0; MAX_TX_LEN];
    for j in 0..MAX_TX_LEN {
        if j < shift {
            preimage[j] = 0x02;
        } else if j < prefix_len {
            preimage[j] = list_header[j - shift];
        } else if j < prefix_len + fields_len {
            preimage[j] = body[fields_start + j - prefix_len];
        } else if j < total {
            preimage[j] = suffix[j - prefix_len - fields_len];
        }
    }
    let unsigned_hash = keccak256(preimage, total);

    // ---- signature
    let r = read_scalar(body, list.offset[f_r], list.length[f_r]);
    let s = read_scalar(body, list.offset[f_s], list.length[f_s]);
    let mut signature: [u8; 64] = [0; 64];
    for i in 0..32 {
        signature[i] = r[i];
        signature[32 + i] = s[i];
    }

    // ---- recipient and calldata
    assert(list.length[f_to] == 20, "Transaction has no 20-byte recipient");
    let mut to: [u8; 20] = [0; 20];
    for i in 0..20 {
        to[i] = body[list.offset[f_to] + i];
    }

    let data_length = list.length[f_data];
    let mut selector: [u8; 4] = [0; 4];
    for i in 0..4 {
        if i < data_length {
            selector[i] = body[list.offset[f_data] + i];
        }
    }

    SignedTx { unsigned_hash, signature, to, data_length, selector }
}

#[test]
fn rlp_uint_encodes_like_ethereum() {
    let (a, al) = rlp_uint(0);
    assert((al == 1) & (a[0] == 0x80));
    let (b, bl) = rlp_uint(0x7f);
    assert((bl == 1) & (b[0] == 0x7f));
    let (c, cl) = rlp_uint(0x80);
    assert((cl == 2) & (c[0] == 0x81) & (c[1] == 0x80));
    // GIWA Sepolia, 91342 = 0x0164ce
    let (d, dl) = rlp_uint(91342);
    assert((dl == 4) & (d[0] == 0x83) & (d[1] == 0x01) & (d[2] == 0x64) & (d[3] == 0xce));
}

#[test]
fn a_short_scalar_is_left_padded() {
    let bytes: [u8; 4] = [0xaa, 0xbb, 0xcc, 0xdd];
    let out = read_scalar(bytes, 1, 2);
    assert((out[29] == 0) & (out[30] == 0xbb) & (out[31] == 0xcc));
}
