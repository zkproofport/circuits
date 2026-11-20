// EIP-1559 Transaction Parser (Type 0x02 only)
//
// RLP-based parser specifically for EIP-1559 transactions.
// Supports any valid EIP-1559 transaction without hardcoded offsets.
//
// IMPORTANT: This parser ONLY supports Type 0x02 (EIP-1559) transactions.
// Legacy (Type 0), EIP-2930 (Type 0x01), and EIP-4844 (Type 0x03) are NOT supported.
//
// Why EIP-1559 only?
// - Coinbase attestations on Base chain exclusively use EIP-1559 transactions
// - Base is an Optimism-based L2 that uses EIP-1559 as the standard
// - Adding support for other transaction types would increase circuit complexity
//   without practical benefit for the Coinbase attestation use case

use dep::keccak256::keccak256;
use crate::rlp;

/// EIP-1559 Transaction Field Indices (12 fields total)
// Commented out unused fields to avoid compiler warnings
// Uncomment if needed for additional transaction validation

// global FIELD_CHAIN_ID: u32 = 0;           // Network identifier
// global FIELD_NONCE: u32 = 1;              // Transaction sequence number
// global FIELD_MAX_PRIORITY_FEE: u32 = 2;   // Tip to miner (EIP-1559)
// global FIELD_MAX_FEE: u32 = 3;            // Maximum gas price (EIP-1559)
// global FIELD_GAS_LIMIT: u32 = 4;          // Maximum gas units
global FIELD_TO: u32 = 5;                    // Recipient address
// global FIELD_VALUE: u32 = 6;              // ETH amount to transfer
global FIELD_DATA: u32 = 7;                  // Contract call data (calldata)
global FIELD_ACCESS_LIST: u32 = 8;           // EIP-2930 access list
global FIELD_V: u32 = 9;                     // Signature recovery id
global FIELD_R: u32 = 10;                    // Signature r value
global FIELD_S: u32 = 11;                    // Signature s value

/// Creates the unsigned transaction hash using RLP-based parsing
///
/// Strategy: Use RLP parser to find where signature fields (v,r,s) start,
/// then remove them from the original transaction while preserving RLP encoding.
///
/// Generic RLP-based parsing - works with any valid EIP-1559 transaction.
/// tx_length parameter is needed to know where padding starts in the fixed-size array.
pub fn create_unsigned_tx_hash(raw_tx: [u8; 300], tx_length: u32) -> [u8; 32] {
    assert(raw_tx[0] == 0x02, "Must be EIP-1559");

    // Extract RLP data (skip 0x02 prefix)
    let mut rlp_data: [u8; 299] = [0; 299];
    for i in 0..299 {
        if i < (tx_length - 1) {
            rlp_data[i] = raw_tx[i + 1];
        }
    }

    // Decode transaction to find field positions
    let tx_list: rlp::RLP_List<12> = rlp::decode1(rlp_data);
    assert(tx_list.num_fields == 12, "Invalid EIP-1559 structure");

    // Find where access_list field ends (last unsigned field)
    // Signature starts right after access_list
    let access_list_data_type = tx_list.data_type[FIELD_ACCESS_LIST];
    let access_list_offset = tx_list.offset[FIELD_ACCESS_LIST];
    let access_list_length = tx_list.length[FIELD_ACCESS_LIST];

    // Calculate where access_list ends based on its type
    let access_list_end = if access_list_data_type == 1 {
        // LIST type: offset + length gives us the end
        access_list_offset + access_list_length
    } else {
        // STRING type (empty access list is 0xc0): need to add header size
        if access_list_length == 0 {
            access_list_offset + 1  // 0xc0 (1 byte for empty list)
        } else {
            access_list_offset + access_list_length + 1
        }
    };

    // Signature RLP length = from end of access_list to end of rlp_data
    let signature_rlp_length = (tx_length - 1) - access_list_end;

    // Build unsigned transaction
    let mut unsigned_tx: [u8; 300] = [0; 300];
    let unsigned_length = tx_length - signature_rlp_length;

    // Copy unsigned portion
    for i in 0..300 {
        if i < unsigned_length {
            unsigned_tx[i] = raw_tx[i];
        }
    }

    // Fix RLP list length byte
    let signed_rlp_length = raw_tx[2];
    let unsigned_rlp_length = signed_rlp_length - (signature_rlp_length as u8);
    unsigned_tx[2] = unsigned_rlp_length;

    keccak256(unsigned_tx, unsigned_length)
}

/// Extracts the destination address using RLP parser
pub fn extract_to_address(raw_tx: [u8; 300]) -> [u8; 20] {
    assert(raw_tx[0] == 0x02, "Must be EIP-1559");

    let mut rlp_data: [u8; 299] = [0; 299];
    for i in 0..299 {
        rlp_data[i] = raw_tx[i + 1];
    }

    let tx_list: rlp::RLP_List<12> = rlp::decode1(rlp_data);

    // Extract 'to' field (index 5)
    let to_offset: u32 = tx_list.offset[FIELD_TO];
    let to_length: u32 = tx_list.length[FIELD_TO];

    assert(to_length == 20, "Invalid address length");

    let mut to_address: [u8; 20] = [0; 20];
    for i in 0..20 {
        to_address[i] = rlp_data[to_offset + i];
    }

    to_address
}

/// Extracts calldata using RLP parser
pub fn extract_calldata(raw_tx: [u8; 300]) -> [u8; 36] {
    assert(raw_tx[0] == 0x02, "Must be EIP-1559");

    let mut rlp_data: [u8; 299] = [0; 299];
    for i in 0..299 {
        rlp_data[i] = raw_tx[i + 1];
    }

    let tx_list: rlp::RLP_List<12> = rlp::decode1(rlp_data);

    // Extract 'data' field (index 7)
    let data_offset: u32 = tx_list.offset[FIELD_DATA];
    let data_length: u32 = tx_list.length[FIELD_DATA];

    assert(data_length >= 36, "Calldata too short");

    let mut calldata: [u8; 36] = [0; 36];
    for i in 0..36 {
        calldata[i] = rlp_data[data_offset + i];
    }

    calldata
}

/// Extracts address from calldata
pub fn extract_address_from_calldata(calldata: [u8; 36]) -> [u8; 20] {
    let mut address: [u8; 20] = [0; 20];

    for i in 0..20 {
        address[i] = calldata[16 + i];
    }

    address
}

/// Extracts signature (v, r, s) using RLP parser
pub fn extract_signature_from_tx(raw_tx: [u8; 300]) -> [u8; 65] {
    assert(raw_tx[0] == 0x02, "Must be EIP-1559");

    // Extract RLP data (skip 0x02 prefix)
    let mut rlp_data: [u8; 299] = [0; 299];
    for i in 0..299 {
        rlp_data[i] = raw_tx[i + 1];
    }

    let tx_list: rlp::RLP_List<12> = rlp::decode1(rlp_data);

    // Extract v, r, s
    let v_offset: u32 = tx_list.offset[FIELD_V];
    let v_length: u32 = tx_list.length[FIELD_V];
    let r_offset: u32 = tx_list.offset[FIELD_R];
    let r_length: u32 = tx_list.length[FIELD_R];
    let s_offset: u32 = tx_list.offset[FIELD_S];
    let s_length: u32 = tx_list.length[FIELD_S];

    assert(r_length == 32, "Invalid r length");
    assert(s_length == 32, "Invalid s length");

    let mut signature: [u8; 65] = [0; 65];

    // Extract r
    for i in 0..32 {
        signature[i] = rlp_data[r_offset + i];
    }

    // Extract s
    for i in 0..32 {
        signature[32 + i] = rlp_data[s_offset + i];
    }

    // Extract v
    let v_byte = if v_length == 0 {
        0
    } else if v_length == 1 {
        rlp_data[v_offset]
    } else {
        // v is RLP encoded as 0x01 for value 1
        let v_prefix = rlp_data[v_offset];
        if v_prefix < 0x80 {
            v_prefix  // Single byte value
        } else if v_prefix == 0x80 {
            0  // Empty string = 0
        } else {
            rlp_data[v_offset + 1]  // Length-prefixed
        }
    };

    signature[64] = v_byte;

    signature
}