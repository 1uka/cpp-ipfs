/**
 * @brief Buffers with varint prefixes defining the codec used
 * 
 * @file codec.hpp
 * @author Luka Atanasovski
 * @date 2018-05-19
 */


#pragma once


#include <common/types.hpp>
#include <common/varint.hpp>


namespace multi {
namespace codec {

enum prefix
{
    bin =                  0x55,

    // bases encodings
    base1 =                0x01,
    // base2 =                0x55,
    base8 =                0x07,
    base10 =               0x09,

    // serialization formats
    cbor =                 0x51,
    protobuf =             0x50,
    rlp =                  0x60,
    bencode =              0x63,

    // multiformats
    multicodec =           0x30,
    multihash =            0x31,
    multiaddr =            0x32,
    multibase =            0x33,

    // multihashes
    sha1 =                 0x11,
    sha2_256 =             0x12,
    sha2_512 =             0x13,
    dbl_sha2_256 =         0x56,
    sha3_224 =             0x17,
    sha3_256 =             0x16,
    sha3_384 =             0x15,
    sha3_512 =             0x14,
    shake_128 =            0x18,
    shake_256 =            0x19,
    keccak_224 =           0x1A,
    keccak_256 =           0x1B,
    keccak_384 =           0x1C,
    keccak_512 =           0x1D,
    murmur3 =              0x22,
    blake2b_8 =            0xb201,
    blake2b_16 =           0xb202,
    blake2b_24 =           0xb203,
    blake2b_32 =           0xb204,
    blake2b_40 =           0xb205,
    blake2b_48 =           0xb206,
    blake2b_56 =           0xb207,
    blake2b_64 =           0xb208,
    blake2b_72 =           0xb209,
    blake2b_80 =           0xb20a,
    blake2b_88 =           0xb20b,
    blake2b_96 =           0xb20c,
    blake2b_104 =          0xb20d,
    blake2b_112 =          0xb20e,
    blake2b_120 =          0xb20f,
    blake2b_128 =          0xb210,
    blake2b_136 =          0xb211,
    blake2b_144 =          0xb212,
    blake2b_152 =          0xb213,
    blake2b_160 =          0xb214,
    blake2b_168 =          0xb215,
    blake2b_176 =          0xb216,
    blake2b_184 =          0xb217,
    blake2b_192 =          0xb218,
    blake2b_200 =          0xb219,
    blake2b_208 =          0xb21a,
    blake2b_216 =          0xb21b,
    blake2b_224 =          0xb21c,
    blake2b_232 =          0xb21d,
    blake2b_240 =          0xb21e,
    blake2b_248 =          0xb21f,
    blake2b_256 =          0xb220,
    blake2b_264 =          0xb221,
    blake2b_272 =          0xb222,
    blake2b_280 =          0xb223,
    blake2b_288 =          0xb224,
    blake2b_296 =          0xb225,
    blake2b_304 =          0xb226,
    blake2b_312 =          0xb227,
    blake2b_320 =          0xb228,
    blake2b_328 =          0xb229,
    blake2b_336 =          0xb22a,
    blake2b_344 =          0xb22b,
    blake2b_352 =          0xb22c,
    blake2b_360 =          0xb22d,
    blake2b_368 =          0xb22e,
    blake2b_376 =          0xb22f,
    blake2b_384 =          0xb230,
    blake2b_392 =          0xb231,
    blake2b_400 =          0xb232,
    blake2b_408 =          0xb233,
    blake2b_416 =          0xb234,
    blake2b_424 =          0xb235,
    blake2b_432 =          0xb236,
    blake2b_440 =          0xb237,
    blake2b_448 =          0xb238,
    blake2b_456 =          0xb239,
    blake2b_464 =          0xb23a,
    blake2b_472 =          0xb23b,
    blake2b_480 =          0xb23c,
    blake2b_488 =          0xb23d,
    blake2b_496 =          0xb23e,
    blake2b_504 =          0xb23f,
    blake2b_512 =          0xb240,
    blake2s_8 =            0xb241,
    blake2s_16 =           0xb242,
    blake2s_24 =           0xb243,
    blake2s_32 =           0xb244,
    blake2s_40 =           0xb245,
    blake2s_48 =           0xb246,
    blake2s_56 =           0xb247,
    blake2s_64 =           0xb248,
    blake2s_72 =           0xb249,
    blake2s_80 =           0xb24a,
    blake2s_88 =           0xb24b,
    blake2s_96 =           0xb24c,
    blake2s_104 =          0xb24d,
    blake2s_112 =          0xb24e,
    blake2s_120 =          0xb24f,
    blake2s_128 =          0xb250,
    blake2s_136 =          0xb251,
    blake2s_144 =          0xb252,
    blake2s_152 =          0xb253,
    blake2s_160 =          0xb254,
    blake2s_168 =          0xb255,
    blake2s_176 =          0xb256,
    blake2s_184 =          0xb257,
    blake2s_192 =          0xb258,
    blake2s_200 =          0xb259,
    blake2s_208 =          0xb25a,
    blake2s_216 =          0xb25b,
    blake2s_224 =          0xb25c,
    blake2s_232 =          0xb25d,
    blake2s_240 =          0xb25e,
    blake2s_248 =          0xb25f,
    blake2s_256 =          0xb260,

    // multiaddrs
    ip4 =                  0x04,
    ip6 =                  0x29,
    tcp =                  0x06,
    udp =                  0x0111,
    dccp =                 0x21,
    sctp =                 0x84,
    udt =                  0x012D,
    utp =                  0x012E,
    ipfs =                 0x01A5,
    http =                 0x01E0,
    https =                0x01BB,
    quic =                 0x01CC,
    ws =                   0x01DD,
    onion =                0x01BC,
    p2p_circuit =          0x0122,

    // IPLD formats
    dag_pb =               0x70,
    dag_cbor =             0x71,

    git_raw =              0x78,

    eth_block =            0x90,
    eth_block_list =       0x91,
    eth_tx_trie =          0x92,
    eth_tx =               0x93,
    eth_tx_receipt_trie =  0x94,
    eth_tx_receipt =       0x95,
    eth_state_trie =       0x96,
    eth_account_snapshot = 0x97,
    eth_storage_trie =     0x98,

    bitcoin_block =        0xb0,
    bitcoin_tx =           0xb1,

    zcash_block =          0xc0,
    zcash_tx =             0xc1,

    stellar_block =        0xd0,
    stellar_tx =           0xd1,

    torrent_info =         0x7b,
    torrent_file =         0x7c,
    ed25519_pub =          0xed
};

inline uint64_t extract_prefix(const bytes& buf) { return uvarint(buf); }
inline void add_prefix(bytes& buf, prefix codec) { put_uvarint(buf, codec); }
inline void remove_prefix(bytes& buf)
{
    int len;
    uvarint(buf, &len);
    buf.erase(buf.begin(), buf.begin() + len);
}

}
}

