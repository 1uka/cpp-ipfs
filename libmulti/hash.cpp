/**
 * @brief Multihash implementation in cpp
 * 
 * @file hash.cpp
 * @author Luka Atanasovski
 * @date 2018-05-15
 */

#include "hash.hpp"

#include <cryptopp/sha.h>
#include <cryptopp/sha3.h>
#include <cryptopp/keccak.h>
#include <cryptopp/blake2.h>

#include <common/varint.hpp>

namespace multi
{
namespace hash
{

bytes sum(const bytes &input, const Type &type)
{
    bytes digest(type.len());

    switch (type.code())
    {
    case ID.code():
        digest = bytes(input);
        put_uvarint(digest, 0x0000);
        return digest;
    case sha1.code():
        CryptoPP::SHA1().CalculateDigest(digest.data(), input.data(), input.size());
        break;
    case sha2_256.code():
        CryptoPP::SHA256().CalculateDigest(digest.data(), input.data(), input.size());
        break;
    case sha2_512.code():
        CryptoPP::SHA256().CalculateDigest(digest.data(), input.data(), input.size());
        break;
    case sha3_224.code():
        CryptoPP::SHA3_224().CalculateDigest(digest.data(), input.data(), input.size());
        break;
    case sha3_256.code():
        CryptoPP::SHA3_256().CalculateDigest(digest.data(), input.data(), input.size());
        break;
    case sha3_384.code():
        CryptoPP::SHA3_384().CalculateDigest(digest.data(), input.data(), input.size());
        break;
    case sha3_512.code():
        CryptoPP::SHA3_512().CalculateDigest(digest.data(), input.data(), input.size());
        break;
    case keccak_224.code():
        CryptoPP::Keccak_224().CalculateDigest(digest.data(), input.data(), input.size());
        break;
    case keccak_256.code():
        CryptoPP::Keccak_256().CalculateDigest(digest.data(), input.data(), input.size());
        break;
    case keccak_384.code():
        CryptoPP::Keccak_384().CalculateDigest(digest.data(), input.data(), input.size());
        break;
    case keccak_512.code():
        CryptoPP::Keccak_512().CalculateDigest(digest.data(), input.data(), input.size());
        break;

    default:
        if (type.code() >> 8 == 0xb2) // blake2x
        {
            uint8_t lb = type.code() & 0xff; // find out if its blake2b or blake2s (or neither)
            if (lb >= 0x01 && lb <= 0x40)
            {
                CryptoPP::BLAKE2b(false, type.len()).CalculateDigest(digest.data(), input.data(), input.size());
            }
            else if (lb >= 0x41 && lb <= 0x60)
            {
                CryptoPP::BLAKE2s(false, type.len()).CalculateDigest(digest.data(), input.data(), input.size());
            }
            else
                throw Exception("invalid blake hash code");
        }
        else
            throw Exception("unknown hash function type");
    }

    put_uvarint(digest, type.len());
    put_uvarint(digest, type.code());

    return digest;
}

Decoded::Decoded(const bytes &_hash)
{
    if (_hash.size() < 2)
    {
        return;
    }
    int len;
    uvarint(_hash, &len);
    if (len > 10)
    {
        len = 2;
    }
    m_hash = bytes(_hash.begin() + len, _hash.end());
    m_type = Type(_hash[0], _hash[1]);
}

} // namespace hash
} // namespace multi