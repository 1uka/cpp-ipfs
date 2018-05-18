/**
 * @brief Multihash implementation in cpp
 * 
 * @file hash.cpp
 * @author Luka Atanasovski
 * @date 2018-05-15
 */

#include "hash.hpp"

namespace multi {
namespace hash {


bytes sum(const bytes& input, const Type& type)
{
	bytes digest(type.len());

	switch(type.code())
	{
		case sha1.code():
		{
			CryptoPP::SHA1 sha1;
			sha1.CalculateDigest(digest.data(), input.data(), input.size());
			break;
		}
		case sha2_256.code():
		{
			CryptoPP::SHA256 sha2;
			sha2.CalculateDigest(digest.data(), input.data(), input.size());
			break;
		}
		case sha2_512.code():
		{
			CryptoPP::SHA256 sha2;
			sha2.CalculateDigest(digest.data(), input.data(), input.size());
			break;
		}
		case sha3_224.code():
		{
			CryptoPP::SHA3_224 sha3;
			sha3.CalculateDigest(digest.data(), input.data(), input.size());
			break;
		}
		case sha3_256.code():
		{
			CryptoPP::SHA3_256 sha3;
			sha3.CalculateDigest(digest.data(), input.data(), input.size());
			break;
		}
		case sha3_384.code():
		{
			CryptoPP::SHA3_384 sha3;
			sha3.CalculateDigest(digest.data(), input.data(), input.size());
			break;
		}
		case sha3_512.code():
		{
			CryptoPP::SHA3_512 sha3;
			sha3.CalculateDigest(digest.data(), input.data(), input.size());
			break;
		}
		case keccak_224.code():
		{
			CryptoPP::Keccak_224 keccak;
			keccak.CalculateDigest(digest.data(), input.data(), input.size());
			break;
		}
		case keccak_256.code():
		{
			CryptoPP::Keccak_256 keccak;
			keccak.CalculateDigest(digest.data(), input.data(), input.size());
			break;
		}
		case keccak_384.code():
		{
			CryptoPP::Keccak_384 keccak;
			keccak.CalculateDigest(digest.data(), input.data(), input.size());
			break;
		}
		case keccak_512.code():
		{
			CryptoPP::Keccak_512 keccak;
			keccak.CalculateDigest(digest.data(), input.data(), input.size());
			break;
		}

		default:
			if(type.code() >> 8 == 0xb2) // blake2x
			{
				uint8_t lb = type.code() & 0xff; // find out if its blake2b or blake2s (or neither)
				if(lb >= 0x01 && lb <= 0x40)
				{
					CryptoPP::BLAKE2b bl2b(false, type.len());
					bl2b.CalculateDigest(digest.data(), input.data(), input.size());
				} else if(lb >= 0x41 && lb <= 0x60)
				{
					CryptoPP::BLAKE2s bl2s(false, type.len());
					bl2s.CalculateDigest(digest.data(), input.data(), input.size());
				} else throw Exception("invalid blake hash code");
			} else throw Exception("unknown hash function type");
	}

	digest.insert(digest.begin(), type.len());
	digest.insert(digest.begin(), type.code());
	
	return digest;
}


}
}