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
		case blake2b_8.code():
		{
			CryptoPP::BLAKE2b bl2b(false, 8 / 8);
			bl2b.CalculateDigest(digest.data(), input.data(), input.size());
			break;
		}
		case blake2b_16.code():
		{
			CryptoPP::BLAKE2b bl2b(false, 16 / 8);
			bl2b.CalculateDigest(digest.data(), input.data(), input.size());
			break;
		}
		case blake2b_24.code():
		{
			CryptoPP::BLAKE2b bl2b(false, 24 / 8);
			bl2b.CalculateDigest(digest.data(), input.data(), input.size());
			break;
		}
		case blake2b_32.code():
		{
			CryptoPP::BLAKE2b bl2b(false, 32 / 8);
			bl2b.CalculateDigest(digest.data(), input.data(), input.size());
			break;
		}
		case blake2b_40.code():
		{
			CryptoPP::BLAKE2b bl2b(false, 40 / 8);
			bl2b.CalculateDigest(digest.data(), input.data(), input.size());
			break;
		}
		case blake2b_48.code():
		{
			CryptoPP::BLAKE2b bl2b(false, 48 / 8);
			bl2b.CalculateDigest(digest.data(), input.data(), input.size());
			break;
		}
		case blake2b_56.code():
		{
			CryptoPP::BLAKE2b bl2b(false, 56 / 8);
			bl2b.CalculateDigest(digest.data(), input.data(), input.size());
			break;
		}
		case blake2b_64.code():
		{
			CryptoPP::BLAKE2b bl2b(false, 64 / 8);
			bl2b.CalculateDigest(digest.data(), input.data(), input.size());
			break;
		}
		case blake2b_72.code():
		{
			CryptoPP::BLAKE2b bl2b(false, 72 / 8);
			bl2b.CalculateDigest(digest.data(), input.data(), input.size());
			break;
		}
		case blake2b_80.code():
		{
			CryptoPP::BLAKE2b bl2b(false, 80 / 8);
			bl2b.CalculateDigest(digest.data(), input.data(), input.size());
			break;
		}
		case blake2b_88.code():
		{
			CryptoPP::BLAKE2b bl2b(false, 88 / 8);
			bl2b.CalculateDigest(digest.data(), input.data(), input.size());
			break;
		}
		case blake2b_96.code():
		{
			CryptoPP::BLAKE2b bl2b(false, 96 / 8);
			bl2b.CalculateDigest(digest.data(), input.data(), input.size());
			break;
		}
		case blake2b_104.code():
		{
			CryptoPP::BLAKE2b bl2b(false, 104 / 8);
			bl2b.CalculateDigest(digest.data(), input.data(), input.size());
			break;
		}
		case blake2b_112.code():
		{
			CryptoPP::BLAKE2b bl2b(false, 112 / 8);
			bl2b.CalculateDigest(digest.data(), input.data(), input.size());
			break;
		}
		case blake2b_120.code():
		{
			CryptoPP::BLAKE2b bl2b(false, 120 / 8);
			bl2b.CalculateDigest(digest.data(), input.data(), input.size());
			break;
		}
		case blake2b_128.code():
		{
			CryptoPP::BLAKE2b bl2b(false, 128 / 8);
			bl2b.CalculateDigest(digest.data(), input.data(), input.size());
			break;
		}
		case blake2b_136.code():
		{
			CryptoPP::BLAKE2b bl2b(false, 136 / 8);
			bl2b.CalculateDigest(digest.data(), input.data(), input.size());
			break;
		}
		case blake2b_144.code():
		{
			CryptoPP::BLAKE2b bl2b(false, 144 / 8);
			bl2b.CalculateDigest(digest.data(), input.data(), input.size());
			break;
		}
		case blake2b_152.code():
		{
			CryptoPP::BLAKE2b bl2b(false, 152 / 8);
			bl2b.CalculateDigest(digest.data(), input.data(), input.size());
			break;
		}
		case blake2b_160.code():
		{
			CryptoPP::BLAKE2b bl2b(false, 160 / 8);
			bl2b.CalculateDigest(digest.data(), input.data(), input.size());
			break;
		}
		case blake2b_168.code():
		{
			CryptoPP::BLAKE2b bl2b(false, 168 / 8);
			bl2b.CalculateDigest(digest.data(), input.data(), input.size());
			break;
		}
		case blake2b_176.code():
		{
			CryptoPP::BLAKE2b bl2b(false, 176 / 8);
			bl2b.CalculateDigest(digest.data(), input.data(), input.size());
			break;
		}
		case blake2b_184.code():
		{
			CryptoPP::BLAKE2b bl2b(false, 184 / 8);
			bl2b.CalculateDigest(digest.data(), input.data(), input.size());
			break;
		}
		case blake2b_192.code():
		{
			CryptoPP::BLAKE2b bl2b(false, 192 / 8);
			bl2b.CalculateDigest(digest.data(), input.data(), input.size());
			break;
		}
		case blake2b_200.code():
		{
			CryptoPP::BLAKE2b bl2b(false, 200 / 8);
			bl2b.CalculateDigest(digest.data(), input.data(), input.size());
			break;
		}
		case blake2b_208.code():
		{
			CryptoPP::BLAKE2b bl2b(false, 208 / 8);
			bl2b.CalculateDigest(digest.data(), input.data(), input.size());
			break;
		}
		case blake2b_216.code():
		{
			CryptoPP::BLAKE2b bl2b(false, 216 / 8);
			bl2b.CalculateDigest(digest.data(), input.data(), input.size());
			break;
		}
		case blake2b_224.code():
		{
			CryptoPP::BLAKE2b bl2b(false, 224 / 8);
			bl2b.CalculateDigest(digest.data(), input.data(), input.size());
			break;
		}
		case blake2b_232.code():
		{
			CryptoPP::BLAKE2b bl2b(false, 232 / 8);
			bl2b.CalculateDigest(digest.data(), input.data(), input.size());
			break;
		}
		case blake2b_240.code():
		{
			CryptoPP::BLAKE2b bl2b(false, 240 / 8);
			bl2b.CalculateDigest(digest.data(), input.data(), input.size());
			break;
		}
		case blake2b_248.code():
		{
			CryptoPP::BLAKE2b bl2b(false, 248 / 8);
			bl2b.CalculateDigest(digest.data(), input.data(), input.size());
			break;
		}
		case blake2b_256.code():
		{
			CryptoPP::BLAKE2b bl2b(false, 256 / 8);
			bl2b.CalculateDigest(digest.data(), input.data(), input.size());
			break;
		}
		case blake2b_264.code():
		{
			CryptoPP::BLAKE2b bl2b(false, 264 / 8);
			bl2b.CalculateDigest(digest.data(), input.data(), input.size());
			break;
		}
		case blake2b_272.code():
		{
			CryptoPP::BLAKE2b bl2b(false, 272 / 8);
			bl2b.CalculateDigest(digest.data(), input.data(), input.size());
			break;
		}
		case blake2b_280.code():
		{
			CryptoPP::BLAKE2b bl2b(false, 280 / 8);
			bl2b.CalculateDigest(digest.data(), input.data(), input.size());
			break;
		}
		case blake2b_288.code():
		{
			CryptoPP::BLAKE2b bl2b(false, 288 / 8);
			bl2b.CalculateDigest(digest.data(), input.data(), input.size());
			break;
		}
		case blake2b_296.code():
		{
			CryptoPP::BLAKE2b bl2b(false, 296 / 8);
			bl2b.CalculateDigest(digest.data(), input.data(), input.size());
			break;
		}
		case blake2b_304.code():
		{
			CryptoPP::BLAKE2b bl2b(false, 304 / 8);
			bl2b.CalculateDigest(digest.data(), input.data(), input.size());
			break;
		}
		case blake2b_312.code():
		{
			CryptoPP::BLAKE2b bl2b(false, 312 / 8);
			bl2b.CalculateDigest(digest.data(), input.data(), input.size());
			break;
		}
		case blake2b_320.code():
		{
			CryptoPP::BLAKE2b bl2b(false, 320 / 8);
			bl2b.CalculateDigest(digest.data(), input.data(), input.size());
			break;
		}
		case blake2b_328.code():
		{
			CryptoPP::BLAKE2b bl2b(false, 328 / 8);
			bl2b.CalculateDigest(digest.data(), input.data(), input.size());
			break;
		}
		case blake2b_336.code():
		{
			CryptoPP::BLAKE2b bl2b(false, 336 / 8);
			bl2b.CalculateDigest(digest.data(), input.data(), input.size());
			break;
		}
		case blake2b_344.code():
		{
			CryptoPP::BLAKE2b bl2b(false, 344 / 8);
			bl2b.CalculateDigest(digest.data(), input.data(), input.size());
			break;
		}
		case blake2b_352.code():
		{
			CryptoPP::BLAKE2b bl2b(false, 352 / 8);
			bl2b.CalculateDigest(digest.data(), input.data(), input.size());
			break;
		}
		case blake2b_360.code():
		{
			CryptoPP::BLAKE2b bl2b(false, 360 / 8);
			bl2b.CalculateDigest(digest.data(), input.data(), input.size());
			break;
		}
		case blake2b_368.code():
		{
			CryptoPP::BLAKE2b bl2b(false, 368 / 8);
			bl2b.CalculateDigest(digest.data(), input.data(), input.size());
			break;
		}
		case blake2b_376.code():
		{
			CryptoPP::BLAKE2b bl2b(false, 376 / 8);
			bl2b.CalculateDigest(digest.data(), input.data(), input.size());
			break;
		}
		case blake2b_384.code():
		{
			CryptoPP::BLAKE2b bl2b(false, 384 / 8);
			bl2b.CalculateDigest(digest.data(), input.data(), input.size());
			break;
		}
		case blake2b_392.code():
		{
			CryptoPP::BLAKE2b bl2b(false, 392 / 8);
			bl2b.CalculateDigest(digest.data(), input.data(), input.size());
			break;
		}
		case blake2b_400.code():
		{
			CryptoPP::BLAKE2b bl2b(false, 400 / 8);
			bl2b.CalculateDigest(digest.data(), input.data(), input.size());
			break;
		}
		case blake2b_408.code():
		{
			CryptoPP::BLAKE2b bl2b(false, 408 / 8);
			bl2b.CalculateDigest(digest.data(), input.data(), input.size());
			break;
		}
		case blake2b_416.code():
		{
			CryptoPP::BLAKE2b bl2b(false, 416 / 8);
			bl2b.CalculateDigest(digest.data(), input.data(), input.size());
			break;
		}
		case blake2b_424.code():
		{
			CryptoPP::BLAKE2b bl2b(false, 424 / 8);
			bl2b.CalculateDigest(digest.data(), input.data(), input.size());
			break;
		}
		case blake2b_432.code():
		{
			CryptoPP::BLAKE2b bl2b(false, 432 / 8);
			bl2b.CalculateDigest(digest.data(), input.data(), input.size());
			break;
		}
		case blake2b_440.code():
		{
			CryptoPP::BLAKE2b bl2b(false, 440 / 8);
			bl2b.CalculateDigest(digest.data(), input.data(), input.size());
			break;
		}
		case blake2b_448.code():
		{
			CryptoPP::BLAKE2b bl2b(false, 448 / 8);
			bl2b.CalculateDigest(digest.data(), input.data(), input.size());
			break;
		}
		case blake2b_456.code():
		{
			CryptoPP::BLAKE2b bl2b(false, 456 / 8);
			bl2b.CalculateDigest(digest.data(), input.data(), input.size());
			break;
		}
		case blake2b_464.code():
		{
			CryptoPP::BLAKE2b bl2b(false, 464 / 8);
			bl2b.CalculateDigest(digest.data(), input.data(), input.size());
			break;
		}
		case blake2b_472.code():
		{
			CryptoPP::BLAKE2b bl2b(false, 472 / 8);
			bl2b.CalculateDigest(digest.data(), input.data(), input.size());
			break;
		}
		case blake2b_480.code():
		{
			CryptoPP::BLAKE2b bl2b(false, 480 / 8);
			bl2b.CalculateDigest(digest.data(), input.data(), input.size());
			break;
		}
		case blake2b_488.code():
		{
			CryptoPP::BLAKE2b bl2b(false, 488 / 8);
			bl2b.CalculateDigest(digest.data(), input.data(), input.size());
			break;
		}
		case blake2b_496.code():
		{
			CryptoPP::BLAKE2b bl2b(false, 496 / 8);
			bl2b.CalculateDigest(digest.data(), input.data(), input.size());
			break;
		}
		case blake2b_504.code():
		{
			CryptoPP::BLAKE2b bl2b(false, 504 / 8);
			bl2b.CalculateDigest(digest.data(), input.data(), input.size());
			break;
		}
		case blake2b_512.code():
		{
			CryptoPP::BLAKE2b bl2b(false, 512 / 8);
			bl2b.CalculateDigest(digest.data(), input.data(), input.size());
			break;
		}
		case blake2s_8.code():
		{
			CryptoPP::BLAKE2s bl2s(false, 8 / 8);
			bl2s.CalculateDigest(digest.data(), input.data(), input.size());
			break;
		}
		case blake2s_16.code():
		{
			CryptoPP::BLAKE2s bl2s(false, 16 / 8);
			bl2s.CalculateDigest(digest.data(), input.data(), input.size());
			break;
		}
		case blake2s_24.code():
		{
			CryptoPP::BLAKE2s bl2s(false, 24 / 8);
			bl2s.CalculateDigest(digest.data(), input.data(), input.size());
			break;
		}
		case blake2s_32.code():
		{
			CryptoPP::BLAKE2s bl2s(false, 32 / 8);
			bl2s.CalculateDigest(digest.data(), input.data(), input.size());
			break;
		}
		case blake2s_40.code():
		{
			CryptoPP::BLAKE2s bl2s(false, 40 / 8);
			bl2s.CalculateDigest(digest.data(), input.data(), input.size());
			break;
		}
		case blake2s_48.code():
		{
			CryptoPP::BLAKE2s bl2s(false, 48 / 8);
			bl2s.CalculateDigest(digest.data(), input.data(), input.size());
			break;
		}
		case blake2s_56.code():
		{
			CryptoPP::BLAKE2s bl2s(false, 56 / 8);
			bl2s.CalculateDigest(digest.data(), input.data(), input.size());
			break;
		}
		case blake2s_64.code():
		{
			CryptoPP::BLAKE2s bl2s(false, 64 / 8);
			bl2s.CalculateDigest(digest.data(), input.data(), input.size());
			break;
		}
		case blake2s_72.code():
		{
			CryptoPP::BLAKE2s bl2s(false, 72 / 8);
			bl2s.CalculateDigest(digest.data(), input.data(), input.size());
			break;
		}
		case blake2s_80.code():
		{
			CryptoPP::BLAKE2s bl2s(false, 80 / 8);
			bl2s.CalculateDigest(digest.data(), input.data(), input.size());
			break;
		}
		case blake2s_88.code():
		{
			CryptoPP::BLAKE2s bl2s(false, 88 / 8);
			bl2s.CalculateDigest(digest.data(), input.data(), input.size());
			break;
		}
		case blake2s_96.code():
		{
			CryptoPP::BLAKE2s bl2s(false, 96 / 8);
			bl2s.CalculateDigest(digest.data(), input.data(), input.size());
			break;
		}
		case blake2s_104.code():
		{
			CryptoPP::BLAKE2s bl2s(false, 104 / 8);
			bl2s.CalculateDigest(digest.data(), input.data(), input.size());
			break;
		}
		case blake2s_112.code():
		{
			CryptoPP::BLAKE2s bl2s(false, 112 / 8);
			bl2s.CalculateDigest(digest.data(), input.data(), input.size());
			break;
		}
		case blake2s_120.code():
		{
			CryptoPP::BLAKE2s bl2s(false, 120 / 8);
			bl2s.CalculateDigest(digest.data(), input.data(), input.size());
			break;
		}
		case blake2s_128.code():
		{
			CryptoPP::BLAKE2s bl2s(false, 128 / 8);
			bl2s.CalculateDigest(digest.data(), input.data(), input.size());
			break;
		}
		case blake2s_136.code():
		{
			CryptoPP::BLAKE2s bl2s(false, 136 / 8);
			bl2s.CalculateDigest(digest.data(), input.data(), input.size());
			break;
		}
		case blake2s_144.code():
		{
			CryptoPP::BLAKE2s bl2s(false, 144 / 8);
			bl2s.CalculateDigest(digest.data(), input.data(), input.size());
			break;
		}
		case blake2s_152.code():
		{
			CryptoPP::BLAKE2s bl2s(false, 152 / 8);
			bl2s.CalculateDigest(digest.data(), input.data(), input.size());
			break;
		}
		case blake2s_160.code():
		{
			CryptoPP::BLAKE2s bl2s(false, 160 / 8);
			bl2s.CalculateDigest(digest.data(), input.data(), input.size());
			break;
		}
		case blake2s_168.code():
		{
			CryptoPP::BLAKE2s bl2s(false, 168 / 8);
			bl2s.CalculateDigest(digest.data(), input.data(), input.size());
			break;
		}
		case blake2s_176.code():
		{
			CryptoPP::BLAKE2s bl2s(false, 176 / 8);
			bl2s.CalculateDigest(digest.data(), input.data(), input.size());
			break;
		}
		case blake2s_184.code():
		{
			CryptoPP::BLAKE2s bl2s(false, 184 / 8);
			bl2s.CalculateDigest(digest.data(), input.data(), input.size());
			break;
		}
		case blake2s_192.code():
		{
			CryptoPP::BLAKE2s bl2s(false, 192 / 8);
			bl2s.CalculateDigest(digest.data(), input.data(), input.size());
			break;
		}
		case blake2s_200.code():
		{
			CryptoPP::BLAKE2s bl2s(false, 200 / 8);
			bl2s.CalculateDigest(digest.data(), input.data(), input.size());
			break;
		}
		case blake2s_208.code():
		{
			CryptoPP::BLAKE2s bl2s(false, 208 / 8);
			bl2s.CalculateDigest(digest.data(), input.data(), input.size());
			break;
		}
		case blake2s_216.code():
		{
			CryptoPP::BLAKE2s bl2s(false, 216 / 8);
			bl2s.CalculateDigest(digest.data(), input.data(), input.size());
			break;
		}
		case blake2s_224.code():
		{
			CryptoPP::BLAKE2s bl2s(false, 224 / 8);
			bl2s.CalculateDigest(digest.data(), input.data(), input.size());
			break;
		}
		case blake2s_232.code():
		{
			CryptoPP::BLAKE2s bl2s(false, 232 / 8);
			bl2s.CalculateDigest(digest.data(), input.data(), input.size());
			break;
		}
		case blake2s_240.code():
		{
			CryptoPP::BLAKE2s bl2s(false, 240 / 8);
			bl2s.CalculateDigest(digest.data(), input.data(), input.size());
			break;
		}
		case blake2s_248.code():
		{
			CryptoPP::BLAKE2s bl2s(false, 248 / 8);
			bl2s.CalculateDigest(digest.data(), input.data(), input.size());
			break;
		}
		case blake2s_256.code():
		{
			CryptoPP::BLAKE2s bl2s(false, 256 / 8);
			bl2s.CalculateDigest(digest.data(), input.data(), input.size());
			break;
		}

		default:
			throw new std::invalid_argument("unknown hash function type");
	}

	digest.insert(digest.begin(), type.len());
	digest.insert(digest.begin(), type.code());
	
	return digest;
}


}
}