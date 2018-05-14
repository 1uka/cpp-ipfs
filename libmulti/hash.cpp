#include "hash.hpp"

namespace multi {
namespace hash {


bytes sum(const bytes& input, const Type& type)
{
  bytes digest(type.len());
  digest.insert(digest.begin(), type.len());
  digest.insert(digest.begin(), type.code());

  switch(type.code())
  {
    case sha1.code():
    {
      CryptoPP::SHA1 sha1;
      sha1.CalculateDigest(digest.data()+2, input.data(), input.size());
      break;
    }
    case sha2_256.code():
    {
      CryptoPP::SHA256 sha2;
      sha2.CalculateDigest(digest.data()+2, input.data(), input.size());
      break;
    }
    case sha2_512.code():
    {
      CryptoPP::SHA256 sha2;
      sha2.CalculateDigest(digest.data()+2, input.data(), input.size());
      break;
    }
    case sha3_224.code():
    {
      CryptoPP::SHA3_224 sha3;
      sha3.CalculateDigest(digest.data()+2, input.data(), input.size());
      break;
    }
    case sha3_256.code():
    {
      CryptoPP::SHA3_256 sha3;
      sha3.CalculateDigest(digest.data()+2, input.data(), input.size());
      break;
    }
    case sha3_384.code():
    {
      CryptoPP::SHA3_384 sha3;
      sha3.CalculateDigest(digest.data()+2, input.data(), input.size());
      break;
    }
    case sha3_512.code():
    {
      CryptoPP::SHA3_512 sha3;
      sha3.CalculateDigest(digest.data()+2, input.data(), input.size());
      break;
    }
    case keccak_224.code():
    {
      CryptoPP::Keccak_224 keccak;
      keccak.CalculateDigest(digest.data()+2, input.data(), input.size());
      break;
    }
    case keccak_256.code():
    {
      CryptoPP::Keccak_256 keccak;
      keccak.CalculateDigest(digest.data()+2, input.data(), input.size());
      break;
    }
    case keccak_384.code():
    {
      CryptoPP::Keccak_384 keccak;
      keccak.CalculateDigest(digest.data()+2, input.data(), input.size());
      break;
    }
    case keccak_512.code():
    {
      CryptoPP::Keccak_512 keccak;
      keccak.CalculateDigest(digest.data()+2, input.data(), input.size());
      break;
    }
    case blake2b_104.code():
    {
      CryptoPP::BLAKE2b bl2b(false, 104 / 8);
      bl2b.CalculateDigest(digest.data()+2, input.data(), input.size());
      break;
    }
    case blake2b_112.code():
    {
      CryptoPP::BLAKE2b bl2b(false, 112 / 8);
      bl2b.CalculateDigest(digest.data()+2, input.data(), input.size());
      break;
    }
    case blake2b_120.code():
    {
      CryptoPP::BLAKE2b bl2b(false, 120 / 8);
      bl2b.CalculateDigest(digest.data()+2, input.data(), input.size());
      break;
    }
    case blake2b_128.code():
    {
      CryptoPP::BLAKE2b bl2b(false, 128 / 8);
      bl2b.CalculateDigest(digest.data()+2, input.data(), input.size());
      break;
    }
    case blake2b_136.code():
    {
      CryptoPP::BLAKE2b bl2b(false, 136 / 8);
      bl2b.CalculateDigest(digest.data()+2, input.data(), input.size());
      break;
    }
    case blake2b_144.code():
    {
      CryptoPP::BLAKE2b bl2b(false, 144 / 8);
      bl2b.CalculateDigest(digest.data()+2, input.data(), input.size());
      break;
    }
    case blake2b_152.code():
    {
      CryptoPP::BLAKE2b bl2b(false, 152 / 8);
      bl2b.CalculateDigest(digest.data()+2, input.data(), input.size());
      break;
    }
    case blake2b_160.code():
    {
      CryptoPP::BLAKE2b bl2b(false, 160 / 8);
      bl2b.CalculateDigest(digest.data()+2, input.data(), input.size());
      break;
    }
    case blake2b_168.code():
    {
      CryptoPP::BLAKE2b bl2b(false, 168 / 8);
      bl2b.CalculateDigest(digest.data()+2, input.data(), input.size());
      break;
    }
    case blake2b_176.code():
    {
      CryptoPP::BLAKE2b bl2b(false, 176 / 8);
      bl2b.CalculateDigest(digest.data()+2, input.data(), input.size());
      break;
    }
    case blake2b_184.code():
    {
      CryptoPP::BLAKE2b bl2b(false, 184 / 8);
      bl2b.CalculateDigest(digest.data()+2, input.data(), input.size());
      break;
    }
    case blake2b_192.code():
    {
      CryptoPP::BLAKE2b bl2b(false, 192 / 8);
      bl2b.CalculateDigest(digest.data()+2, input.data(), input.size());
      break;
    }
    case blake2b_200.code():
    {
      CryptoPP::BLAKE2b bl2b(false, 200 / 8);
      bl2b.CalculateDigest(digest.data()+2, input.data(), input.size());
      break;
    }

    default:
      throw new std::invalid_argument("unknown hash function type");
  }
  
  return digest;
}

}
}