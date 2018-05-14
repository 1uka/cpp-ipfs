#include <common/types.hpp>
#include <libmulti/hash.hpp>
#include <libmulti/base.hpp>
#include <iostream>

/* driver */
int main()
{
  std::string enc = "NR2WWYJAMUQGIZLGNFXGS5DJOZXG6IDOMFVGUYLL";
  std::cout << "Base32 encoded: " 
            << enc << std::endl;
  
  bytes dec = multi::base::Endec<multi::base::Type::Base32>().decode(enc);
  enc = std::string(dec.begin(), dec.end());
  std::cout << "Decoded: "
            << enc << std::endl;

  enc = multi::base::encode(multi::base::Type::Base64, dec);
  std::cout << "Base64 encoded: "
            << enc << std::endl;

  dec = multi::base::decode(enc);

  enc = multi::base::encode(multi::base::Type::Base16, dec);
  std::cout << "Encoded in Base16 (hex): "
            << enc << std::endl;

  dec = multi::base::decode(enc);
  enc = std::string(dec.begin(), dec.end());
  std::cout << "Aaaand back from Base16: "
            << enc << std::endl;

  enc = multi::base::encode(multi::base::Type::Base58BTC, dec);
  std::cout << "Now for base58, encoded is:"
            << enc << std::endl;

  dec = multi::base::decode(enc);
  std::cout << "Decoded back: "
            << std::string(dec.begin(), dec.end()) << std::endl; 
  dec = multi::hash::sum(dec);
  std::cout << "Hashed: "
            << multi::base::encode(multi::base::Base58BTC, dec) << std::endl;
  return 0;
}