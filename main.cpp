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
	try
	{
		dec = multi::hash::sum(dec);
	} catch(std::invalid_argument e)
	{
		std::cout << e.exception::what() << std::endl;
		return -1;
	}
	
	std::cout << "Multihash length: " << dec.size() << std::endl;
	std::cout << "Hashed: "
						<< multi::base::encode(multi::base::Base58BTC, dec) << std::endl;

	multi::hash::Decoded d = multi::hash::decode(dec);
	std::cout << "Hash type: " << d.code() << std::endl;
	std::cout << "Hash len: " << d.len() << std::endl;
	std::cout << "Hash without prefix: " << multi::base::encode(multi::base::Base58BTC, bytes(d.hash(), d.hash() + d.len())) << std::endl;
	return 0;
}
