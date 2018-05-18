#include <common/types.hpp>
#include <libmulti/hash.hpp>
#include <libmulti/base.hpp>
#include <libmulti/codec.hpp>
#include <iostream>


/* driver */
int main()
{
	std::string enc = "bNR2WWYJAMUQGIZLGNFXGS5DJOZXG6IDOMFVGUYLL";
	std::cout << "Base32 encoded: " 
						<< enc << std::endl;
	
	bytes dec = multi::base::decode(enc);
	enc = std::string(dec.begin(), dec.end());
	std::cout << "Decoded: "
						<< enc << std::endl;

	enc = multi::base::encode(dec, multi::base::b64);
	std::cout << "Base64 encoded: "
						<< enc << std::endl;

	dec = multi::base::decode(enc);

	enc = multi::base::encode(dec, multi::base::b16);
	std::cout << "Encoded in Base16 (hex): "
						<< enc << std::endl;

	dec = multi::base::decode(enc);
	enc = std::string(dec.begin(), dec.end());
	std::cout << "Aaaand back from Base16: "
						<< enc << std::endl;

	enc = multi::base::encode(dec);
	std::cout << "Now for base58, encoded is:"
						<< enc << std::endl;

	dec = multi::base::decode(enc);
	std::cout << "Decoded back: "
						<< std::string(dec.begin(), dec.end()) << std::endl;
	try
	{
		dec = multi::hash::sum(dec);
	} catch(const Exception& e)
	{
		std::cout << e.what() << std::endl;
		return -1;
	}
	
	std::cout << "Multihash length: " << dec.size() << std::endl;
	std::cout << "Hashed: "
						<< multi::base::encode(dec) << std::endl;

	multi::hash::Decoded d = multi::hash::decode(dec);
	bytes with_codec = d.hash();
	multi::codec::add_prefix(with_codec, multi::codec::sha2_256);
	std::cout << "Hash type: " << d.code() << std::endl;
	std::cout << "Hash len: " << d.len() << std::endl;
	std::cout << "Hash (without prefix): " << multi::base::encode(d.hash()) << std::endl;
	std::cout << "Hash (with codec prefix): " << multi::base::encode(with_codec) << std::endl;
	std::cout << "Extracted prefix: " << multi::codec::extract_prefix(with_codec) << std::endl;
	return 0;
}
