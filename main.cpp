#include <common/types.hpp>
#include <crypto/key.hpp>

#include <libmulti/hash.hpp>
#include <libmulti/base.hpp>
#include <libmulti/codec.hpp>
#include <libmulti/addr.hpp>
#include <libmulti/stream.hpp>
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

	try
	{
		// std::string addr = "/ipfs/QmYwAPJzv5CZsnA625s3Xf2nemtYgPpHdWEz79ojWnPbdG";
		std::string addr = "/ip4/0.0.0.0/tcp/1221";
		multi::Addr* ma = new multi::Addr(addr);
		std::cout << "To string: " << ma->string() << std::endl;
		std::cout << "Value for ip4: " << ma->value_for_proto(multi::addr::protocodes::P_IP4) << std::endl;
		std::cout << "Value for tcp: " << ma->value_for_proto(multi::addr::protocodes::P_TCP) << std::endl;
		multi::Addr* ma2 = new multi::Addr(addr);
		if(*ma == *ma2)
		{
			std::cout << "EQUAL" << std::endl;
		} else {
			std::cout << "MA: " << ma->string() << std::endl;
			std::cout << "MA2: " << ma2->string() << std::endl;
		}
		multi::Addr decaps = ma->decapsulate("/tcp/1221");
		std::cout << "Decapsulated: " << decaps.string() << std::endl;
		delete ma2;
		delete ma;
	} catch(const Exception& e)
	{
		std::cout << e.what() << std::endl;
	}

	std::cout << "Initiating ostream test" << std::endl;

	std::stringbuf* buf = new std::stringbuf();
	std::iostream* rw = new std::iostream(buf);
	multi::Stream* ms;
	multi::stream::Muxer mx;
	mx.add_handler("handleme", [](const std::string& s, std::iostream& is) -> void{
		std::cout << "im handled\n"; 
	});
	try
	{
		std::string m = "/multistream/1.0.0";
		std::string m2 = "handleme";

		multi::stream::delim_write(*rw, bytes(m2.begin(), m2.end()));
		multi::stream::delim_write(*rw, bytes(m.begin(), m.end()));

		ms = mx.negotiate_lazy(*rw);
	} catch(const Exception& e)
	{
		std::cout << e.what() << std::endl;
		delete buf;
		delete rw;
		rw->clear();
		return -1;
	}
	ms->read(dec);
	std::cout << "from multistream: " << std::string(dec.begin(), dec.end()) << std::endl;
	delete buf;
	delete ms;
	delete rw;
	return 0;
}
