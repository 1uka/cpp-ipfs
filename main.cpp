#include <common/channel.hpp>

#include <libmulti/codec.hpp>
#include <libmulti/addr.hpp>
#include <libmulti/stream.hpp>

#include <crypto/common.hpp>

#include <iostream>
#include <chrono>

#include <boost/algorithm/string.hpp>


void test_crypto()
{
	crypto::PrivKey* pk = crypto::GenerateKey(crypto::pb::RSA, 1024);

	std::string m = "jas sum luka atanasovski";
	bytes hash(multi::hash::sha1.len());
	CryptoPP::SHA256().CalculateDigest(hash.data(), (const CryptoPP::byte*) m.data(), m.length());

	bytes signature = pk->sign(hash);
	
	crypto::PubKey* pub = pk->get_public();

	if(pub->verify(hash, signature))
	{
		std::cout << "Signature schemes work" << std::endl;
	} else 
	{
		std::cout << "Fixthedamnsignatureschemes" << std::endl;
	}

	bytes ct = pub->encrypt(m);
	bytes pt = pk->decrypt(ct);
	std::string dec(pt.begin(), pt.end());
	if(dec == m)
	{
		std::cout << "Encrypt/decrypt works" << std::endl;
	} else
	{
		std::cout << "fix enc/dec" << std::endl;
	}
	delete pk;
	delete pub;
}

void test_multiaddr()
{
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
}

void test_proto_negotiation()
{
	chan_t<int> done;
	std::stringbuf* buf = new std::stringbuf();
	std::iostream* rw = new std::iostream(buf);
	multi::stream::Muxer* mux = new multi::stream::Muxer();
	mux->add_handler("/a", NULL);
	mux->add_handler("/b", NULL);
	mux->add_handler("/c", NULL);
	std::string ret;
	std::thread([&]{
		try
		{
			mux->negotiate(*rw, ret);
		} catch(const Exception& e)
		{
			std::cout << e.what() << std::endl;
			return;
		}
		if(ret != "/a")
		{
			std::cout << "incorrect proto: " << ret << std::endl;
		}
		done.close();
	}).detach();
	int sink;
	try
	{
		multi::stream::select_proto_or_fail("/a", *rw);
	} catch(const Exception& e)
	{
		std::cout << e.what() << std::endl;
		delete buf;
		delete rw;
		delete mux;
		return;
	}

	if(done.pop_wait_for(sink, std::chrono::seconds(1)) == boost::fibers::channel_op_status::timeout)
	{
		std::cout << "negotiation didnt complete in time" << std::endl;
		delete buf;
		delete rw;
		delete mux;
		return;
	}

	std::cout << "success!" << std::endl;
	delete buf;
	delete rw;
	delete mux;
}

/* driver */
int main()
{	
	test_multiaddr();
	test_proto_negotiation();
	test_crypto();
}
