#include <common/channel.hpp>

#include <libmulti/codec.hpp>
#include <libmulti/addr.hpp>
#include <libmulti/stream.hpp>

#include <libcrypto/common.hpp>

#include <libp2p/peerstore.hpp>

#include <iostream>
#include <chrono>

#include <boost/algorithm/string.hpp>


void test_key_functions(const crypto::PrivKey* k)
{
    std::string m = "jas sum luka atanasovski";
    bytes hash(multi::hash::sha2_256.len());
    CryptoPP::SHA256().CalculateDigest(hash.data(), (const CryptoPP::byte*) m.data(), m.length());
    bytes signature = k->sign(hash);
    crypto::PubKey* pub = k->get_public();
    if(pub->verify(hash, signature))
    {
        std::cout << "Signature schemes work" << std::endl;
    } else 
    {
        std::cout << "Fixthedamnsignatureschemes" << std::endl;
    }
    bytes ct = pub->encrypt(m);
    bytes pt = k->decrypt(ct);
    std::string dec(pt.begin(), pt.end());
    if(dec == m)
    {
        std::cout << "Encrypt/decrypt works" << std::endl;
    } else
    {
        std::cout << "fix enc/dec" << std::endl;
    }

    // crypto::PrivKey* unm = crypto::unmarshal_privkey(k->raw());
    // if(unm == NULL || unm->raw() != k->raw())
    // {
    // 	std::cout << "unmarshaling does not work" << std::endl;
    // }

    // if(unm != NULL) delete unm;

    delete pub;
    std::cout << "KEY TEST DONE" << std::endl;
}

void test_crypto()
{
    crypto::PrivKey* k = crypto::GenerateKey(crypto::pb::KeyType::RSA, 2048);
    std::cout << "TESTING RSA" << std::endl;
    test_key_functions(k);
    delete k;

    k = crypto::GenerateKey(crypto::pb::KeyType::Secp256k1);
    std::cout << "TESTING SECP256K1" << std::endl;
    test_key_functions(k);
    delete k;

    // curve25519 is still not fully supported by crypto++
    // k = crypto::GenerateKey(crypto::pb::KeyType::Ed25519);
    // std::cout << "TESTING ED25519" << std::endl;
    // test_key_functions(k);
    // delete k;
}


void test_peerid()
{
    crypto::PrivKey* k = crypto::GenerateKey(crypto::pb::KeyType::Secp256k1);
    crypto::PubKey* pub = k->get_public();

    libp2p::ID id(k);
    if(!id.matches_pubkey(pub))
    {
        std::cout << "ID does not match public key" << std::endl;
    }
    crypto::PubKey* extracted = id.extract_pubkey();
    if(extracted == NULL)
    {
        std::cout << "Failed extracting public key" << std::endl;
        delete pub;
        delete k;
        return;
    }
    std::cout << "Derived from private: " << multi::base::encode(pub->raw()) << std::endl;
    std::cout << "Extracted form id: " << multi::base::encode(extracted->raw()) << std::endl;

    delete pub;
    delete extracted;
    delete k;
}

void test_peerinfo()
{
    std::string addr = "/ip4/0.0.0.0/ipfs/QmYwAPJzv5CZsnA625s3Xf2nemtYgPpHdWEz79ojWnPbdG";
    multi::Addr* ma = new multi::Addr(addr);
    
    libp2p::PeerInfo* pi;
    try
    {
        pi = new libp2p::PeerInfo(*ma);
        std::cout << "PeerInfo id:" << pi->m_id.pretty() << std::endl;
        std::vector<multi::Addr> p2paddrs = pi->p2p_addrs();
        std::cout << "P2P Addrs: " << std::endl;
        for(auto&& a : p2paddrs)
        {
            std::cout << a.string() << std::endl;
        }
        std::string marsh = pi->marshal_json();
        std::cout << "Marshaled: " << marsh << std::endl;
        pi->unmarshal_json(marsh);
        std::cout << "PeerInfo (unmarshalled) id:" << pi->m_id.pretty() << std::endl;
    } catch(Exception& e)
    {
        std::cout << e.what() << std::endl;
        delete ma;
        return;
    }
    delete ma;
    delete pi;
}


void test_multiaddr()
{
    try
    {
        std::string addr = "/ip4/0.0.0.0/ipfs/QmYwAPJzv5CZsnA625s3Xf2nemtYgPpHdWEz79ojWnPbdG";
        multi::Addr* ma = new multi::Addr(addr);
        std::vector<multi::addr::protocol> protos = ma->protocols();
        std::cout << "To string: " << ma->string() << std::endl;
        std::cout << "Protocols: " << std::endl;
        for(auto&& p : protos)
        {
            std::cout << p.m_name << std::endl;
        }
        std::cout << "Value for ip4: " << ma->value_for_proto(multi::addr::protocodes::P_IP4) << std::endl;
        std::cout << "Value for ipfs: " << ma->value_for_proto(multi::addr::protocodes::P_IPFS) << std::endl;
        multi::Addr* ma2 = new multi::Addr(addr);
        if(*ma == *ma2)
        {
            std::cout << "EQUAL" << std::endl;
        } else {
            std::cout << "MA: " << ma->string() << std::endl;
            std::cout << "MA2: " << ma2->string() << std::endl;
        }
        multi::Addr decaps = ma->decapsulate("/ipfs/QmYwAPJzv5CZsnA625s3Xf2nemtYgPpHdWEz79ojWnPbdG");
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
    test_peerid();
    test_peerinfo();
}
