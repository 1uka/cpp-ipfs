#include "key.hpp"
#include "common.hpp"

namespace crypto {

Key::~Key() {}
PubKey::~PubKey() {}
PrivKey::~PrivKey() {}

PrivKey* GenerateKey(pb::KeyType t, int bits)
{
	switch(t)
	{
		case pb::KeyType::RSA:
			return new RsaPrivateKey(bits);
		case pb::KeyType::Secp256k1:
			return new Secp256k1PrivateKey();
		case pb::KeyType::Ed25519:
			return new Ed25519PrivateKey();
		default:
			return NULL;
	}
}

PubKey* unmarshal_pubkey(const bytes& buf)
{
	pb::PublicKey* pmes = new pb::PublicKey();
	if(!pmes->ParseFromArray(&buf[0], buf.size()))
	{
		return NULL;
	}
	if(pubkey_unmarshallers.count(pmes->type()))
	{
		pubkey_unmarshaller um = pubkey_unmarshallers[pmes->type()];
		const std::string& data = pmes->data();
		return um(bytes(data.begin(), data.end()));
	}
	return NULL;
}

PrivKey* unmarshal_privkey(const bytes& buf)
{
	pb::PublicKey* pmes = new pb::PublicKey();
	if(!pmes->ParseFromArray(&buf[0], buf.size()))
	{
		return NULL;
	}
	if(pubkey_unmarshallers.count(pmes->type()))
	{
		privkey_unmarshaller um = privkey_unmarshallers[pmes->type()];
		const std::string& data = pmes->data();
		return um(bytes(data.begin(), data.end()));
	}
	return NULL;
}



}