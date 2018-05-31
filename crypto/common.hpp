#pragma once


#include "rsa.hpp"
#include "secp256k1.hpp"
#include "ed25519.hpp"

namespace crypto {


using pubkey_unmarshaller 	= std::function<PubKey*(const bytes&)>;
using privkey_unmarshaller 	= std::function<PrivKey*(const bytes&)>;

static std::unordered_map<pb::KeyType, pubkey_unmarshaller> pubkey_unmarshallers = {
	{pb::KeyType::RSA, unmarshal_rsa_pubkey},
	{pb::KeyType::Secp256k1, unmarshal_secp256k1_pubkey},
	{pb::KeyType::Ed25519, unmarshal_ed25519_pubkey}
};

static std::unordered_map<pb::KeyType, privkey_unmarshaller> privkey_unmarshallers = {
	{pb::KeyType::RSA, unmarshal_rsa_privkey},
	{pb::KeyType::Secp256k1, unmarshal_secp256k1_privkey},
	{pb::KeyType::Ed25519, unmarshal_ed25519_privkey}
};


}