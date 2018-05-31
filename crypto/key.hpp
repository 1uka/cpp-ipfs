/**
 * @brief Private/Public key cryptographic utilities
 * 
 * @file key.hpp
 * @author Luka Atanasovski
 * @date 2018-05-23
 */
#pragma once


#include <common/types.hpp>

#include <cryptopp/cryptlib.h>
#include <cryptopp/osrng.h>
#include <cryptopp/oids.h>
#include <cryptopp/eccrypto.h>

#include "pb/crypto.pb.h"

#define SECP256K1 CryptoPP::ASN1::secp256k1()
#define ED25519 CryptoPP::ASN1::curve25519()

namespace crypto {


class Key
{
public:
	Key() = default;
	virtual ~Key() = 0;

	virtual bytes raw() const = 0;
};


class PubKey : public Key
{
public:
	PubKey() = default;
	virtual ~PubKey() = 0;
	
	virtual bool verify(const bytes&, const bytes&) const = 0;
	virtual bool verify(const std::string&, const std::string&) const = 0;

	virtual bytes encrypt(const bytes&) const = 0;
	virtual bytes encrypt(const std::string&) const = 0;
};

class PrivKey : public Key
{
public:
	PrivKey() = default;
	virtual ~PrivKey() = 0;

	virtual bytes sign(const std::string&) const = 0;
	virtual bytes sign(const bytes&) const = 0;
	virtual PubKey* get_public() const = 0;

	virtual bytes decrypt(const bytes&) const = 0;
	virtual bytes decrypt(const std::string&) const = 0;
};


using pubkey_unmarshaller 	= std::function<PubKey*(const bytes&)>;
using privkey_unmarshaller 	= std::function<PrivKey*(const bytes&)>;

// std::unordered_map<KeyType, pubkey_unmarshaller> pubkey_unmarshallers;
// std::unordered_map<KeyType, privkey_unmarshaller> privkey_unmarshallers;


PrivKey* GenerateKey(pb::KeyType, int);


}