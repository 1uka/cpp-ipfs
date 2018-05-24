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

#define SECP256K1 CryptoPP::ASN1::secp256k1()
#define ED25519 CryptoPP::ASN1::curve25519()

namespace crypto {

enum KeyType
{
	KEY_SECP256K1 = 0,
	KEY_ED25519,
	KEY_RSA,
};


class Key
{
public:
	Key() = default;
	virtual ~Key() = default;

	virtual bytes raw() const;
};


class PubKey : virtual public Key
{
public:
	virtual bool verify(const bytes&, const bytes&);
};

class PrivKey : virtual public Key
{
public:
	virtual bytes sign(const bytes&) const;
	virtual PubKey get_public() const;
};


PrivKey GenerateKey(KeyType, int);


}