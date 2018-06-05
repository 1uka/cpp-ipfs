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

    virtual PubKey* clone() const = 0;
    
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

    virtual PrivKey* clone() const = 0;

    virtual bytes sign(const std::string&) const = 0;
    virtual bytes sign(const bytes&) const = 0;
    virtual PubKey* get_public() const = 0;

    virtual bytes decrypt(const bytes&) const = 0;
    virtual bytes decrypt(const std::string&) const = 0;
};

PrivKey* GenerateKey(pb::KeyType t, int bits = 0);

PubKey* unmarshal_pubkey(const bytes&);
PrivKey* unmarshal_privkey(const bytes&);

inline bytes marshal_pubkey(const PubKey* k) { return (k != NULL ? k->raw() : bytes()); }
inline bytes marshal_privkey(const PrivKey* k) { return (k != NULL ? k->raw() : bytes()); }


}