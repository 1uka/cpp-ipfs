#pragma once


#include "key.hpp"


namespace crypto {

#ifndef ECC_ALGORITHM
#define ECC_ALGORITHM CryptoPP::ECP
#endif // !ECC_ALGORITHM

#ifndef SECP256K1_CURVE
#define SECP256K1_CURVE CryptoPP::ASN1::secp256k1()
#endif // !SECP256K1_CURVE

using _ecies = CryptoPP::ECIES<ECC_ALGORITHM>;
using _ecdsa = CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>;

class Secp256k1PublicKey;
class Secp256k1PrivateKey;

PrivKey* unmarshal_secp256k1_privkey(const bytes&);
bytes marshal_secp256k1_privkey(const Secp256k1PrivateKey*);

PubKey* unmarshal_secp256k1_pubkey(const bytes&);
bytes marshal_secp256k1_pubkey(const Secp256k1PublicKey*);


class Secp256k1PublicKey : public PubKey
{
public:
	~Secp256k1PublicKey() = default;

	inline explicit Secp256k1PublicKey(const _ecies::PrivateKey& _sk)
	{
		_sk.MakePublicKey(m_pk);
	}
	explicit Secp256k1PublicKey(const _ecies::PublicKey& _pk) : m_pk(_pk) {};

	inline PubKey* clone() const { return new Secp256k1PublicKey(*this); }
	bytes raw() const;

	bool verify(const std::string&, const std::string&) const;
	inline bool verify(const bytes& m, const bytes& s) const
	{
		return verify(std::string(m.begin(), m.end()), std::string(s.begin(), s.end()));
	}

	bytes encrypt(const bytes&) const;
	inline bytes encrypt(const std::string& m) const { return encrypt(bytes(m.begin(), m.end())); }

	inline const _ecies::PublicKey& key() const { return m_pk; }

private:
	_ecies::PublicKey m_pk;
};

class Secp256k1PrivateKey : public PrivKey
{
public:
	~Secp256k1PrivateKey() = default;

	explicit Secp256k1PrivateKey();

	explicit Secp256k1PrivateKey(const _ecies::PrivateKey& _sk) : m_sk(_sk) {};

	inline PrivKey* clone() const { return new Secp256k1PrivateKey(*this); }
	bytes raw() const;

	inline PubKey* get_public() const { return new Secp256k1PublicKey(m_sk); }

	bytes sign(const std::string&) const;
	inline bytes sign(const bytes& m) const { return sign(std::string(m.begin(), m.end())); }

	bytes decrypt(const bytes&) const;
	inline bytes decrypt(const std::string& m) const { return decrypt(bytes(m.begin(), m.end())); }

	inline const _ecies::PrivateKey& key() const { return m_sk; }

private:
	_ecies::PrivateKey m_sk;
};



}