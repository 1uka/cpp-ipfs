#pragma once


#include "key.hpp"


namespace crypto {

#ifndef ECC_ALGORITHM
#define ECC_ALGORITHM CryptoPP::ECP
#endif // !ECC_ALGORITHM

#ifndef ED25519_CURVE
#define ED25519_CURVE CryptoPP::ASN1::curve25519()
#endif // !Ed25519_CURVE

using _ecies = CryptoPP::ECIES<ECC_ALGORITHM>;
using _ecdsa = CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>;

class Ed25519PublicKey : public PubKey
{
public:
	~Ed25519PublicKey() = default;

	inline explicit Ed25519PublicKey(const _ecies::PrivateKey& _sk)
	{
		_sk.MakePublicKey(m_pk);
	}
	explicit Ed25519PublicKey(const _ecies::PublicKey& _pk) : m_pk(_pk) {};

	inline bytes raw() const { return bytes(); }; // TODO: fo real

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

class Ed25519PrivateKey : public PrivKey
{
public:
	~Ed25519PrivateKey() = default;

	explicit Ed25519PrivateKey();

	explicit Ed25519PrivateKey(const _ecies::PrivateKey& _sk) : m_sk(_sk) {};

	inline bytes raw() const { return bytes(); } // TODO: fo real
	inline PubKey* get_public() const { return new Ed25519PublicKey(m_sk); }

	bytes sign(const std::string&) const;
	inline bytes sign(const bytes& m) const { return sign(std::string(m.begin(), m.end())); }

	bytes decrypt(const bytes&) const;
	inline bytes decrypt(const std::string& m) const { return decrypt(bytes(m.begin(), m.end())); }

	inline const _ecies::PrivateKey& key() const { return m_sk; }

private:
	_ecies::PrivateKey m_sk;
};


PrivKey* unmarshal_ed25519_privkey(const bytes&);
bytes marshal_Ed25519_privkey(const Ed25519PrivateKey*);

PubKey* unmarshal_ed25519_pubkey(const bytes&);
bytes marshal_ed25519_pubkey(const Ed25519PublicKey*);


}