#pragma once


#include "key.hpp"


namespace crypto {

using __ecdsa_priv 	= CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::PrivateKey;
using __ecdsa_pub		= CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::PublicKey;

using __ecdsa_signer 		= CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::Signer;
using __ecdsa_verifier 	= CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::Verifier;

class Secp256k1PublicKey : public PubKey
{
public:
	~Secp256k1PublicKey() = default;

	inline explicit Secp256k1PublicKey(const __ecdsa_priv& _sk)
	{
		_sk.MakePublicKey(m_pk);
	}

	inline bytes raw() const { return bytes(); }; // TODO: fo real

	bool verify(const std::string&, const std::string&) const;
	inline bool verify(const bytes& m, const bytes& s) const
	{
		return verify(std::string(m.begin(), m.end()), std::string(s.begin(), s.end()));
	}

	bytes encrypt(const bytes&) const;
	inline bytes encrypt(const std::string& m) const { return encrypt(bytes(m.begin(), m.end())); }

private:
	__ecdsa_pub m_pk;
};

class Secp256k1PrivateKey : public PrivKey
{
public:
	~Secp256k1PrivateKey() = default;

	explicit Secp256k1PrivateKey();

	inline bytes raw() const { return bytes(); } // TODO: fo real
	inline PubKey* get_public() const { return new Secp256k1PublicKey(m_sk); }

	bytes sign(const std::string&) const;
	inline bytes sign(const bytes& m) const { return sign(std::string(m.begin(), m.end())); }

	bytes decrypt(const bytes&) const;
	inline bytes decrypt(const std::string& m) const { return decrypt(bytes(m.begin(), m.end())); }

private:
	__ecdsa_priv m_sk;
};



}