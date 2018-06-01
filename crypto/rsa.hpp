#pragma once


#include "key.hpp"
#include <cryptopp/rsa.h>


namespace crypto {

class RsaPublicKey;
class RsaPrivateKey;

PrivKey* unmarshal_rsa_privkey(const bytes&);
bytes marshal_rsa_privkey(const RsaPrivateKey*);
PubKey* unmarshal_rsa_pubkey(const bytes&);
bytes marshal_rsa_pubkey(const RsaPublicKey*);


class RsaPublicKey : public PubKey
{
public:
	RsaPublicKey() = default;
	~RsaPublicKey() = default;

	explicit RsaPublicKey(const CryptoPP::RSA::PublicKey& _pk) : m_pk(_pk) {};
	explicit RsaPublicKey(const CryptoPP::RSA::PrivateKey& _sk) : m_pk(_sk) {};

	bytes raw() const;

	bool verify(const std::string&, const std::string&) const;
	inline bool verify(const bytes& m, const bytes& s) const
	{
		return verify(std::string(m.begin(), m.end()), std::string(s.begin(), s.end()));
	}

	bytes encrypt(const bytes&) const;
	inline bytes encrypt(const std::string& m) const { return encrypt(bytes(m.begin(), m.end())); }

	inline const CryptoPP::RSA::PublicKey& key() const { return m_pk; }

	// friend inline bool operator==(const RsaPublicKey& l, const RsaPublicKey& r) { return l.m_pk == r.m_pk; }

private:
	CryptoPP::RSA::PublicKey m_pk;
};

class RsaPrivateKey : public PrivKey
{
public:
	RsaPrivateKey() = default;
	~RsaPrivateKey() = default;

	explicit RsaPrivateKey(unsigned int);
	
	explicit RsaPrivateKey(const CryptoPP::RSA::PrivateKey& _sk) : m_sk(_sk) {};
	
	bytes raw() const;
	inline PubKey* get_public() const { return new RsaPublicKey(m_sk); }
	
	bytes sign(const std::string&) const;
	inline bytes sign(const bytes& m) const { return sign(std::string(m.begin(), m.end())); }

	bytes decrypt(const bytes&) const;
	inline bytes decrypt(const std::string& m) const { return decrypt(bytes(m.begin(), m.end())); }

	inline const CryptoPP::RSA::PrivateKey& key() const { return m_sk; }

	// friend inline bool operator==(const RsaPrivateKey& l, const RsaPrivateKey& r) { return l.m_sk == r.m_sk; }

private:
	CryptoPP::RSA::PrivateKey m_sk;
};


}