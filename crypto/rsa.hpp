#pragma once


#include "key.hpp"
#include <cryptopp/rsa.h>


namespace crypto {


class RsaPublicKey : public PubKey
{
public:
	RsaPublicKey() = default;
	~RsaPublicKey() = default;

	explicit RsaPublicKey(const CryptoPP::RSA::PrivateKey& _sk) : m_pk(_sk) {};

	inline bytes raw() const { return bytes(); }; // TODO: fo real

	bool verify(const std::string&, const std::string&) const;
	inline bool verify(const bytes& m, const bytes& s) const
	{
		return verify(std::string(m.begin(), m.end()), std::string(s.begin(), s.end()));
	}

private:
	CryptoPP::RSA::PublicKey m_pk;
};

class RsaPrivateKey : public PrivKey
{
public:
	RsaPrivateKey() = default;
	~RsaPrivateKey() = default;

	explicit RsaPrivateKey(unsigned int);
	
	inline bytes raw() const { return bytes(); } // TODO: fo real
	inline PubKey* get_public() const { return new RsaPublicKey(m_sk); }
	
	bytes sign(const std::string&) const;
	inline bytes sign(const bytes& m) const { return sign(std::string(m.begin(), m.end())); }

private:
	CryptoPP::RSA::PrivateKey m_sk;
};


}