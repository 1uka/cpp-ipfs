#include "rsa.hpp"


namespace crypto {

RsaPrivateKey::RsaPrivateKey(unsigned int bits)
{
	CryptoPP::AutoSeededRandomPool rng;
	CryptoPP::RSA::PrivateKey priv;

	priv.GenerateRandomWithKeySize(rng, bits);
	this->m_sk = priv;
}

bytes RsaPrivateKey::sign(const std::string& m) const
{
	CryptoPP::AutoSeededRandomPool rng;

	CryptoPP::RSASSA_PKCS1v15_SHA_Signer signer(this->m_sk);
	size_t len = signer.MaxSignatureLength();
	CryptoPP::SecByteBlock signature(len);
	len = signer.SignMessage(
		rng,
		(const CryptoPP::byte*) m.c_str(),
		m.length(),
		signature
	);

	signature.resize(len);
	return bytes(signature.begin(), signature.end());
}

bool RsaPublicKey::verify(const std::string& m, const std::string& s) const
{
	CryptoPP::RSASSA_PKCS1v15_SHA_Verifier verifier(this->m_pk);
	return verifier.VerifyMessage(
		(const CryptoPP::byte*) m.c_str(),
		m.length(),
		(const CryptoPP::byte*) s.c_str(),
		s.length()
	);
}

}