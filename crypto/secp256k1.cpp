#include "crypto/secp256k1.hpp"


namespace crypto {


Secp256k1PrivateKey::Secp256k1PrivateKey()
{
	CryptoPP::AutoSeededRandomPool rng;
	m_sk.Initialize(rng, SECP256K1);
}


bytes Secp256k1PrivateKey::sign(const std::string& m) const
{
	CryptoPP::AutoSeededRandomPool rng;
	__ecdsa_signer signer(this->m_sk);
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

bytes Secp256k1PrivateKey::decrypt(const bytes& m) const
{
	CryptoPP::AutoSeededRandomPool rng;
	CryptoPP::PK_Decryptor decryptor(this->m_sk); // FIXME: find dec object
	size_t dpl = decryptor.MaxPlaintextLength(m.size());
	CryptoPP::SecByteBlock pt(dpl);
	
	CryptoPP::DecodingResult res = decryptor.Decrypt(
		rng,
		(const CryptoPP::byte*) m.data(),
		m.size(),
		pt
	);

	assert(res.isValidCoding);
	assert(res.messageLength <= decryptor.MaxPlaintextLength(m.size()));

	pt.resize(res.messageLength);

	return bytes(pt.begin(), pt.end());
}



}