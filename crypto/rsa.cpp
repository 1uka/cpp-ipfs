#include "rsa.hpp"


namespace crypto {


RsaPrivateKey::RsaPrivateKey(unsigned int bits)
{
	CryptoPP::AutoSeededRandomPool rng;
	this->m_sk.GenerateRandomWithKeySize(rng, bits);
}

bytes RsaPrivateKey::raw() const
{
	bytes ms = marshal_rsa_privkey(this);

	pb::PrivateKey pbmes;
	pbmes.set_type(pb::KeyType::RSA);
	pbmes.set_data(&ms[0], ms.size());
	std::string ser;
	if(!pbmes.SerializeToString(&ser))
	{
		return bytes();
	}

	return bytes(ser.begin(), ser.end());
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

bytes RsaPrivateKey::decrypt(const bytes& m) const
{
	CryptoPP::AutoSeededRandomPool rng;
	CryptoPP::RSAES_PKCS1v15_Decryptor decryptor(this->m_sk);
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

bytes RsaPublicKey::raw() const
{
	bytes ms = marshal_rsa_pubkey(this);

	pb::PrivateKey pbmes;
	pbmes.set_type(pb::KeyType::RSA);
	pbmes.set_data(&ms[0], ms.size());
	std::string ser;
	if(!pbmes.SerializeToString(&ser))
	{
		return bytes();
	}

	return bytes(ser.begin(), ser.end());
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

bytes RsaPublicKey::encrypt(const bytes& m) const
{
	CryptoPP::AutoSeededRandomPool rng;
	CryptoPP::RSAES_PKCS1v15_Encryptor encryptor(this->m_pk);
	size_t ecl = encryptor.CiphertextLength(m.size());
	CryptoPP::SecByteBlock ct(ecl);

	encryptor.Encrypt(
		rng,
		(const CryptoPP::byte*) m.data(),
		m.size(),
		ct
	);

	return bytes(ct.begin(), ct.end());
}

PrivKey* unmarshal_rsa_privkey(const bytes& buf)
{
	CryptoPP::ArraySource src(&buf[0], buf.size(), true);
	CryptoPP::RSA::PrivateKey pk;
	pk.BERDecode(src);
	return new RsaPrivateKey(pk);
}

bytes marshal_rsa_privkey(const RsaPrivateKey* k)
{
	bytes buf(8192);
	CryptoPP::ArraySink as(&buf[0], buf.size());
	k->key().DEREncode(as);
	return bytes(&buf[0], &buf[0] + as.TotalPutLength());
}

PubKey* unmarshal_rsa_pubkey(const bytes& buf)
{
	CryptoPP::ArraySource src(&buf[0], buf.size(), true);
	CryptoPP::RSA::PublicKey pk;
	pk.BERDecode(src);
	return new RsaPublicKey(pk);
}

bytes marshal_rsa_pubkey(const RsaPublicKey* k)
{
	bytes buf(8192);
	CryptoPP::ArraySink as(&buf[0], buf.size());
	k->key().DEREncode(as);
	return bytes(&buf[0], &buf[0] + as.TotalPutLength());
}

}