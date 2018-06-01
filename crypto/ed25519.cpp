#include "ed25519.hpp"


namespace crypto {


Ed25519PrivateKey::Ed25519PrivateKey()
{
	CryptoPP::AutoSeededRandomPool rng;
	m_sk.Initialize(rng, ED25519_CURVE);
}

bytes Ed25519PrivateKey::raw() const
{
	bytes ms = marshal_ed25519_privkey(this);

	pb::PrivateKey pbmes;
	pbmes.set_type(pb::KeyType::Ed25519);
	pbmes.set_data(&ms[0], ms.size());
	std::string ser;
	if(!pbmes.SerializeToString(&ser))
	{
		return bytes();
	}

	return bytes(ser.begin(), ser.end());
}

bytes Ed25519PrivateKey::sign(const std::string& m) const
{
	CryptoPP::AutoSeededRandomPool rng;
	_ecdsa::Signer signer(this->m_sk);
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

bytes Ed25519PrivateKey::decrypt(const bytes& m) const
{
	CryptoPP::AutoSeededRandomPool rng;

	_ecies::Decryptor decryptor(this->m_sk);
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

bytes Ed25519PublicKey::raw() const
{
	bytes ms = marshal_ed25519_pubkey(this);

	pb::PrivateKey pbmes;
	pbmes.set_type(pb::KeyType::Ed25519);
	pbmes.set_data(&ms[0], ms.size());
	std::string ser;
	if(!pbmes.SerializeToString(&ser))
	{
		return bytes();
	}

	return bytes(ser.begin(), ser.end());
}

bool Ed25519PublicKey::verify(const std::string& m, const std::string& s) const
{
	_ecdsa::Verifier verifier(this->m_pk);
	return verifier.VerifyMessage(
		(const CryptoPP::byte*) m.c_str(),
		m.length(),
		(const CryptoPP::byte*) s.c_str(),
		s.length()
	);
}

bytes Ed25519PublicKey::encrypt(const bytes& m) const
{
	CryptoPP::AutoSeededRandomPool rng;
	_ecies::Encryptor encryptor(this->m_pk);
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

PrivKey* unmarshal_ed25519_privkey(const bytes& buf)
{
	CryptoPP::ArraySource src(&buf[0], buf.size(), true);
	_ecies::PrivateKey pk;
	pk.BERDecode(src);
	return new Ed25519PrivateKey(pk);
}

bytes marshal_ed25519_privkey(const Ed25519PrivateKey* k)
{
	bytes buf(8192);
	CryptoPP::ArraySink as(&buf[0], buf.size());
	k->key().DEREncode(as);
	return bytes(&buf[0], &buf[0] + as.TotalPutLength());
}

PubKey* unmarshal_ed25519_pubkey(const bytes& buf)
{
	CryptoPP::ArraySource src(&buf[0], buf.size(), true);
	_ecies::PrivateKey pk;
	pk.BERDecode(src);
	return new Ed25519PublicKey(pk);
}

bytes marshal_ed25519_pubkey(const Ed25519PublicKey* k)
{
	bytes buf(8192);
	CryptoPP::ArraySink as(&buf[0], buf.size());
	k->key().DEREncode(as);
	return bytes(&buf[0], &buf[0] + as.TotalPutLength());
}


}