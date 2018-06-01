#include "peer_id.hpp"

#include <libmulti/hash.hpp>


namespace libp2p {

std::string pubkey_to_idstr(const crypto::PubKey* pub)
{
	bytes b = pub->raw();
	bytes hash;
	if(b.size() < MAX_INLINE_KEY_LEN)
	{
		hash = multi::hash::sum(b);
	} else
	{
		hash = multi::hash::sum(b, multi::hash::ID);
	}

	return std::string(hash.begin(), hash.end());
}

ID::ID(const crypto::PrivKey* _k)
{
	const crypto::PubKey* pub = _k->get_public();
	m_str = pubkey_to_idstr(pub);
	delete pub;
}


crypto::PubKey* ID::extract_pubkey() const
{
	try
	{
		crypto::PubKey* pk = crypto::unmarshal_pubkey(multi::hash::Decoded(m_str).hash());
		return pk;
	} catch(CryptoPP::BERDecodeErr& e)
	{
		return NULL;
	}
}

bool ID::matches_pubkey(const crypto::PubKey* pk)
{
	ID oid(pk);
	return oid.m_str == this->m_str;
}

}