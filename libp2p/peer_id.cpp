#include "peer_id.hpp"

#include <libmulti/hash.hpp>


namespace libp2p {


ID::ID(const crypto::PubKey* pub)
{
	bytes b = pub->raw();
	delete pub;
	bytes hash;
	hash = multi::hash::sum(b);
	// if(b.size() < MAX_INLINE_KEY_LEN)
	// {
	// } else
	// {
	// 	hash = multi::hash::sum(b, multi::hash::ID);
	// } FIXME: this should be somewhat different

	m_str = std::string(hash.begin(), hash.end());
}


crypto::PubKey* ID::extract_pubkey() const
{
	crypto::PubKey* pk = crypto::unmarshal_pubkey(multi::hash::Decoded(m_str).hash());
	return pk;
}

bool ID::matches_pubkey(const crypto::PubKey* pk)
{
	ID oid(pk);
	return oid.m_str == this->m_str;
}

}