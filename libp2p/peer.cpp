#include "peer.hpp"

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


void PeerSet::add(const ID& id)
{
	set_lock.lock();
	m_set.insert(id);
	set_lock.unlock();
}

bool PeerSet::try_add(const ID& id)
{
	set_lock.lock();
	if(m_set.size() >= m_cap && m_set.count(id))
	{
		return false;
	}
	m_set.insert(id);
	return true;
}

bool PeerSet::contains(const ID& id)
{
	set_lock.lock();
	bool _containts = m_set.count(id) > 0;
	set_lock.unlock();
	return _containts;
}

size_t PeerSet::size()
{
	set_lock.lock();
	size_t _size = m_set.size();
	set_lock.unlock();
	return _size;
}

std::vector<ID> PeerSet::peers()
{
	set_lock.lock();
	std::vector<ID> ret(m_set.size());
	
	for(auto&& id : m_set)
	{
		ret.push_back(id);
	}
	set_lock.unlock();
	return ret;
}

}