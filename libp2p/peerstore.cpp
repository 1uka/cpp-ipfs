#include "peerstore.hpp"

#include <nlohmann/json.hpp>

#include <boost/algorithm/string.hpp>

namespace libp2p {


PeerInfo::PeerInfo(const multi::Addr& _maddr)
{
	std::vector<multi::Addr> parts = _maddr.split();
	if(parts.size() < 1)
	{
		throw INVALID_MADDR;
	}
	
	multi::Addr ipfs_part = parts.back();
	if(ipfs_part.protocols()[0].m_code != multi::addr::P_IPFS)
	{
		throw INVALID_MADDR;
	}

	std::vector<std::string> pid_parts;
	std::string s = ipfs_part.string();
	boost::split(pid_parts, s, [](char c) { return c == '/'; });
	std::string pid_str = pid_parts.back();
	m_id = ID(idb58_decode(pid_str));
	if(parts.size() > 1)
	{
		multi::Addr m;
		for(auto&& p : parts)
		{
			m.encapsulate(p);
		}
		m_addrs.push_back(m);
	}
}

std::vector<multi::Addr> PeerInfo::p2p_addrs()
{
	std::vector<multi::Addr> ret;
	std::string tpl = "/" + multi::addr::proto_with_code(multi::addr::P_IPFS).m_name + "/";
	
	for(auto&& addr : this->m_addrs)
	{
		multi::Addr p2p_addr(tpl + idb58_encode(this->m_id));
		ret.push_back(addr.encapsulate(p2p_addr));
	}
	
	return ret;
}

std::string PeerInfo::marshal_json()
{
	nlohmann::json j;
	j["ID"] = this->m_id.pretty();
	std::vector<std::string> addrs;
	
	for(auto&& a : this->m_addrs)
	{
		if(a.string() == "") continue;
		addrs.push_back(a.string());
	}
	j["Addrs"] = addrs;
	return j.dump();
}

void PeerInfo::unmarshal_json(const std::string& j_string)
{
	nlohmann::json j = nlohmann::json::parse(j_string);
	this->m_id = idb58_decode(j["ID"]);
	std::vector<std::string> addrs = j["Addrs"];
	
	for(auto&& a : addrs)
	{
		this->m_addrs.push_back(multi::Addr(a));
	}	
}


_key_book::~_key_book()
{
	for(auto&& pk : m_pks)
	{
		delete pk.second;
	}

	for(auto&& sk : m_pks)
	{
		delete sk.second;
	}
}

std::vector<ID> _key_book::peers()
{
	m_lock.lock();
	std::vector<ID> ps;
	
	for(auto&& pk : m_pks)
	{
		ps.push_back(pk.first);
	}
	for(auto&& sk : m_sks)
	{
		if(std::find(ps.begin(), ps.end(), sk.first) != ps.end())
		{
			ps.push_back(sk.first);
		}
	}

	m_lock.unlock();
	return ps;
}

crypto::PubKey* _key_book::pubkey(const ID& id)
{
	m_lock.lock();
	crypto::PubKey* pk = m_pks[id];
	m_lock.unlock();
	if(pk != NULL)
	{
		return pk;
	}
	pk = id.extract_pubkey();
	if(pk != NULL)
	{
		m_lock.lock();
		m_pks[id] = pk;
		m_lock.unlock();
	}

	return pk;
}

void _key_book::add_pubkey(const ID& id, const crypto::PubKey* pk)
{
	if(!id.matches_pubkey(pk))
	{
		return;
	}

	m_lock.lock();
	m_pks[id] = pk->clone();
	m_lock.unlock();
}

crypto::PrivKey* _key_book::privkey(const ID& id)
{
	m_lock.lock();
	crypto::PrivKey* sk = m_sks[id];
	m_lock.unlock();
	return sk;
}


void _key_book::add_privkey(const ID& id, const crypto::PrivKey* sk)
{
	if(!id.matches_privkey(sk))
	{
		return;
	}

	m_lock.lock();
	m_sks[id] = sk->clone();
	m_lock.unlock();
}



}