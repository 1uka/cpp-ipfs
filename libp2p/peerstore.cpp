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


AddrBook::~AddrBook() {}
KeyBook::~KeyBook() {}
Peerstore::~Peerstore() {}

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



_peerstore::~_peerstore()
{
	for(auto&& kv : m_ds)
	{
		delete kv.second;
	}
}

std::vector<ID> _peerstore::peers()
{
	PeerSet ps;
	
	for(auto&& p : _key_book::peers())
	{
		ps.add(p);
	}
	
	return std::vector<ID>(ps.m_set.begin(), ps.m_set.end());
}

PeerInfo _peerstore::peer_info(const ID& id)
{
	// TODO: after addr_manager is implemented
}


void* _peerstore::get(const ID& id, const std::string& key)
{
	proto_lock.lock();
	void* ret = NULL;
	if(m_ds.count(id.m_str + "/" + key) > 0)
	{
		ret = m_ds[id.m_str + "/" + key];
	}
	proto_lock.unlock();
	return ret;
}

void _peerstore::put(const ID& id, const std::string& key, void* val)
{
	proto_lock.lock();
	m_ds[id.m_str + "/" + key] = val;
	proto_lock.unlock();
}


std::vector<std::string> _peerstore::get_protocols(const ID& id)
{
	proto_lock.lock();
	std::set<std::string>* pset = __get_proto_set(id);
	std::vector<std::string> ret;
	if(pset != NULL)
	{
		for(auto&& k : *pset)
		{
			ret.push_back(k);
		}
	}
	proto_lock.unlock();
	return ret;
}

void _peerstore::add_protocols(const ID& id, const std::vector<std::string>& protos)
{
	proto_lock.lock();
	std::set<std::string>* pset = __get_proto_set(id);
	if(pset == NULL)
	{
		pset = new std::set<std::string>(); // TODO: this might cause mem leak if not cleared
	}

	for(auto&& p : protos)
	{
		pset->insert(p);
	}
	this->put(id, "protocols", pset);
	proto_lock.unlock();
}

void _peerstore::set_protocols(const ID& id, const std::vector<std::string>& protos)
{
	proto_lock.lock();
	std::set<std::string>* pset = new std::set<std::string>(); // TODO: this might cause mem leak if not cleared
	for(auto&& p : protos)
	{
		pset->insert(p);
	}
	this->put(id, "protocols", pset);
	proto_lock.unlock();
}

std::vector<std::string> _peerstore::supports_protocols(const ID& id, const std::vector<std::string>& protos)
{
	proto_lock.lock();
	std::vector<std::string> ret;
	std::set<std::string>* pset = __get_proto_set(id);
	if(pset == NULL)
	{
		proto_lock.unlock();
		return ret;
	}

	for(auto&& p : protos)
	{
		if(pset->count(p) > 0)
		{
			ret.push_back(p);
		}
	}

	proto_lock.unlock();
	return ret;
}

std::vector<PeerInfo> peer_infos(Peerstore* ps, const std::vector<ID>& ids)
{
	std::vector<PeerInfo> ret;
	for(auto&& id : ids)
	{
		ret.push_back(ps->peer_info(id));
	}
	return ret;
}

std::vector<ID> peerinfo_ids(const std::vector<PeerInfo>& pi)
{
	std::vector<ID> ret;
	for(auto&& i : pi)
	{
		ret.push_back(i.m_id);
	}
	return ret;
}



}