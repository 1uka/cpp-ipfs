#include "peerstore.hpp"


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

std::vector<multi::Addr> PeerInfo::to_p2p_addrs()
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


}