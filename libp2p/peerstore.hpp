#pragma once


#include "peer.hpp"

#include <libmulti/addr.hpp>


namespace libp2p {

#define INVALID_MADDR Exception("invalid p2p multiaddr")

struct PeerInfo
{
	PeerInfo() = default;
	~PeerInfo() = default;

	explicit PeerInfo(const multi::Addr&);

	std::vector<multi::Addr> p2p_addrs();

	ID m_id;
	std::vector<multi::Addr> m_addrs;
};


}