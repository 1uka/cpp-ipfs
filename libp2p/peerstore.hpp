#pragma once


#include "peer.hpp"

#include <chrono>

#include <libmulti/addr.hpp>


namespace libp2p {

#define INVALID_MADDR Exception("invalid p2p multiaddr")

struct PeerInfo
{
	PeerInfo() = default;
	~PeerInfo() = default;

	explicit PeerInfo(const multi::Addr&);

	std::vector<multi::Addr> p2p_addrs();
	std::string marshal_json();
	void unmarshal_json(const std::string&);

	ID m_id;
	std::vector<multi::Addr> m_addrs;
};


class AddrBook
{
public:
	AddrBook() = default;
	virtual ~AddrBook() = 0;

	virtual void add_addr(const ID&, const multi::Addr&, std::chrono::duration<int64_t>) = 0;
	virtual void add_addr(const ID&, const std::vector<multi::Addr>&, std::chrono::duration<int64_t>) = 0;
	
	virtual void set_addr(const ID&, const multi::Addr&, std::chrono::duration<int64_t>) = 0;
	virtual void set_addr(const ID&, const std::vector<multi::Addr>&, std::chrono::duration<int64_t>) = 0;

	virtual void update_addrs(const ID&, std::chrono::duration<int64_t>, std::chrono::duration<int64_t>) = 0;

	virtual std::vector<multi::Addr> addrs(const ID&) = 0;

	virtual void clean_addrs(const ID&) = 0;
};


class KeyBook
{
public:
	KeyBook() = default;
	virtual ~KeyBook() = 0;

	virtual crypto::PubKey* pubkey(const ID&) = 0;
	virtual void add_pubkey(const ID&, const crypto::PubKey*) = 0;

	virtual crypto::PrivKey* privkey(const ID&) = 0;
	virtual void add_privkey(const ID&, const crypto::PrivKey*) = 0;
};


class _key_book : public KeyBook
{
public:
	_key_book() = default;
	~_key_book();

	std::vector<ID> peers();

	crypto::PubKey* pubkey(const ID&);
	void add_pubkey(const ID&, const crypto::PubKey*);

	crypto::PrivKey* privkey(const ID&);
	void add_privkey(const ID&, const crypto::PrivKey*);

private:
	std::unordered_map<ID, crypto::PubKey*> m_pks;
	std::unordered_map<ID, crypto::PrivKey*> m_sks;
	std::mutex m_lock;
};


}