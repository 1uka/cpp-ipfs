#pragma once


#include "peer.hpp"

#include <chrono>

#include <libmulti/addr.hpp>
#include <common/channel.hpp>


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


class Peerstore : public KeyBook, public AddrBook
{
public:
	Peerstore() = default;
	virtual ~Peerstore() = 0;

	virtual std::vector<ID> peers() = 0;
	virtual PeerInfo peer_info(const ID&) = 0;

	virtual void* get(const ID&, const std::string&) = 0;
	virtual void put(const ID&, const std::string&, const void*) = 0;

	virtual std::vector<std::string> get_protocols(const ID&) = 0;
	virtual void add_protocols(const ID&, const std::vector<std::string>&) = 0;
	virtual void set_protocols(const ID&, const std::vector<std::string>&) = 0;
	virtual std::vector<std::string> supports_protocols(const ID&, const std::vector<std::string>&) = 0;
};


#define TEMP_ADDR_TTL 	std::chrono::seconds(10)
#define PROV_ADDR_TTL 	std::chrono::minutes(10)
#define RECENT_CONN_TTL std::chrono::minutes(10)
#define OWN_ADDR_TTL		std::chrono::minutes(10)

#define PERMA_ADDR_TTL 		((int) (1 << 63) - 1)
#define CONNECTED_ADDR_TTL PERMA_ADDR_TTL-1



struct expiring_addr
{
	multi::Addr addr;
	std::chrono::duration<int64_t> ttl;
	std::time_t expires;
};

typedef std::vector<expiring_addr> addr_slice;

struct addr_sub
{
	chan_t<multi::Addr> pubch;
	std::mutex lk;
	std::vector<multi::Addr> buffer;
};

class AddrManager : public AddrBook
{
public:
private:
	std::mutex addrmu;

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



class _peerstore : public _key_book
{
public:
	_peerstore() = default;
	~_peerstore();

	std::vector<ID> peers();
	PeerInfo peer_info(const ID&);

	void* get(const ID&, const std::string&);
	void put(const ID&, const std::string&, void*);

	std::vector<std::string> get_protocols(const ID&);
	void add_protocols(const ID&, const std::vector<std::string>&);
	void set_protocols(const ID&, const std::vector<std::string>&);
	std::vector<std::string> supports_protocols(const ID&, const std::vector<std::string>&);

private:
	std::unordered_map<std::string, void*> m_ds;
	std::mutex ds_lock;
	std::mutex proto_lock;

	inline std::set<std::string>* __get_proto_set(const ID& id)
	{
		return static_cast<std::set<std::string>*>(this->get(id, "protocols"));
	}
};


std::vector<PeerInfo> peer_infos(Peerstore*, const std::vector<ID>&);
std::vector<ID> peerinfo_ids(const std::vector<PeerInfo>&);


}