#pragma once


#include <libmulti/hash.hpp>
#include <crypto/common.hpp>


namespace libp2p {

#define MAX_INLINE_KEY_LEN 42

struct ID;

std::string idb58_encode(const ID&);
std::string pubkey_to_idstr(const crypto::PubKey*);

struct ID
{
	ID() = default;
	~ID() = default;

	ID(const std::string& _s) : m_str(_s) {};
	ID(const bytes& _b) : m_str(_b.begin(), _b.end()) {};
	ID(const crypto::PubKey* _pub) : m_str(pubkey_to_idstr(_pub)) {};
	ID(const crypto::PrivKey*);

	inline std::string pretty() const { return idb58_encode(*this); }

	bool matches_pubkey(const crypto::PubKey*);
	inline bool matches_privkey(const crypto::PrivKey* k) { return matches_pubkey(k->get_public()); }

	crypto::PubKey* extract_pubkey() const;

	inline void operator=(const ID& r) { m_str = r.m_str; }
	inline void operator=(const std::string& r) { m_str = r; }

	friend inline bool operator<(const ID& l, const ID& r) { return l.m_str < r.m_str; }
	std::string m_str;
};

inline std::string idb58_encode(const ID& id) { return multi::base::b58btc_encode(id.m_str); }
inline ID idb58_decode(const std::string& s) { return ID(multi::base::b58btc_decode(s)); }
inline std::string idhex_encode(const ID& id) { return multi::base::b16_encode(id.m_str); }
inline ID idhex_decode(const std::string& s) { return ID(multi::base::b16_decode(s)); }


struct PeerSet final
{
	PeerSet() = default;
	~PeerSet() = default;
	
	explicit PeerSet(unsigned int _cap) : m_cap(_cap) {};

	void add(const ID&);
	bool try_add(const ID&);
	bool contains(const ID&);
	size_t size();
	std::vector<ID> peers();

	std::set<ID> m_set;
	std::mutex set_lock;
	int m_cap;
};


}