#pragma once


#include <libmulti/hash.hpp>
#include <crypto/common.hpp>


namespace libp2p {

#define MAX_INLINE_KEY_LEN 42

struct ID;
std::string idb58_encode(const ID&);

struct ID
{
	ID(const std::string& _s) : m_str(_s) {};
	ID(const bytes& _b) : m_str(_b.begin(), _b.end()) {};
	ID(const crypto::PubKey*);
	ID(const crypto::PrivKey* k) : ID(k->get_public()) {}; 

	inline std::string pretty() const { return idb58_encode(*this); }

	bool matches_pubkey(const crypto::PubKey*);
	inline bool matches_privkey(const crypto::PrivKey* k) { return matches_pubkey(k->get_public()); }

	crypto::PubKey* extract_pubkey() const;

	inline void operator=(const ID& r) { m_str = r.m_str; }
	inline void operator=(const std::string& r) { m_str = r; }

	std::string m_str;
};

inline std::string idb58_encode(const ID& id) { return multi::base::b58btc_encode(id.m_str); }
inline ID idb58_decode(const std::string& s) { return ID(multi::hash::fromb58_string(s).hash()); }
inline std::string idhex_encode(const ID& id) { return multi::base::b16_encode(id.m_str); }
inline ID idhex_decode(const std::string& s) { return ID(multi::hash::fromhex_string(s).hash()); }


}