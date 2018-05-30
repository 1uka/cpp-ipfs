#include "key.hpp"

#include "rsa.hpp"

namespace crypto {

Key::~Key() {}
PubKey::~PubKey() {}
PrivKey::~PrivKey() {}

PrivKey* GenerateKey(pb::KeyType t, int bits)
{
	switch(t)
	{
		case pb::KeyType::RSA:
			return new RsaPrivateKey(bits);
	}
}

}