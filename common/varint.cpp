#include "varint.hpp"

int put_uvarint(bytes& buf, uint64_t x, bool prefix)
{
	int i = 0;
	while(x >= 0x80)
	{
		prefix ? (void) buf.insert(buf.begin() + i, (byte) x | 0x80) : buf.push_back((byte) x | 0x80);
		i++;
		x >>= 7;
	}
	prefix ? (void) buf.insert(buf.begin() + i, (byte) x) : buf.push_back((byte) x);
	return i + 1;
}

int put_uvarint(std::ostream& os, uint64_t x)
{
	int i = 0;
	while(x >= 0x80)
	{
		os << ((byte) x | 0x80);
		i++;
		x >>= 7;
	}
	os << (byte) x;
	return i + 1;
}

uint64_t uvarint(const bytes& buf, int* len)
{
	uint64_t x = 0;
	unsigned int s = 0;
	for (size_t i = 0; i < buf.size(); i++)
	{
		if(buf[i] < 0x80)
		{
			if(i > 9 || (i == 9 && buf[i] > 1))
			{
				*len = -(i + 1); 
			}
			if(len != NULL) { *len = i + 1; }
			return x | ((uint64_t) buf[i]) << s;
		}

		x |= ((uint64_t) buf[i] & 0x7f) << s;
		s += 7;
	}
	if(len != NULL) { *len = 0; }
	return 0;
}

uint64_t uvarint(std::istream& is, int* len)
{
	uint64_t x = 0;
	unsigned int s = 0;
	for (size_t i = 0; i < 10; i++)
	{
		byte y;
		is >> y;
		if(y < 0x80)
		{
			if(i > 9 || (i == 9 && y > 1))
			{
				*len = -(i + 1); 
			}
			if(len != NULL) { *len = i + 1; }
			return x | ((uint64_t) y) << s;
		}

		x |= ((uint64_t) y & 0x7f) << s;
		s += 7;
	}
	if(len != NULL) { *len = 0; }
	return 0;
}

int put_varint(bytes& buf, int64_t x, bool prefix)
{
	uint64_t ux = ((uint64_t) x) << 1;
	if(x < 0) { ux = ~ux; }
	return put_uvarint(buf, ux, prefix);
}

int varint(const bytes& buf, int* len)
{
	uint64_t ux = uvarint(buf, len);
	int64_t x = (int64_t) ux >> 1;
	if((ux & 1) != 0) { x = ~x; }
	return x;
}



