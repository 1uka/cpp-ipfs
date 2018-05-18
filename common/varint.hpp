#pragma once

#include "types.hpp"


int put_uvarint(bytes&, uint64_t);
uint64_t uvarint(const bytes&);

int put_varint(bytes&, int64_t);
int varint(const bytes&);
