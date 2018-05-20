#pragma once

#ifndef VARINT_H
#define VARINT_H

#include "types.hpp"

#define VINT_PREFIX true
#define VINT_SUFFIX false


int put_uvarint(bytes&, uint64_t, bool prefix = VINT_PREFIX);
uint64_t uvarint(const bytes&, int* len = 0);

int put_varint(bytes&, int64_t, bool prefix = VINT_PREFIX);
int varint(const bytes&, int* len = 0);

#endif // !VARINT_H
