/**
 * @brief varint implementation (referenced from Go's varint implementation)
 * 
 * @file varint.cpp
 * @author Luka Atanasovski
 * @date 2018-05-20
 */

#pragma once


#include "types.hpp"

#define VINT_PREFIX true
#define VINT_SUFFIX false


int put_uvarint(bytes&, uint64_t, bool prefix = VINT_PREFIX);
uint64_t uvarint(const bytes&, int* len = 0);

int put_varint(bytes&, int64_t, bool prefix = VINT_PREFIX);
int varint(const bytes&, int* len = 0);
