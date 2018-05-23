/**
 * @brief Private/Public key cryptographic utilities
 * 
 * @file key.hpp
 * @author Luka Atanasovski
 * @date 2018-05-23
 */
#pragma once

#include <cryptopp/cryptlib.h>
#include <cryptopp/osrng.h>
#include <cryptopp/oids.h>
#include <cryptopp/eccrypto.h>

#define SECP256K1 CryptoPP::ASN1::secp256k1()

namespace crypto {


}