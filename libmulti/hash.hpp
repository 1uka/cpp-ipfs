/**
 * @brief Multihash implementation in cpp
 * 
 * @file hash.hpp
 * @author Luka Atanasovski
 * @date 2018-05-15
 */


#pragma once


#include "base.hpp"


namespace multi {
namespace hash {


/**
 * `Type` represents a wrapper class for hash type and is used instead of enum,
 * so we can store both `code` and `lenght` in the same place in memory. The instances of this 
 * class are evaluated at compile-time for better performance.
 * 
 */
class Type final
{
public:

	constexpr explicit Type(unsigned short _code, unsigned short _len) : m_code(_code), m_len(_len) {};

	constexpr unsigned short code() const { return m_code; };
	constexpr unsigned short len() const { return m_len; };

private:
	unsigned short m_code;
	unsigned short m_len;
};


/**
 * the ones that are commented out are specified in the multihash table,
 * but i dont have their implementation in cpp
 */
constexpr Type const ID(0xff, -1);
constexpr Type const sha1(0x11, 20);
constexpr Type const sha2_256(0x12, 32);
constexpr Type const sha2_512(0x13, 64);
// constexpr Type const dbl_sha2_256(0x56, 32);
constexpr Type const sha3_224(0x17, 28);
constexpr Type const sha3_256(0x16, 32);
constexpr Type const sha3_384(0x15, 48);
constexpr Type const sha3_512(0x14, 64);
// constexpr Type const shake_128(0x18, 32);
// constexpr Type const shake_256(0x19, 64);
constexpr Type const keccak_224(0x1A, 28);
constexpr Type const keccak_256(0x1B, 32);
constexpr Type const keccak_384(0x1C, 48);
constexpr Type const keccak_512(0x1D, 64);
// constexpr Type const murmur3_128(0x22, 32);
constexpr Type const blake2b_8(0xb201, 0x01);
constexpr Type const blake2b_16(0xb202, 0x02);
constexpr Type const blake2b_24(0xb203, 0x03);
constexpr Type const blake2b_32(0xb204, 0x04);
constexpr Type const blake2b_40(0xb205, 0x05);
constexpr Type const blake2b_48(0xb206, 0x06);
constexpr Type const blake2b_56(0xb207, 0x07);
constexpr Type const blake2b_64(0xb208, 0x08);
constexpr Type const blake2b_72(0xb209, 0x09);
constexpr Type const blake2b_80(0xb20a, 0x0a);
constexpr Type const blake2b_88(0xb20b, 0x0b);
constexpr Type const blake2b_96(0xb20c, 0x0c);
constexpr Type const blake2b_104(0xb20d, 0x0d);
constexpr Type const blake2b_112(0xb20e, 0x0e);
constexpr Type const blake2b_120(0xb20f, 0x0f);
constexpr Type const blake2b_128(0xb210, 0x10);
constexpr Type const blake2b_136(0xb211, 0x11);
constexpr Type const blake2b_144(0xb212, 0x12);
constexpr Type const blake2b_152(0xb213, 0x13);
constexpr Type const blake2b_160(0xb214, 0x14);
constexpr Type const blake2b_168(0xb215, 0x15);
constexpr Type const blake2b_176(0xb216, 0x16);
constexpr Type const blake2b_184(0xb217, 0x17);
constexpr Type const blake2b_192(0xb218, 0x18);
constexpr Type const blake2b_200(0xb219, 0x19);
constexpr Type const blake2b_208(0xb21a, 0x1a);
constexpr Type const blake2b_216(0xb21b, 0x1b);
constexpr Type const blake2b_224(0xb21c, 0x1c);
constexpr Type const blake2b_232(0xb21d, 0x1d);
constexpr Type const blake2b_240(0xb21e, 0x1e);
constexpr Type const blake2b_248(0xb21f, 0x1f);
constexpr Type const blake2b_256(0xb220, 0x20);
constexpr Type const blake2b_264(0xb221, 0x21);
constexpr Type const blake2b_272(0xb222, 0x22);
constexpr Type const blake2b_280(0xb223, 0x23);
constexpr Type const blake2b_288(0xb224, 0x24);
constexpr Type const blake2b_296(0xb225, 0x25);
constexpr Type const blake2b_304(0xb226, 0x26);
constexpr Type const blake2b_312(0xb227, 0x27);
constexpr Type const blake2b_320(0xb228, 0x28);
constexpr Type const blake2b_328(0xb229, 0x29);
constexpr Type const blake2b_336(0xb22a, 0x2a);
constexpr Type const blake2b_344(0xb22b, 0x2b);
constexpr Type const blake2b_352(0xb22c, 0x2c);
constexpr Type const blake2b_360(0xb22d, 0x2d);
constexpr Type const blake2b_368(0xb22e, 0x2e);
constexpr Type const blake2b_376(0xb22f, 0x2f);
constexpr Type const blake2b_384(0xb230, 0x30);
constexpr Type const blake2b_392(0xb231, 0x31);
constexpr Type const blake2b_400(0xb232, 0x32);
constexpr Type const blake2b_408(0xb233, 0x33);
constexpr Type const blake2b_416(0xb234, 0x34);
constexpr Type const blake2b_424(0xb235, 0x35);
constexpr Type const blake2b_432(0xb236, 0x36);
constexpr Type const blake2b_440(0xb237, 0x37);
constexpr Type const blake2b_448(0xb238, 0x38);
constexpr Type const blake2b_456(0xb239, 0x39);
constexpr Type const blake2b_464(0xb23a, 0x3a);
constexpr Type const blake2b_472(0xb23b, 0x3b);
constexpr Type const blake2b_480(0xb23c, 0x3c);
constexpr Type const blake2b_488(0xb23d, 0x3d);
constexpr Type const blake2b_496(0xb23e, 0x3e);
constexpr Type const blake2b_504(0xb23f, 0x3f);
constexpr Type const blake2b_512(0xb240, 0x40);
constexpr Type const blake2s_8(0xb241, 0x01);
constexpr Type const blake2s_16(0xb242, 0x02);
constexpr Type const blake2s_24(0xb243, 0x03);
constexpr Type const blake2s_32(0xb244, 0x04);
constexpr Type const blake2s_40(0xb245, 0x05);
constexpr Type const blake2s_48(0xb246, 0x06);
constexpr Type const blake2s_56(0xb247, 0x07);
constexpr Type const blake2s_64(0xb248, 0x08);
constexpr Type const blake2s_72(0xb249, 0x09);
constexpr Type const blake2s_80(0xb24a, 0x0a);
constexpr Type const blake2s_88(0xb24b, 0x0b);
constexpr Type const blake2s_96(0xb24c, 0x0c);
constexpr Type const blake2s_104(0xb24d, 0x0d);
constexpr Type const blake2s_112(0xb24e, 0x0e);
constexpr Type const blake2s_120(0xb24f, 0x0f);
constexpr Type const blake2s_128(0xb250, 0x10);
constexpr Type const blake2s_136(0xb251, 0x11);
constexpr Type const blake2s_144(0xb252, 0x12);
constexpr Type const blake2s_152(0xb253, 0x13);
constexpr Type const blake2s_160(0xb254, 0x14);
constexpr Type const blake2s_168(0xb255, 0x15);
constexpr Type const blake2s_176(0xb256, 0x16);
constexpr Type const blake2s_184(0xb257, 0x17);
constexpr Type const blake2s_192(0xb258, 0x18);
constexpr Type const blake2s_200(0xb259, 0x19);
constexpr Type const blake2s_208(0xb25a, 0x1a);
constexpr Type const blake2s_216(0xb25b, 0x1b);
constexpr Type const blake2s_224(0xb25c, 0x1c);
constexpr Type const blake2s_232(0xb25d, 0x1d);
constexpr Type const blake2s_240(0xb25e, 0x1e);
constexpr Type const blake2s_248(0xb25f, 0x1f);
constexpr Type const blake2s_256(0xb260, 0x20);
// constexpr Type const Skein256_8(0xb301, 0x01);
// constexpr Type const Skein256_16(0xb302, 0x02);
// constexpr Type const Skein256_24(0xb303, 0x03);
// constexpr Type const Skein256_32(0xb304, 0x04);
// constexpr Type const Skein256_40(0xb305, 0x05);
// constexpr Type const Skein256_48(0xb306, 0x06);
// constexpr Type const Skein256_56(0xb307, 0x07);
// constexpr Type const Skein256_64(0xb308, 0x08);
// constexpr Type const Skein256_72(0xb309, 0x09);
// constexpr Type const Skein256_80(0xb30a, 0x0a);
// constexpr Type const Skein256_88(0xb30b, 0x0b);
// constexpr Type const Skein256_96(0xb30c, 0x0c);
// constexpr Type const Skein256_104(0xb30d, 0x0d);
// constexpr Type const Skein256_112(0xb30e, 0x0e);
// constexpr Type const Skein256_120(0xb30f, 0x0f);
// constexpr Type const Skein256_128(0xb310, 0x10);
// constexpr Type const Skein256_136(0xb311, 0x11);
// constexpr Type const Skein256_144(0xb312, 0x12);
// constexpr Type const Skein256_152(0xb313, 0x13);
// constexpr Type const Skein256_160(0xb314, 0x14);
// constexpr Type const Skein256_168(0xb315, 0x15);
// constexpr Type const Skein256_176(0xb316, 0x16);
// constexpr Type const Skein256_184(0xb317, 0x17);
// constexpr Type const Skein256_192(0xb318, 0x18);
// constexpr Type const Skein256_200(0xb319, 0x19);
// constexpr Type const Skein256_208(0xb31a, 0x1a);
// constexpr Type const Skein256_216(0xb31b, 0x1b);
// constexpr Type const Skein256_224(0xb31c, 0x1c);
// constexpr Type const Skein256_232(0xb31d, 0x1d);
// constexpr Type const Skein256_240(0xb31e, 0x1e);
// constexpr Type const Skein256_248(0xb31f, 0x1f);
// constexpr Type const Skein256_256(0xb320, 0x20);
// constexpr Type const Skein512_8(0xb321, 0x01);
// constexpr Type const Skein512_16(0xb322, 0x02);
// constexpr Type const Skein512_24(0xb323, 0x03);
// constexpr Type const Skein512_32(0xb324, 0x04);
// constexpr Type const Skein512_40(0xb325, 0x05);
// constexpr Type const Skein512_48(0xb326, 0x06);
// constexpr Type const Skein512_56(0xb327, 0x07);
// constexpr Type const Skein512_64(0xb328, 0x08);
// constexpr Type const Skein512_72(0xb329, 0x09);
// constexpr Type const Skein512_80(0xb32a, 0x0a);
// constexpr Type const Skein512_88(0xb32b, 0x0b);
// constexpr Type const Skein512_96(0xb32c, 0x0c);
// constexpr Type const Skein512_104(0xb32d, 0x0d);
// constexpr Type const Skein512_112(0xb32e, 0x0e);
// constexpr Type const Skein512_120(0xb32f, 0x0f);
// constexpr Type const Skein512_128(0xb330, 0x10);
// constexpr Type const Skein512_136(0xb331, 0x11);
// constexpr Type const Skein512_144(0xb332, 0x12);
// constexpr Type const Skein512_152(0xb333, 0x13);
// constexpr Type const Skein512_160(0xb334, 0x14);
// constexpr Type const Skein512_168(0xb335, 0x15);
// constexpr Type const Skein512_176(0xb336, 0x16);
// constexpr Type const Skein512_184(0xb337, 0x17);
// constexpr Type const Skein512_192(0xb338, 0x18);
// constexpr Type const Skein512_200(0xb339, 0x19);
// constexpr Type const Skein512_208(0xb33a, 0x1a);
// constexpr Type const Skein512_216(0xb33b, 0x1b);
// constexpr Type const Skein512_224(0xb33c, 0x1c);
// constexpr Type const Skein512_232(0xb33d, 0x1d);
// constexpr Type const Skein512_240(0xb33e, 0x1e);
// constexpr Type const Skein512_248(0xb33f, 0x1f);
// constexpr Type const Skein512_256(0xb340, 0x20);
// constexpr Type const Skein512_264(0xb341, 0x21);
// constexpr Type const Skein512_272(0xb342, 0x22);
// constexpr Type const Skein512_280(0xb343, 0x23);
// constexpr Type const Skein512_288(0xb344, 0x24);
// constexpr Type const Skein512_296(0xb345, 0x25);
// constexpr Type const Skein512_304(0xb346, 0x26);
// constexpr Type const Skein512_312(0xb347, 0x27);
// constexpr Type const Skein512_320(0xb348, 0x28);
// constexpr Type const Skein512_328(0xb349, 0x29);
// constexpr Type const Skein512_336(0xb34a, 0x2a);
// constexpr Type const Skein512_344(0xb34b, 0x2b);
// constexpr Type const Skein512_352(0xb34c, 0x2c);
// constexpr Type const Skein512_360(0xb34d, 0x2d);
// constexpr Type const Skein512_368(0xb34e, 0x2e);
// constexpr Type const Skein512_376(0xb34f, 0x2f);
// constexpr Type const Skein512_384(0xb350, 0x30);
// constexpr Type const Skein512_392(0xb351, 0x31);
// constexpr Type const Skein512_400(0xb352, 0x32);
// constexpr Type const Skein512_408(0xb353, 0x33);
// constexpr Type const Skein512_416(0xb354, 0x34);
// constexpr Type const Skein512_424(0xb355, 0x35);
// constexpr Type const Skein512_432(0xb356, 0x36);
// constexpr Type const Skein512_440(0xb357, 0x37);
// constexpr Type const Skein512_448(0xb358, 0x38);
// constexpr Type const Skein512_456(0xb359, 0x39);
// constexpr Type const Skein512_464(0xb35a, 0x3a);
// constexpr Type const Skein512_472(0xb35b, 0x3b);
// constexpr Type const Skein512_480(0xb35c, 0x3c);
// constexpr Type const Skein512_488(0xb35d, 0x3d);
// constexpr Type const Skein512_496(0xb35e, 0x3e);
// constexpr Type const Skein512_504(0xb35f, 0x3f);
// constexpr Type const Skein512_512(0xb360, 0x40);
// constexpr Type const Skein1024_8(0xb361, 0x01);
// constexpr Type const Skein1024_16(0xb362, 0x02);
// constexpr Type const Skein1024_24(0xb363, 0x03);
// constexpr Type const Skein1024_32(0xb364, 0x04);
// constexpr Type const Skein1024_40(0xb365, 0x05);
// constexpr Type const Skein1024_48(0xb366, 0x06);
// constexpr Type const Skein1024_56(0xb367, 0x07);
// constexpr Type const Skein1024_64(0xb368, 0x08);
// constexpr Type const Skein1024_72(0xb369, 0x09);
// constexpr Type const Skein1024_80(0xb36a, 0x0a);
// constexpr Type const Skein1024_88(0xb36b, 0x0b);
// constexpr Type const Skein1024_96(0xb36c, 0x0c);
// constexpr Type const Skein1024_104(0xb36d, 0x0d);
// constexpr Type const Skein1024_112(0xb36e, 0x0e);
// constexpr Type const Skein1024_120(0xb36f, 0x0f);
// constexpr Type const Skein1024_128(0xb370, 0x10);
// constexpr Type const Skein1024_136(0xb371, 0x11);
// constexpr Type const Skein1024_144(0xb372, 0x12);
// constexpr Type const Skein1024_152(0xb373, 0x13);
// constexpr Type const Skein1024_160(0xb374, 0x14);
// constexpr Type const Skein1024_168(0xb375, 0x15);
// constexpr Type const Skein1024_176(0xb376, 0x16);
// constexpr Type const Skein1024_184(0xb377, 0x17);
// constexpr Type const Skein1024_192(0xb378, 0x18);
// constexpr Type const Skein1024_200(0xb379, 0x19);
// constexpr Type const Skein1024_208(0xb37a, 0x1a);
// constexpr Type const Skein1024_216(0xb37b, 0x1b);
// constexpr Type const Skein1024_224(0xb37c, 0x1c);
// constexpr Type const Skein1024_232(0xb37d, 0x1d);
// constexpr Type const Skein1024_240(0xb37e, 0x1e);
// constexpr Type const Skein1024_248(0xb37f, 0x1f);
// constexpr Type const Skein1024_256(0xb380, 0x20);
// constexpr Type const Skein1024_264(0xb381, 0x21);
// constexpr Type const Skein1024_272(0xb382, 0x22);
// constexpr Type const Skein1024_280(0xb383, 0x23);
// constexpr Type const Skein1024_288(0xb384, 0x24);
// constexpr Type const Skein1024_296(0xb385, 0x25);
// constexpr Type const Skein1024_304(0xb386, 0x26);
// constexpr Type const Skein1024_312(0xb387, 0x27);
// constexpr Type const Skein1024_320(0xb388, 0x28);
// constexpr Type const Skein1024_328(0xb389, 0x29);
// constexpr Type const Skein1024_336(0xb38a, 0x2a);
// constexpr Type const Skein1024_344(0xb38b, 0x2b);
// constexpr Type const Skein1024_352(0xb38c, 0x2c);
// constexpr Type const Skein1024_360(0xb38d, 0x2d);
// constexpr Type const Skein1024_368(0xb38e, 0x2e);
// constexpr Type const Skein1024_376(0xb38f, 0x2f);
// constexpr Type const Skein1024_384(0xb390, 0x30);
// constexpr Type const Skein1024_392(0xb391, 0x31);
// constexpr Type const Skein1024_400(0xb392, 0x32);
// constexpr Type const Skein1024_408(0xb393, 0x33);
// constexpr Type const Skein1024_416(0xb394, 0x34);
// constexpr Type const Skein1024_424(0xb395, 0x35);
// constexpr Type const Skein1024_432(0xb396, 0x36);
// constexpr Type const Skein1024_440(0xb397, 0x37);
// constexpr Type const Skein1024_448(0xb398, 0x38);
// constexpr Type const Skein1024_456(0xb399, 0x39);
// constexpr Type const Skein1024_464(0xb39a, 0x3a);
// constexpr Type const Skein1024_472(0xb39b, 0x3b);
// constexpr Type const Skein1024_480(0xb39c, 0x3c);
// constexpr Type const Skein1024_488(0xb39d, 0x3d);
// constexpr Type const Skein1024_496(0xb39e, 0x3e);
// constexpr Type const Skein1024_504(0xb39f, 0x3f);
// constexpr Type const Skein1024_512(0xb3a0, 0x40);
// constexpr Type const Skein1024_520(0xb3a1, 0x41);
// constexpr Type const Skein1024_528(0xb3a2, 0x42);
// constexpr Type const Skein1024_536(0xb3a3, 0x43);
// constexpr Type const Skein1024_544(0xb3a4, 0x44);
// constexpr Type const Skein1024_552(0xb3a5, 0x45);
// constexpr Type const Skein1024_560(0xb3a6, 0x46);
// constexpr Type const Skein1024_568(0xb3a7, 0x47);
// constexpr Type const Skein1024_576(0xb3a8, 0x48);
// constexpr Type const Skein1024_584(0xb3a9, 0x49);
// constexpr Type const Skein1024_592(0xb3aa, 0x4a);
// constexpr Type const Skein1024_600(0xb3ab, 0x4b);
// constexpr Type const Skein1024_608(0xb3ac, 0x4c);
// constexpr Type const Skein1024_616(0xb3ad, 0x4d);
// constexpr Type const Skein1024_624(0xb3ae, 0x4e);
// constexpr Type const Skein1024_632(0xb3af, 0x4f);
// constexpr Type const Skein1024_640(0xb3b0, 0x50);
// constexpr Type const Skein1024_648(0xb3b1, 0x51);
// constexpr Type const Skein1024_656(0xb3b2, 0x52);
// constexpr Type const Skein1024_664(0xb3b3, 0x53);
// constexpr Type const Skein1024_672(0xb3b4, 0x54);
// constexpr Type const Skein1024_680(0xb3b5, 0x55);
// constexpr Type const Skein1024_688(0xb3b6, 0x56);
// constexpr Type const Skein1024_696(0xb3b7, 0x57);
// constexpr Type const Skein1024_704(0xb3b8, 0x58);
// constexpr Type const Skein1024_712(0xb3b9, 0x59);
// constexpr Type const Skein1024_720(0xb3ba, 0x5a);
// constexpr Type const Skein1024_728(0xb3bb, 0x5b);
// constexpr Type const Skein1024_736(0xb3bc, 0x5c);
// constexpr Type const Skein1024_744(0xb3bd, 0x5d);
// constexpr Type const Skein1024_752(0xb3be, 0x5e);
// constexpr Type const Skein1024_760(0xb3bf, 0x5f);
// constexpr Type const Skein1024_768(0xb3c0, 0x60);
// constexpr Type const Skein1024_776(0xb3c1, 0x61);
// constexpr Type const Skein1024_784(0xb3c2, 0x62);
// constexpr Type const Skein1024_792(0xb3c3, 0x63);
// constexpr Type const Skein1024_800(0xb3c4, 0x64);
// constexpr Type const Skein1024_808(0xb3c5, 0x65);
// constexpr Type const Skein1024_816(0xb3c6, 0x66);
// constexpr Type const Skein1024_824(0xb3c7, 0x67);
// constexpr Type const Skein1024_832(0xb3c8, 0x68);
// constexpr Type const Skein1024_840(0xb3c9, 0x69);
// constexpr Type const Skein1024_848(0xb3ca, 0x6a);
// constexpr Type const Skein1024_856(0xb3cb, 0x6b);
// constexpr Type const Skein1024_864(0xb3cc, 0x6c);
// constexpr Type const Skein1024_872(0xb3cd, 0x6d);
// constexpr Type const Skein1024_880(0xb3ce, 0x6e);
// constexpr Type const Skein1024_888(0xb3cf, 0x6f);
// constexpr Type const Skein1024_896(0xb3d0, 0x70);
// constexpr Type const Skein1024_904(0xb3d1, 0x71);
// constexpr Type const Skein1024_912(0xb3d2, 0x72);
// constexpr Type const Skein1024_920(0xb3d3, 0x73);
// constexpr Type const Skein1024_928(0xb3d4, 0x74);
// constexpr Type const Skein1024_936(0xb3d5, 0x75);
// constexpr Type const Skein1024_944(0xb3d6, 0x76);
// constexpr Type const Skein1024_952(0xb3d7, 0x77);
// constexpr Type const Skein1024_960(0xb3d8, 0x78);
// constexpr Type const Skein1024_968(0xb3d9, 0x79);
// constexpr Type const Skein1024_976(0xb3da, 0x7a);
// constexpr Type const Skein1024_984(0xb3db, 0x7b);
// constexpr Type const Skein1024_992(0xb3dc, 0x7c);
// constexpr Type const Skein1024_1000(0xb3dd, 0x7d);
// constexpr Type const Skein1024_1008(0xb3de, 0x7e);
// constexpr Type const Skein1024_1016(0xb3df, 0x7f);
// constexpr Type const Skein1024_1024(0xb3e0, 0x80);




/**
 * @brief Apply a hash function to some data
 * 
 * @param input the data you want to be hashed
 * @param type 	the hash function to be applied
 * @return bytes the multihash of the input data
 */
bytes sum(const bytes& input, const Type& type = sha2_256);
inline bytes sum(const std::string& input, const Type& type = sha2_256)
{
	return sum(std::string(input.begin(), input.end()), type);
}


/**
 * @brief Wrapper for a decoded multihash 
 * containing the raw hash (without the prefix), and other info
 * 
 */
class Decoded final
{
public:
	Decoded() = default;
	~Decoded() = default;

	explicit Decoded(const bytes&);
	explicit Decoded(const std::string& _s) : Decoded(bytes(_s.begin(), _s.end())) {};

	constexpr const bytes& hash() const { return m_hash; };
	constexpr const Type& type() const { return m_type; };
	
	constexpr const unsigned short code() const { return m_type.code(); };
	constexpr const unsigned short len() const { return m_type.len(); };

private:
	bytes m_hash;
	Type m_type;
};

inline Decoded fromhex_string(const std::string& s) { return Decoded(multi::base::b16_decode(s)); }
inline Decoded fromb58_string(const std::string& s) { return Decoded(multi::base::b58btc_decode(s)); }
inline std::string b58_string(const bytes& mh) { return multi::base::b58btc_encode(mh); }

}  
}
