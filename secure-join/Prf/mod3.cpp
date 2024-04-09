#include "secure-join/Defines.h"
#include "mod3.h"
#include "cryptoTools/Crypto/PRNG.h"
#include "cryptoTools/Common/BitVector.h"
#include "cryptoTools/Common/Aligned.h"

#include <immintrin.h>
namespace secJoin
{



    // z =  x + y mod 3
    void mod3Add(
        span<block> z1, span<block> z0,
        span<block> x1, span<block> x0,
        span<block> y1, span<block> y0)
    {
        assert(z1.size() == z0.size());
        assert(z1.size() == x0.size());
        assert(z1.size() == y0.size());
        assert(x1.size() == x0.size());
        assert(y1.size() == y0.size());

        //auto x1x0 = x1 ^ x0;
        //auto z1 = (1 ^ y0 ^ x0) * (x1x0 ^ y1);
        //auto z0 = (1 ^ x1 ^ y1) * (x1x0 ^ y0);
        //auto e = (x + y) % 3;
        for (u64 i = 0; i < z0.size(); ++i)
        {
            auto x1i = x1.data()[i];
            auto x0i = x0.data()[i];
            auto y1i = y1.data()[i];
            auto y0i = y0.data()[i];
            auto x1x0 = x1i ^ x0i;
            z1.data()[i] = (y0i ^ x0i).andnot_si128(x1x0 ^ y1i);
            z0.data()[i] = (x1i ^ y1i).andnot_si128(x1x0 ^ y0i);
        }
    }

    // (ab) += y0 mod 3
    // we treat binary x1 as the MSB and binary x0 as lsb.
    // That is, for bits, x1 x0 y0, we sets 
    //   t = x1 * 2 + x0 + y0
    //   x1 = t / 2
    //   x0 = t % 2
    void mod3Add(
        span<block> z1, span<block> z0,
        span<block> x1, span<block> x0,
        span<block> y0)
    {
        //auto z1 = x1 ^ (x1 ^ x0) * y0;
        //auto z0 = x0 ^ (1 ^ x1) * y0;
        assert(z1.size() == z0.size());
        assert(z1.size() == x0.size());
        assert(z1.size() == y0.size());
        assert(x1.size() == x0.size());


        for (u64 i = 0; i < x1.size(); ++i)
        {
            auto ab = x1.data()[i] ^ x0.data()[i];
            auto abc = ab & y0.data()[i];

            auto zz1 = x1.data()[i] ^ abc;

            auto nac = x1.data()[i].andnot_si128(y0.data()[i]);
            auto zz0 = x0.data()[i] ^ nac;

            z1.data()[i] = zz1;
            z0.data()[i] = zz0;

        }
    }


    void sampleMod3(PRNG& prng, span<u8> mBuffer)
    {
        auto n = mBuffer.size();
        auto dst = mBuffer.data();
        block m[8], t[8], eq[8];
        block allOne = oc::AllOneBlock;
        block block1 = block::allSame<u16>(1);
        block block3 = block::allSame<u16>(3);

        static constexpr int batchSize = 16;
        std::array<std::array<block, 8>, 64> buffer;
        std::array<u8* __restrict, 64> iters;

        for (u64 i = 0; i < n;)
        {
            for (u64 j = 0; j < 64; ++j)
                iters[j] = (u8*)buffer[j].data();

            for (u64 bb = 0; bb < batchSize; ++bb)
            {
                prng.mAes.ecbEncCounterMode(prng.mBlockIdx, 8, m);
                prng.mBlockIdx += 8;


                for (u64 j = 0; j < 8; ++j)
                {
                    if (j)
                    {
                        m[0] = m[0] >> 2;
                        m[1] = m[1] >> 2;
                        m[2] = m[2] >> 2;
                        m[3] = m[3] >> 2;
                        m[4] = m[4] >> 2;
                        m[5] = m[5] >> 2;
                        m[6] = m[6] >> 2;
                        m[7] = m[7] >> 2;
                    }

                    t[0] = m[0] & block3;
                    t[1] = m[1] & block3;
                    t[2] = m[2] & block3;
                    t[3] = m[3] & block3;
                    t[4] = m[4] & block3;
                    t[5] = m[5] & block3;
                    t[6] = m[6] & block3;
                    t[7] = m[7] & block3;

                    eq[0] = _mm_cmpeq_epi16(t[0], block3);
                    eq[1] = _mm_cmpeq_epi16(t[1], block3);
                    eq[2] = _mm_cmpeq_epi16(t[2], block3);
                    eq[3] = _mm_cmpeq_epi16(t[3], block3);
                    eq[4] = _mm_cmpeq_epi16(t[4], block3);
                    eq[5] = _mm_cmpeq_epi16(t[5], block3);
                    eq[6] = _mm_cmpeq_epi16(t[6], block3);
                    eq[7] = _mm_cmpeq_epi16(t[7], block3);

                    eq[0] = eq[0] ^ allOne;
                    eq[1] = eq[1] ^ allOne;
                    eq[2] = eq[2] ^ allOne;
                    eq[3] = eq[3] ^ allOne;
                    eq[4] = eq[4] ^ allOne;
                    eq[5] = eq[5] ^ allOne;
                    eq[6] = eq[6] ^ allOne;
                    eq[7] = eq[7] ^ allOne;

                    eq[0] = eq[0] & block1;
                    eq[1] = eq[1] & block1;
                    eq[2] = eq[2] & block1;
                    eq[3] = eq[3] & block1;
                    eq[4] = eq[4] & block1;
                    eq[5] = eq[5] & block1;
                    eq[6] = eq[6] & block1;
                    eq[7] = eq[7] & block1;

                    auto t16 = (u16 * __restrict)t;
                    auto e16 = (u16 * __restrict)eq;
                    for (u64 j = 0; j < 64; ++j)
                    {
                        iters[j][0] = t16[j];
                        iters[j] += e16[j];
                    }
                }
            }

            for (u64 j = 0; j < 64 && i < n; ++j)
            {
                auto b = (u8*)buffer[j].data();

                auto size = iters[j] - b;
                auto min = std::min<u64>(size, n - i);
                if (min)
                {
                    memcpy(dst + i, b, min);
                    i += min;
                }
            }
        }
    }

    void sampleMod3(PRNG& prng, span<block> msb, span<block> lsb, oc::AlignedUnVector<u8>& b)
    {
        b.resize(msb.size() * 128);
        sampleMod3(prng, b);
        block block1 = block::allSame<u8>(1);
        block block2 = block::allSame<u8>(2);

        for (u64 i = 0; i < msb.size(); ++i)
        {
            auto bb = (block*)&b.data()[i * 128];
            assert((u64)bb % 16 == 0);

            block tt[8];
            tt[0] = bb[0] & block1;
            tt[1] = bb[1] & block1;
            tt[2] = bb[2] & block1;
            tt[3] = bb[3] & block1;
            tt[4] = bb[4] & block1;
            tt[5] = bb[5] & block1;
            tt[6] = bb[6] & block1;
            tt[7] = bb[7] & block1;

            lsb[i] =
                tt[0] << 0 ^
                tt[1] << 1 ^
                tt[2] << 2 ^
                tt[3] << 3 ^
                tt[4] << 4 ^
                tt[5] << 5 ^
                tt[6] << 6 ^
                tt[7] << 7;


            tt[0] = bb[0] & block2;
            tt[1] = bb[1] & block2;
            tt[2] = bb[2] & block2;
            tt[3] = bb[3] & block2;
            tt[4] = bb[4] & block2;
            tt[5] = bb[5] & block2;
            tt[6] = bb[6] & block2;
            tt[7] = bb[7] & block2;

            msb[i] =
                tt[0] >> 1 ^
                tt[1] << 0 ^
                tt[2] << 1 ^
                tt[3] << 2 ^
                tt[4] << 3 ^
                tt[5] << 4 ^
                tt[6] << 5 ^
                tt[7] << 6;
        }
    }

    // generated using buildMod3Tabel. Each of the first 243=3^5 positions
    // contains 5 mod-3 values. the first byte of each entry contains the 
    //5 lsb. the second byte contains the 5 msb. The third byte contains a 
    // zero-one flag indicating if this sample less that 243 ad therefore
    // valid. The idea of the sample is that it takes as input a random byte 
    // and returns 5 random mod3 values or bot.
    const std::array<u32, 256> mod3Table =
    { {
        0x10000, 0x10001, 0x10100, 0x10002, 0x10003, 0x10102, 0x10200, 0x10201,
        0x10300, 0x10004, 0x10005, 0x10104, 0x10006, 0x10007, 0x10106, 0x10204,
        0x10205, 0x10304, 0x10400, 0x10401, 0x10500, 0x10402, 0x10403, 0x10502,
        0x10600, 0x10601, 0x10700, 0x10008, 0x10009, 0x10108, 0x1000a, 0x1000b,
        0x1010a, 0x10208, 0x10209, 0x10308, 0x1000c, 0x1000d, 0x1010c, 0x1000e,
        0x1000f, 0x1010e, 0x1020c, 0x1020d, 0x1030c, 0x10408, 0x10409, 0x10508,
        0x1040a, 0x1040b, 0x1050a, 0x10608, 0x10609, 0x10708, 0x10800, 0x10801,
        0x10900, 0x10802, 0x10803, 0x10902, 0x10a00, 0x10a01, 0x10b00, 0x10804,
        0x10805, 0x10904, 0x10806, 0x10807, 0x10906, 0x10a04, 0x10a05, 0x10b04,
        0x10c00, 0x10c01, 0x10d00, 0x10c02, 0x10c03, 0x10d02, 0x10e00, 0x10e01,
        0x10f00, 0x10010, 0x10011, 0x10110, 0x10012, 0x10013, 0x10112, 0x10210,
        0x10211, 0x10310, 0x10014, 0x10015, 0x10114, 0x10016, 0x10017, 0x10116,
        0x10214, 0x10215, 0x10314, 0x10410, 0x10411, 0x10510, 0x10412, 0x10413,
        0x10512, 0x10610, 0x10611, 0x10710, 0x10018, 0x10019, 0x10118, 0x1001a,
        0x1001b, 0x1011a, 0x10218, 0x10219, 0x10318, 0x1001c, 0x1001d, 0x1011c,
        0x1001e, 0x1001f, 0x1011e, 0x1021c, 0x1021d, 0x1031c, 0x10418, 0x10419,
        0x10518, 0x1041a, 0x1041b, 0x1051a, 0x10618, 0x10619, 0x10718, 0x10810,
        0x10811, 0x10910, 0x10812, 0x10813, 0x10912, 0x10a10, 0x10a11, 0x10b10,
        0x10814, 0x10815, 0x10914, 0x10816, 0x10817, 0x10916, 0x10a14, 0x10a15,
        0x10b14, 0x10c10, 0x10c11, 0x10d10, 0x10c12, 0x10c13, 0x10d12, 0x10e10,
        0x10e11, 0x10f10, 0x11000, 0x11001, 0x11100, 0x11002, 0x11003, 0x11102,
        0x11200, 0x11201, 0x11300, 0x11004, 0x11005, 0x11104, 0x11006, 0x11007,
        0x11106, 0x11204, 0x11205, 0x11304, 0x11400, 0x11401, 0x11500, 0x11402,
        0x11403, 0x11502, 0x11600, 0x11601, 0x11700, 0x11008, 0x11009, 0x11108,
        0x1100a, 0x1100b, 0x1110a, 0x11208, 0x11209, 0x11308, 0x1100c, 0x1100d,
        0x1110c, 0x1100e, 0x1100f, 0x1110e, 0x1120c, 0x1120d, 0x1130c, 0x11408,
        0x11409, 0x11508, 0x1140a, 0x1140b, 0x1150a, 0x11608, 0x11609, 0x11708,
        0x11800, 0x11801, 0x11900, 0x11802, 0x11803, 0x11902, 0x11a00, 0x11a01,
        0x11b00, 0x11804, 0x11805, 0x11904, 0x11806, 0x11807, 0x11906, 0x11a04,
        0x11a05, 0x11b04, 0x11c00, 0x11c01, 0x11d00, 0x11c02, 0x11c03, 0x11d02,
        0x11e00, 0x11e01, 0x11f00, 0x0, 0x0, 0x0, 0x0, 0x0,
        0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0
} };

    const std::array<u32, 256> mod3TableV{
        5,5,5,5,5,5,5,5,
        5,5,5,5,5,5,5,5,
        5,5,5,5,5,5,5,5,
        5,5,5,5,5,5,5,5,
        5,5,5,5,5,5,5,5,
        5,5,5,5,5,5,5,5,
        5,5,5,5,5,5,5,5,
        5,5,5,5,5,5,5,5,
        5,5,5,5,5,5,5,5,
        5,5,5,5,5,5,5,5,
        5,5,5,5,5,5,5,5,
        5,5,5,5,5,5,5,5,
        5,5,5,5,5,5,5,5,
        5,5,5,5,5,5,5,5,
        5,5,5,5,5,5,5,5,
        5,5,5,5,5,5,5,5,
        5,5,5,5,5,5,5,5,
        5,5,5,5,5,5,5,5,
        5,5,5,5,5,5,5,5,
        5,5,5,5,5,5,5,5,
        5,5,5,5,5,5,5,5,
        5,5,5,5,5,5,5,5,
        5,5,5,5,5,5,5,5,
        5,5,5,5,5,5,5,5,
        5,5,5,5,5,5,5,5,
        5,5,5,5,5,5,5,5,
        5,5,5,5,5,5,5,5,
        5,5,5,5,5,5,5,5,
        5,5,5,5,5,5,5,5,
        5,5,5,5,5,5,5,5,
        5,5,5,0,0,0,0,0,
        0,0,0,0,0,0,0,0,
    };

    const std::array<u32, 256> mod3TableLsb{ {
     0b00000, 0b00001, 0b00000, 0b00010, 0b00011, 0b00010, 0b00000, 0b00001,
     0b00000, 0b00100, 0b00101, 0b00100, 0b00110, 0b00111, 0b00110, 0b00100,
     0b00101, 0b00100, 0b00000, 0b00001, 0b00000, 0b00010, 0b00011, 0b00010,
     0b00000, 0b00001, 0b00000, 0b01000, 0b01001, 0b01000, 0b01010, 0b01011,
     0b01010, 0b01000, 0b01001, 0b01000, 0b01100, 0b01101, 0b01100, 0b01110,
     0b01111, 0b01110, 0b01100, 0b01101, 0b01100, 0b01000, 0b01001, 0b01000,
     0b01010, 0b01011, 0b01010, 0b01000, 0b01001, 0b01000, 0b00000, 0b00001,
     0b00000, 0b00010, 0b00011, 0b00010, 0b00000, 0b00001, 0b00000, 0b00100,
     0b00101, 0b00100, 0b00110, 0b00111, 0b00110, 0b00100, 0b00101, 0b00100,
     0b00000, 0b00001, 0b00000, 0b00010, 0b00011, 0b00010, 0b00000, 0b00001,
     0b00000, 0b10000, 0b10001, 0b10000, 0b10010, 0b10011, 0b10010, 0b10000,
     0b10001, 0b10000, 0b10100, 0b10101, 0b10100, 0b10110, 0b10111, 0b10110,
     0b10100, 0b10101, 0b10100, 0b10000, 0b10001, 0b10000, 0b10010, 0b10011,
     0b10010, 0b10000, 0b10001, 0b10000, 0b11000, 0b11001, 0b11000, 0b11010,
     0b11011, 0b11010, 0b11000, 0b11001, 0b11000, 0b11100, 0b11101, 0b11100,
     0b11110, 0b11111, 0b11110, 0b11100, 0b11101, 0b11100, 0b11000, 0b11001,
     0b11000, 0b11010, 0b11011, 0b11010, 0b11000, 0b11001, 0b11000, 0b10000,
     0b10001, 0b10000, 0b10010, 0b10011, 0b10010, 0b10000, 0b10001, 0b10000,
     0b10100, 0b10101, 0b10100, 0b10110, 0b10111, 0b10110, 0b10100, 0b10101,
     0b10100, 0b10000, 0b10001, 0b10000, 0b10010, 0b10011, 0b10010, 0b10000,
     0b10001, 0b10000, 0b00000, 0b00001, 0b00000, 0b00010, 0b00011, 0b00010,
     0b00000, 0b00001, 0b00000, 0b00100, 0b00101, 0b00100, 0b00110, 0b00111,
     0b00110, 0b00100, 0b00101, 0b00100, 0b00000, 0b00001, 0b00000, 0b00010,
     0b00011, 0b00010, 0b00000, 0b00001, 0b00000, 0b01000, 0b01001, 0b01000,
     0b01010, 0b01011, 0b01010, 0b01000, 0b01001, 0b01000, 0b01100, 0b01101,
     0b01100, 0b01110, 0b01111, 0b01110, 0b01100, 0b01101, 0b01100, 0b01000,
     0b01001, 0b01000, 0b01010, 0b01011, 0b01010, 0b01000, 0b01001, 0b01000,
     0b00000, 0b00001, 0b00000, 0b00010, 0b00011, 0b00010, 0b00000, 0b00001,
     0b00000, 0b00100, 0b00101, 0b00100, 0b00110, 0b00111, 0b00110, 0b00100,
     0b00101, 0b00100, 0b00000, 0b00001, 0b00000, 0b00010, 0b00011, 0b00010,
     0b00000, 0b00001, 0b00000, 0b00000, 0b00000, 0b00000, 0b00000, 0b00000,
     0b00000, 0b00000, 0b00000, 0b00000, 0b00000, 0b00000, 0b00000, 0b00000,
    } };

    const std::array<u32, 256> mod3TableMsb{ {
     0b00000, 0b00000, 0b00001, 0b00000, 0b00000, 0b00001, 0b00010, 0b00010,
     0b00011, 0b00000, 0b00000, 0b00001, 0b00000, 0b00000, 0b00001, 0b00010,
     0b00010, 0b00011, 0b00100, 0b00100, 0b00101, 0b00100, 0b00100, 0b00101,
     0b00110, 0b00110, 0b00111, 0b00000, 0b00000, 0b00001, 0b00000, 0b00000,
     0b00001, 0b00010, 0b00010, 0b00011, 0b00000, 0b00000, 0b00001, 0b00000,
     0b00000, 0b00001, 0b00010, 0b00010, 0b00011, 0b00100, 0b00100, 0b00101,
     0b00100, 0b00100, 0b00101, 0b00110, 0b00110, 0b00111, 0b01000, 0b01000,
     0b01001, 0b01000, 0b01000, 0b01001, 0b01010, 0b01010, 0b01011, 0b01000,
     0b01000, 0b01001, 0b01000, 0b01000, 0b01001, 0b01010, 0b01010, 0b01011,
     0b01100, 0b01100, 0b01101, 0b01100, 0b01100, 0b01101, 0b01110, 0b01110,
     0b01111, 0b00000, 0b00000, 0b00001, 0b00000, 0b00000, 0b00001, 0b00010,
     0b00010, 0b00011, 0b00000, 0b00000, 0b00001, 0b00000, 0b00000, 0b00001,
     0b00010, 0b00010, 0b00011, 0b00100, 0b00100, 0b00101, 0b00100, 0b00100,
     0b00101, 0b00110, 0b00110, 0b00111, 0b00000, 0b00000, 0b00001, 0b00000,
     0b00000, 0b00001, 0b00010, 0b00010, 0b00011, 0b00000, 0b00000, 0b00001,
     0b00000, 0b00000, 0b00001, 0b00010, 0b00010, 0b00011, 0b00100, 0b00100,
     0b00101, 0b00100, 0b00100, 0b00101, 0b00110, 0b00110, 0b00111, 0b01000,
     0b01000, 0b01001, 0b01000, 0b01000, 0b01001, 0b01010, 0b01010, 0b01011,
     0b01000, 0b01000, 0b01001, 0b01000, 0b01000, 0b01001, 0b01010, 0b01010,
     0b01011, 0b01100, 0b01100, 0b01101, 0b01100, 0b01100, 0b01101, 0b01110,
     0b01110, 0b01111, 0b10000, 0b10000, 0b10001, 0b10000, 0b10000, 0b10001,
     0b10010, 0b10010, 0b10011, 0b10000, 0b10000, 0b10001, 0b10000, 0b10000,
     0b10001, 0b10010, 0b10010, 0b10011, 0b10100, 0b10100, 0b10101, 0b10100,
     0b10100, 0b10101, 0b10110, 0b10110, 0b10111, 0b10000, 0b10000, 0b10001,
     0b10000, 0b10000, 0b10001, 0b10010, 0b10010, 0b10011, 0b10000, 0b10000,
     0b10001, 0b10000, 0b10000, 0b10001, 0b10010, 0b10010, 0b10011, 0b10100,
     0b10100, 0b10101, 0b10100, 0b10100, 0b10101, 0b10110, 0b10110, 0b10111,
     0b11000, 0b11000, 0b11001, 0b11000, 0b11000, 0b11001, 0b11010, 0b11010,
     0b11011, 0b11000, 0b11000, 0b11001, 0b11000, 0b11000, 0b11001, 0b11010,
     0b11010, 0b11011, 0b11100, 0b11100, 0b11101, 0b11100, 0b11100, 0b11101,
     0b11110, 0b11110, 0b11111, 0b00000, 0b00000, 0b00000, 0b00000, 0b00000,
     0b00000, 0b00000, 0b00000, 0b00000, 0b00000, 0b00000, 0b00000, 0b00000,
    } };

    std::array<std::array<u8, 5>, 256>const mod3TableFull{ {
    {  0, 0, 0, 0, 0},{  1, 0, 0, 0, 0},{  2, 0, 0, 0, 0},{  0, 1, 0, 0, 0},{  1, 1, 0, 0, 0},{  2, 1, 0, 0, 0},{  0, 2, 0, 0, 0},{  1, 2, 0, 0, 0},
    {  2, 2, 0, 0, 0},{  0, 0, 1, 0, 0},{  1, 0, 1, 0, 0},{  2, 0, 1, 0, 0},{  0, 1, 1, 0, 0},{  1, 1, 1, 0, 0},{  2, 1, 1, 0, 0},{  0, 2, 1, 0, 0},
    {  1, 2, 1, 0, 0},{  2, 2, 1, 0, 0},{  0, 0, 2, 0, 0},{  1, 0, 2, 0, 0},{  2, 0, 2, 0, 0},{  0, 1, 2, 0, 0},{  1, 1, 2, 0, 0},{  2, 1, 2, 0, 0},
    {  0, 2, 2, 0, 0},{  1, 2, 2, 0, 0},{  2, 2, 2, 0, 0},{  0, 0, 0, 1, 0},{  1, 0, 0, 1, 0},{  2, 0, 0, 1, 0},{  0, 1, 0, 1, 0},{  1, 1, 0, 1, 0},
    {  2, 1, 0, 1, 0},{  0, 2, 0, 1, 0},{  1, 2, 0, 1, 0},{  2, 2, 0, 1, 0},{  0, 0, 1, 1, 0},{  1, 0, 1, 1, 0},{  2, 0, 1, 1, 0},{  0, 1, 1, 1, 0},
    {  1, 1, 1, 1, 0},{  2, 1, 1, 1, 0},{  0, 2, 1, 1, 0},{  1, 2, 1, 1, 0},{  2, 2, 1, 1, 0},{  0, 0, 2, 1, 0},{  1, 0, 2, 1, 0},{  2, 0, 2, 1, 0},
    {  0, 1, 2, 1, 0},{  1, 1, 2, 1, 0},{  2, 1, 2, 1, 0},{  0, 2, 2, 1, 0},{  1, 2, 2, 1, 0},{  2, 2, 2, 1, 0},{  0, 0, 0, 2, 0},{  1, 0, 0, 2, 0},
    {  2, 0, 0, 2, 0},{  0, 1, 0, 2, 0},{  1, 1, 0, 2, 0},{  2, 1, 0, 2, 0},{  0, 2, 0, 2, 0},{  1, 2, 0, 2, 0},{  2, 2, 0, 2, 0},{  0, 0, 1, 2, 0},
    {  1, 0, 1, 2, 0},{  2, 0, 1, 2, 0},{  0, 1, 1, 2, 0},{  1, 1, 1, 2, 0},{  2, 1, 1, 2, 0},{  0, 2, 1, 2, 0},{  1, 2, 1, 2, 0},{  2, 2, 1, 2, 0},
    {  0, 0, 2, 2, 0},{  1, 0, 2, 2, 0},{  2, 0, 2, 2, 0},{  0, 1, 2, 2, 0},{  1, 1, 2, 2, 0},{  2, 1, 2, 2, 0},{  0, 2, 2, 2, 0},{  1, 2, 2, 2, 0},
    {  2, 2, 2, 2, 0},{  0, 0, 0, 0, 1},{  1, 0, 0, 0, 1},{  2, 0, 0, 0, 1},{  0, 1, 0, 0, 1},{  1, 1, 0, 0, 1},{  2, 1, 0, 0, 1},{  0, 2, 0, 0, 1},
    {  1, 2, 0, 0, 1},{  2, 2, 0, 0, 1},{  0, 0, 1, 0, 1},{  1, 0, 1, 0, 1},{  2, 0, 1, 0, 1},{  0, 1, 1, 0, 1},{  1, 1, 1, 0, 1},{  2, 1, 1, 0, 1},
    {  0, 2, 1, 0, 1},{  1, 2, 1, 0, 1},{  2, 2, 1, 0, 1},{  0, 0, 2, 0, 1},{  1, 0, 2, 0, 1},{  2, 0, 2, 0, 1},{  0, 1, 2, 0, 1},{  1, 1, 2, 0, 1},
    {  2, 1, 2, 0, 1},{  0, 2, 2, 0, 1},{  1, 2, 2, 0, 1},{  2, 2, 2, 0, 1},{  0, 0, 0, 1, 1},{  1, 0, 0, 1, 1},{  2, 0, 0, 1, 1},{  0, 1, 0, 1, 1},
    {  1, 1, 0, 1, 1},{  2, 1, 0, 1, 1},{  0, 2, 0, 1, 1},{  1, 2, 0, 1, 1},{  2, 2, 0, 1, 1},{  0, 0, 1, 1, 1},{  1, 0, 1, 1, 1},{  2, 0, 1, 1, 1},
    {  0, 1, 1, 1, 1},{  1, 1, 1, 1, 1},{  2, 1, 1, 1, 1},{  0, 2, 1, 1, 1},{  1, 2, 1, 1, 1},{  2, 2, 1, 1, 1},{  0, 0, 2, 1, 1},{  1, 0, 2, 1, 1},
    {  2, 0, 2, 1, 1},{  0, 1, 2, 1, 1},{  1, 1, 2, 1, 1},{  2, 1, 2, 1, 1},{  0, 2, 2, 1, 1},{  1, 2, 2, 1, 1},{  2, 2, 2, 1, 1},{  0, 0, 0, 2, 1},
    {  1, 0, 0, 2, 1},{  2, 0, 0, 2, 1},{  0, 1, 0, 2, 1},{  1, 1, 0, 2, 1},{  2, 1, 0, 2, 1},{  0, 2, 0, 2, 1},{  1, 2, 0, 2, 1},{  2, 2, 0, 2, 1},
    {  0, 0, 1, 2, 1},{  1, 0, 1, 2, 1},{  2, 0, 1, 2, 1},{  0, 1, 1, 2, 1},{  1, 1, 1, 2, 1},{  2, 1, 1, 2, 1},{  0, 2, 1, 2, 1},{  1, 2, 1, 2, 1},
    {  2, 2, 1, 2, 1},{  0, 0, 2, 2, 1},{  1, 0, 2, 2, 1},{  2, 0, 2, 2, 1},{  0, 1, 2, 2, 1},{  1, 1, 2, 2, 1},{  2, 1, 2, 2, 1},{  0, 2, 2, 2, 1},
    {  1, 2, 2, 2, 1},{  2, 2, 2, 2, 1},{  0, 0, 0, 0, 2},{  1, 0, 0, 0, 2},{  2, 0, 0, 0, 2},{  0, 1, 0, 0, 2},{  1, 1, 0, 0, 2},{  2, 1, 0, 0, 2},
    {  0, 2, 0, 0, 2},{  1, 2, 0, 0, 2},{  2, 2, 0, 0, 2},{  0, 0, 1, 0, 2},{  1, 0, 1, 0, 2},{  2, 0, 1, 0, 2},{  0, 1, 1, 0, 2},{  1, 1, 1, 0, 2},
    {  2, 1, 1, 0, 2},{  0, 2, 1, 0, 2},{  1, 2, 1, 0, 2},{  2, 2, 1, 0, 2},{  0, 0, 2, 0, 2},{  1, 0, 2, 0, 2},{  2, 0, 2, 0, 2},{  0, 1, 2, 0, 2},
    {  1, 1, 2, 0, 2},{  2, 1, 2, 0, 2},{  0, 2, 2, 0, 2},{  1, 2, 2, 0, 2},{  2, 2, 2, 0, 2},{  0, 0, 0, 1, 2},{  1, 0, 0, 1, 2},{  2, 0, 0, 1, 2},
    {  0, 1, 0, 1, 2},{  1, 1, 0, 1, 2},{  2, 1, 0, 1, 2},{  0, 2, 0, 1, 2},{  1, 2, 0, 1, 2},{  2, 2, 0, 1, 2},{  0, 0, 1, 1, 2},{  1, 0, 1, 1, 2},
    {  2, 0, 1, 1, 2},{  0, 1, 1, 1, 2},{  1, 1, 1, 1, 2},{  2, 1, 1, 1, 2},{  0, 2, 1, 1, 2},{  1, 2, 1, 1, 2},{  2, 2, 1, 1, 2},{  0, 0, 2, 1, 2},
    {  1, 0, 2, 1, 2},{  2, 0, 2, 1, 2},{  0, 1, 2, 1, 2},{  1, 1, 2, 1, 2},{  2, 1, 2, 1, 2},{  0, 2, 2, 1, 2},{  1, 2, 2, 1, 2},{  2, 2, 2, 1, 2},
    {  0, 0, 0, 2, 2},{  1, 0, 0, 2, 2},{  2, 0, 0, 2, 2},{  0, 1, 0, 2, 2},{  1, 1, 0, 2, 2},{  2, 1, 0, 2, 2},{  0, 2, 0, 2, 2},{  1, 2, 0, 2, 2},
    {  2, 2, 0, 2, 2},{  0, 0, 1, 2, 2},{  1, 0, 1, 2, 2},{  2, 0, 1, 2, 2},{  0, 1, 1, 2, 2},{  1, 1, 1, 2, 2},{  2, 1, 1, 2, 2},{  0, 2, 1, 2, 2},
    {  1, 2, 1, 2, 2},{  2, 2, 1, 2, 2},{  0, 0, 2, 2, 2},{  1, 0, 2, 2, 2},{  2, 0, 2, 2, 2},{  0, 1, 2, 2, 2},{  1, 1, 2, 2, 2},{  2, 1, 2, 2, 2},
    {  0, 2, 2, 2, 2},{  1, 2, 2, 2, 2},{  2, 2, 2, 2, 2},{  0, 0, 0, 0, 0},{  0, 0, 0, 0, 0},{  0, 0, 0, 0, 0},{  0, 0, 0, 0, 0},{  0, 0, 0, 0, 0},
    {  0, 0, 0, 0, 0},{  0, 0, 0, 0, 0},{  0, 0, 0, 0, 0},{  0, 0, 0, 0, 0},{  0, 0, 0, 0, 0},{  0, 0, 0, 0, 0},{  0, 0, 0, 0, 0},{  0, 0, 0, 0, 0},
    } };


    void buildMod3Table()
    {
        std::array<u32, 256> ret;
        u64 m = 243;
        u64 s = 5;
        u32 vals[5];
        for (u64 j = 0; j < s; ++j)
            vals[j] = 0;
        for (u64 i = 0; i < 256; ++i)
        {
            if (i < m)
            {
                u32 lsb = 0;
                u32 msb = 0;

                for (u64 j = 0; j < s; ++j)
                {
                    auto lsbj = vals[j] & 1;
                    auto msbj = (vals[j] >> 1) & 1;
                    lsb |= lsbj << j;
                    msb |= msbj << j;
                    //std::cout << vals[j] << "(" <<msbj<<"" << lsbj << "), ";
                }
                ret[i] = ((1 << 16) + (msb << 8) + lsb);

                ++vals[0];
                for (u64 j = 0; j < s; ++j)
                {
                    if (vals[j] == 3 && j != s - 1)
                        vals[j + 1]++;
                    vals[j] = vals[j] % 3;
                }

            }
            else
            {
                ret[i] = 0;
                //std::cout << "0," << std::endl;
            }

            std::cout << "0x" << std::hex << ret[i] << ",";
            if (i % 8 == 0)
                std::cout << std::endl;
        }
        //return ret;
    };


    void buildMod3Table2()
    {
        std::array<u32, 256> ret;
       u64 m = 243;
       u64 s = 5;
        u32 vals[5];
        for (u64 j = 0; j < s; ++j)
            vals[j] = 0;

        std::cout << "const std::array<u32, 256> mod3TableV { {\n";
        for (u64 i = 0; i < 256; ++i)
        {
            if (i < m)
                std::cout << "5,";
            else
                std::cout << "0,";

            if (i % 8 == 7)
                std::cout << std::endl;
        }
        std::cout << "}};\n\n";


        for (u64 l = 0; l < 3; ++l)
        {
            if (l == 0)
                std::cout << "const std::array<u32, 256> mod3TableLsb { {\n";
            else if (l == 1)
                std::cout << "const std::array<u32, 256> mod3TableMsb {{ \n";
            else
                std::cout << "const std::array<std::array<u8, 5>, 256> mod3TableFull {{ \n";

            //char delim = ' ';
            for (u64 i = 0; i < 256; ++i)
            {
                if (i < m)
                {
                    u32 lsb = 0;
                    u32 msb = 0;

                    for (u64 j = 0; j < s; ++j)
                    {
                        auto lsbj = vals[j] & 1;
                        auto msbj = (vals[j] >> 1) & 1;
                        lsb |= lsbj << j;
                        msb |= msbj << j;
                        //std::cout << vals[j] << "(" <<msbj<<"" << lsbj << "), ";
                    }

                    if (l == 0)
                        ret[i] = lsb;
                    else if (l == 1)
                        ret[i] = msb;


                    if (l == 2)
                    {
                        std::cout << "{";
                        char d = ' ';
                        for (u64 j = 0; j < s; ++j)
                        {
                            std::cout << std::exchange(d, ',') << ' ' << vals[j];
                        }
                        std::cout << "},";
                    }
                    else
                    {
                        oc::BitVector vv((u8*)&ret[i], 5);
                        std::cout << " 0b" << vv[4] << vv[3] << vv[2] << vv[1] << vv[0] << ",";
                    }
                    //ret[i] = ((1 << 16) + (msb << 8) + lsb);

                    ++vals[0];
                    for (u64 j = 0; j < s; ++j)
                    {
                        if (vals[j] == 3 && j != s - 1)
                            vals[j + 1]++;
                        vals[j] = vals[j] % 3;
                    }

                }
                else
                {
                    ret[i] = 0;
                    //std::cout << "0," << std::endl;
                    if (l < 2)
                        std::cout << " 0b00000,";
                    else
                    {
                        std::cout << "{  0, 0, 0, 0, 0},";
                    }
                }


                if (i % 8 == 7)
                    std::cout << std::endl;

            }

            std::cout << "}};\n\n" << std::dec;
        }
        //return ret;
    };


    //void buildMod3Table4()
    //{
    //    //std::array<u32, 256> ret;
    //    auto m = 27;
    //    auto s = 3;
    //    u32 vals[3];
    //    for (u64 j = 0; j < s; ++j)
    //        vals[j] = 0;

    //    u64 sum[2];
    //    sum[0] = 0;
    //    sum[1] = 0;

    //    for (u64 i = 0; i < m; ++i)
    //    {
    //        sum[i / 16] += 3ull << (i * 4);
    //    }
    //    std::cout << "block validTable( " << sum[1] << "," << sum[0] << ");" << std::endl;

    //    for (u64 l = 0; l < 2; ++l)
    //    {

    //        sum[0] = 0;
    //        sum[1] = 0;
    //        for (u64 i = 0; i < m; ++i)
    //        {
    //            u64 lsb = 0;
    //            u64 msb = 0;

    //            for (u64 j = 0; j < s; ++j)
    //            {
    //                auto lsbj = vals[j] & 1;
    //                auto msbj = (vals[j] >> 1) & 1;
    //                lsb |= lsbj << j;
    //                msb |= msbj << j;
    //                //std::cout << vals[j] << "(" <<msbj<<"" << lsbj << "), ";
    //            }
    //            if (l == 0)
    //                sum[i / 16] += lsb << (i * 4);
    //            else
    //                sum[i / 16] += msb << (i * 4);


    //            ++vals[0];
    //            for (u64 j = 0; j < s; ++j)
    //            {
    //                if (vals[j] == 3 && j != s - 1)
    //                    vals[j + 1]++;
    //                vals[j] = vals[j] % 3;
    //            }
    //        }

    //        if (l == 0)
    //            std::cout << "block lsbTable(";
    //        else
    //            std::cout << "block msbTable(";
    //        std::cout << sum[1] << "," << sum[0] << ");" << std::endl;
    //    }
    //    //return ret;
    //};



    void sampleMod3Lookup(PRNG& prng, span<block> msb, span<block> lsb)
    {
        u64 n = msb.size() * 128;
        auto msbIter = (u64*)msb.data();
        auto lsbIter = (u64*)lsb.data();
        span<u8> rands = prng.getBufferSpan(256);
        u64 rIdx = 0;
        u64 e = rands.size();
        for (u64 i = 0; i < n; i += 64)
        {
            u64 lsb = 0, msb = 0;
            u64 j = 0;
            while (j < 64)
            {
                if (rIdx == e)
                {
                    rands = prng.getBufferSpan(256);
                    rIdx = 0;
                    e = rands.size();
                }
                auto b = rands.data()[rIdx++];
                //auto b = prng.get<u8>();
                auto v = mod3Table[b];
                auto lsbj = v & 255ull;
                auto msbj = (v >> 8) & 255ull;
                auto flag = v >> 16;
                //__assume(flag <= 1);
                lsb |= lsbj << j;
                msb |= msbj << j;
                j += flag * 5;
            }
            *lsbIter++ = lsb;
            *msbIter++ = msb;
        }
    }

    //void sampleMod3Lookup2(PRNG& prng, span<block> msbVec, span<block> lsbVec)
    //{

    //    if (msbVec.size() & 1)
    //        throw RTE_LOC;// must have even size.
    //    if ((u64)msbVec.data() % 32)
    //        throw RTE_LOC;// must be aligned.
    //    if ((u64)lsbVec.data() % 32)
    //        throw RTE_LOC;// must be aligned.



    //    u64 n = msbVec.size() / 2;
    //    auto msbIter = (__m256i*)msbVec.data();
    //    auto lsbIter = (__m256i*)lsbVec.data();

    //    oc::AlignedArray<block, 128> rands;
    //    prng.mAes.ecbEncCounterMode(prng.mBlockIdx, rands.size(), rands.data());
    //    prng.mBlockIdx += rands.size();

    //    u8* randsPtr = (u8*)rands.data();
    //    auto e = (u8*)(rands.data() + rands.size());
    //    //span<u8> rands = prng.getBufferSpan(256);

    //    //u64 rIdx = 0;
    //    oc::AlignedArray<__m256i, 4> lsb;// = _mm256_setzero_si256();
    //    oc::AlignedArray<__m256i, 4> msb;// = _mm256_setzero_si256();
    //    oc::AlignedArray<__m256i, 4> size, v_, lsb_, msb_;// = _mm256_setzero_si256();

    //    for (u64 i = 0; i < n; i += lsb.size())
    //    {
    //        for (u64 k = 0; k < lsb.size(); ++k)
    //        {
    //            lsb[k] = _mm256_setzero_si256();
    //            msb[k] = _mm256_setzero_si256();
    //            size[k] = _mm256_setzero_si256();
    //        }

    //        for (u64 k = 0; k < 14; ++k)
    //        {
    //            for (u64 j = 0; j < lsb.size(); ++j)
    //            {

    //                if (randsPtr + 4 > e)
    //                {
    //                    prng.mAes.ecbEncCounterMode(prng.mBlockIdx, rands.size(), rands.data());
    //                    prng.mBlockIdx += rands.size();
    //                    randsPtr = (u8*)rands.data();
    //                }

    //                v_[j] = _mm256_set_epi64x(
    //                    mod3TableV.data()[randsPtr[3]],
    //                    mod3TableV.data()[randsPtr[2]],
    //                    mod3TableV.data()[randsPtr[1]],
    //                    mod3TableV.data()[randsPtr[0]]);
    //                lsb_[j] = _mm256_set_epi64x(
    //                    mod3TableLsb.data()[randsPtr[3]],
    //                    mod3TableLsb.data()[randsPtr[2]],
    //                    mod3TableLsb.data()[randsPtr[1]],
    //                    mod3TableLsb.data()[randsPtr[0]]);
    //                msb_[j] = _mm256_set_epi64x(
    //                    mod3TableMsb.data()[randsPtr[3]],
    //                    mod3TableMsb.data()[randsPtr[2]],
    //                    mod3TableMsb.data()[randsPtr[1]],
    //                    mod3TableMsb.data()[randsPtr[0]]);

    //                randsPtr += 4;
    //                //lsb[j] = _mm256_sllv_epi64(lsb[j], v_[j]);
    //                //lsb_[j] = _mm256_srlv_epi64(lsb_[j], v_[j]);
    //                //lsb[j] = _mm256_or_si256(lsb[j], lsb_[j]);

    //                //msb[j] = _mm256_sllv_epi64(msb[j], v_[j]);
    //                //msb_[j] = _mm256_srlv_epi64(msb_[j], v_[j]);
    //                //msb[j] = _mm256_or_si256(msb[j], msb_[j]);

    //                //size[j] = _mm256_add_epi64(size[j], v_[j]);
    //            }

    //            lsb[0] = _mm256_sllv_epi64(lsb[0], v_[0]);
    //            lsb[1] = _mm256_sllv_epi64(lsb[1], v_[1]);
    //            lsb[2] = _mm256_sllv_epi64(lsb[2], v_[2]);
    //            lsb[3] = _mm256_sllv_epi64(lsb[3], v_[3]);
    //            //lsb[4] = _mm256_sllv_epi64(lsb[4], v_[4]);
    //            //lsb[5] = _mm256_sllv_epi64(lsb[5], v_[5]);
    //            //lsb[6] = _mm256_sllv_epi64(lsb[6], v_[6]);
    //            //lsb[7] = _mm256_sllv_epi64(lsb[7], v_[7]);

    //            lsb_[0] = _mm256_srlv_epi64(lsb_[0], v_[0]);
    //            lsb_[1] = _mm256_srlv_epi64(lsb_[1], v_[1]);
    //            lsb_[2] = _mm256_srlv_epi64(lsb_[2], v_[2]);
    //            lsb_[3] = _mm256_srlv_epi64(lsb_[3], v_[3]);
    //            //lsb_[4] = _mm256_srlv_epi64(lsb_[4], v_[4]);
    //            //lsb_[5] = _mm256_srlv_epi64(lsb_[5], v_[5]);
    //            //lsb_[6] = _mm256_srlv_epi64(lsb_[6], v_[6]);
    //            //lsb_[7] = _mm256_srlv_epi64(lsb_[7], v_[7]);

    //            lsb[0] = _mm256_or_si256(lsb[0], lsb_[0]);
    //            lsb[1] = _mm256_or_si256(lsb[1], lsb_[1]);
    //            lsb[2] = _mm256_or_si256(lsb[2], lsb_[2]);
    //            lsb[3] = _mm256_or_si256(lsb[3], lsb_[3]);
    //            //lsb[4] = _mm256_or_si256(lsb[4], lsb_[4]);
    //            //lsb[5] = _mm256_or_si256(lsb[5], lsb_[5]);
    //            //lsb[6] = _mm256_or_si256(lsb[6], lsb_[6]);
    //            //lsb[7] = _mm256_or_si256(lsb[7], lsb_[7]);

    //            msb[0] = _mm256_sllv_epi64(msb[0], v_[0]);
    //            msb[1] = _mm256_sllv_epi64(msb[1], v_[1]);
    //            msb[2] = _mm256_sllv_epi64(msb[2], v_[2]);
    //            msb[3] = _mm256_sllv_epi64(msb[3], v_[3]);
    //            //msb[4] = _mm256_sllv_epi64(msb[4], v_[4]);
    //            //msb[5] = _mm256_sllv_epi64(msb[5], v_[5]);
    //            //msb[6] = _mm256_sllv_epi64(msb[6], v_[6]);
    //            //msb[7] = _mm256_sllv_epi64(msb[7], v_[7]);

    //            msb_[0] = _mm256_srlv_epi64(msb_[0], v_[0]);
    //            msb_[1] = _mm256_srlv_epi64(msb_[1], v_[1]);
    //            msb_[2] = _mm256_srlv_epi64(msb_[2], v_[2]);
    //            msb_[3] = _mm256_srlv_epi64(msb_[3], v_[3]);
    //            //msb_[4] = _mm256_srlv_epi64(msb_[4], v_[4]);
    //            //msb_[5] = _mm256_srlv_epi64(msb_[5], v_[5]);
    //            //msb_[6] = _mm256_srlv_epi64(msb_[6], v_[6]);
    //            //msb_[7] = _mm256_srlv_epi64(msb_[7], v_[7]);

    //            msb[0] = _mm256_or_si256(msb[0], msb_[0]);
    //            msb[1] = _mm256_or_si256(msb[1], msb_[1]);
    //            msb[2] = _mm256_or_si256(msb[2], msb_[2]);
    //            msb[3] = _mm256_or_si256(msb[3], msb_[3]);
    //            //msb[4] = _mm256_or_si256(msb[4], msb_[4]);
    //            //msb[5] = _mm256_or_si256(msb[5], msb_[5]);
    //            //msb[6] = _mm256_or_si256(msb[6], msb_[6]);
    //            //msb[7] = _mm256_or_si256(msb[7], msb_[7]);

    //            size[0] = _mm256_add_epi64(size[0], v_[0]);
    //            size[1] = _mm256_add_epi64(size[1], v_[1]);
    //            size[2] = _mm256_add_epi64(size[2], v_[2]);
    //            size[3] = _mm256_add_epi64(size[3], v_[3]);
    //            //size[4] = _mm256_add_epi64(size[4], v_[4]);
    //            //size[5] = _mm256_add_epi64(size[5], v_[5]);
    //            //size[6] = _mm256_add_epi64(size[6], v_[6]);
    //            //size[7] = _mm256_add_epi64(size[7], v_[7]);

    //        }

    //        u64 sizes[4];
    //        for (u64 j = 0; j < lsb.size(); ++j)
    //        {
    //            memcpy(sizes, &size[j], 4 * sizeof(u64));

    //            for (u64 k = 0; k < 4; ++k)
    //            {

    //                auto& lsbk = lsb[j].m256i_u64[k];
    //                auto& msbk = msb[j].m256i_u64[k];

    //                while (sizes[k] < 64)
    //                {
    //                    if (randsPtr == e)
    //                    {
    //                        prng.mAes.ecbEncCounterMode(prng.mBlockIdx, rands.size(), rands.data());
    //                        prng.mBlockIdx += rands.size();
    //                        randsPtr = (u8*)rands.data();
    //                    }

    //                    auto b = *randsPtr++;
    //                    auto v = mod3Table[b];
    //                    auto lsbj = v & 255ull;
    //                    auto msbj = (v >> 8) & 255ull;
    //                    auto flag = 5 * (v >> 16);
    //                    lsbk = lsbk << flag | lsbj;
    //                    msbk = msbk << flag | msbj;

    //                    sizes[k] += flag;
    //                }

    //                //*lsbIter++ = lsbk;
    //                //*msbIter++ = msbk;
    //            }
    //        }

    //        auto s = std::min<u64>(n - i, lsb.size());
    //        for (u64 j = 0; j < s; ++j)
    //        {
    //            _mm256_store_si256(lsbIter, lsb[j]);
    //            _mm256_store_si256(msbIter, msb[j]);
    //            ++lsbIter;
    //            ++msbIter;
    //        }

    //    }
    //}


    void sampleMod3Lookup3(PRNG& prng, span<block> msbVec, span<block> lsbVec)
    {
        //if ((u64)msbVec.data() % 32)
        //    throw RTE_LOC;// must be aligned.
        //if ((u64)lsbVec.data() % 32)
        //    throw RTE_LOC;// must be aligned.
        if(msbVec.size() != lsbVec.size())
            throw RTE_LOC;// must have same size.

        u64 n = msbVec.size();
        auto msbIter = (block*)msbVec.data();
        auto lsbIter = (block*)lsbVec.data();

        oc::AlignedArray<block, 128> rands;
        oc::AlignedArray<block, 8> rands2;

        auto e = (__m256i*)(rands.data() + rands.size());
        auto e2 = (u8*)(rands2.data() + rands2.size());
        auto randsPtr = e;
        u8* rands2Ptr = e2;

        oc::AlignedArray<__m256i, 4> lsbSum;
        oc::AlignedArray<__m256i, 4> msbSum;
        oc::AlignedArray<__m256i, 4> size, v_, lsb_, msb_;

        for (u64 i = 0; i < n; i += lsbSum.size() * 2)
        {
            for (u64 k = 0; k < lsbSum.size(); ++k)
            {
                lsbSum[k] = _mm256_setzero_si256();
                msbSum[k] = _mm256_setzero_si256();
                size[k] = _mm256_setzero_si256();
            }

            for (u64 k = 0; k < 8; ++k)
            {
                if (randsPtr >= e)
                {
                    prng.mAes.ecbEncCounterMode(prng.mBlockIdx, rands.size(), rands.data());
                    prng.mBlockIdx += rands.size();
                    randsPtr = (__m256i*)rands.data();
                }

                __m256i indexBase = _mm256_load_si256(randsPtr);
                for (u64 j = 0; j < lsbSum.size(); ++j)
                {
                    auto indexes = _mm256_and_si256(indexBase, _mm256_set1_epi32(255));
                    indexBase = _mm256_srli_epi32(indexBase, 8);

                    //__m256i indexes = _mm256_set_epi32(
                    //    randsPtr->m256i_u8[j * 8 + 7],
                    //    randsPtr->m256i_u8[j * 8 + 6],
                    //    randsPtr->m256i_u8[j * 8 + 5],
                    //    randsPtr->m256i_u8[j * 8 + 4],
                    //    randsPtr->m256i_u8[j * 8 + 3],
                    //    randsPtr->m256i_u8[j * 8 + 2],
                    //    randsPtr->m256i_u8[j * 8 + 1],
                    //    randsPtr->m256i_u8[j * 8 + 0]
                    //);

                    v_[j] = _mm256_i32gather_epi32((const i32*)mod3TableV.data(), indexes, 4);
                    lsb_[j] = _mm256_i32gather_epi32((const i32*)mod3TableLsb.data(), indexes, 4);
                    msb_[j] = _mm256_i32gather_epi32((const i32*)mod3TableMsb.data(), indexes, 4);
                }
                randsPtr++;

                // shift the sum if we have a valid sample
                lsbSum[0] = _mm256_sllv_epi32(lsbSum[0], v_[0]);
                lsbSum[1] = _mm256_sllv_epi32(lsbSum[1], v_[1]);
                lsbSum[2] = _mm256_sllv_epi32(lsbSum[2], v_[2]);
                lsbSum[3] = _mm256_sllv_epi32(lsbSum[3], v_[3]);

                // 0 if there is overlap
                assert(_mm256_testz_si256(lsbSum[0], lsb_[0]));
                assert(_mm256_testz_si256(lsbSum[1], lsb_[1]));
                assert(_mm256_testz_si256(lsbSum[2], lsb_[2]));
                assert(_mm256_testz_si256(lsbSum[3], lsb_[3]));


                // add in the new sample
                lsbSum[0] = _mm256_or_si256(lsbSum[0], lsb_[0]);
                lsbSum[1] = _mm256_or_si256(lsbSum[1], lsb_[1]);
                lsbSum[2] = _mm256_or_si256(lsbSum[2], lsb_[2]);
                lsbSum[3] = _mm256_or_si256(lsbSum[3], lsb_[3]);

                // shift the sum if we have a valid sample
                msbSum[0] = _mm256_sllv_epi32(msbSum[0], v_[0]);
                msbSum[1] = _mm256_sllv_epi32(msbSum[1], v_[1]);
                msbSum[2] = _mm256_sllv_epi32(msbSum[2], v_[2]);
                msbSum[3] = _mm256_sllv_epi32(msbSum[3], v_[3]);

                // add in the new sample
                msbSum[0] = _mm256_or_si256(msbSum[0], msb_[0]);
                msbSum[1] = _mm256_or_si256(msbSum[1], msb_[1]);
                msbSum[2] = _mm256_or_si256(msbSum[2], msb_[2]);
                msbSum[3] = _mm256_or_si256(msbSum[3], msb_[3]);

                // 0 if there is overlap
                assert(_mm256_testz_si256(lsbSum[0], msb_[0]));
                assert(_mm256_testz_si256(lsbSum[1], msb_[1]));
                assert(_mm256_testz_si256(lsbSum[2], msb_[2]));
                assert(_mm256_testz_si256(lsbSum[3], msb_[3]));

                // add the size
                size[0] = _mm256_add_epi32(size[0], v_[0]);
                size[1] = _mm256_add_epi32(size[1], v_[1]);
                size[2] = _mm256_add_epi32(size[2], v_[2]);
                size[3] = _mm256_add_epi32(size[3], v_[3]);
            }

            for (u64 j = 0; j < lsbSum.size(); ++j)
            {

                for (u64 k = 0; k < 8; ++k)
                {
                    u32* lsbSum32 = (u32*)&lsbSum[j];
                    u32* msbSum32 = (u32*)&msbSum[j];
                    u32* size32 = (u32*)&size[j];

                    auto& lsbk = lsbSum32[k];
                    auto& msbk = msbSum32[k];
                    auto& sizek = size32[k];

                    while (sizek < 32)
                    {
                        if (rands2Ptr == e2)
                        {
                            prng.mAes.ecbEncCounterMode(prng.mBlockIdx, rands2.size(), rands2.data());
                            prng.mBlockIdx += rands2.size();
                            rands2Ptr = (u8*)rands2.data();
                        }

                        auto b = *rands2Ptr++;
                        auto v = mod3Table[b];

                        auto lsbj = v & 255ull;
                        auto msbj = (v >> 8) & 255ull;
                        auto flag = 5 * (v >> 16);
                        lsbk = (lsbk << flag) | lsbj;
                        msbk = (msbk << flag) | msbj;

                        sizek += flag;
                    }
                }
            }

            auto s = std::min<u64>(msbVec.size() - i, lsbSum.size() * 2);
            assert(lsbIter + s <= lsbVec.data() + lsbVec.size());
            assert(msbIter + s <= msbVec.data() + msbVec.size());
            memcpy(lsbIter, lsbSum.data(), s * sizeof(__m128i));
            memcpy(msbIter, msbSum.data(), s * sizeof(__m128i));
            lsbIter += s;
            msbIter += s;

            //for (u64 j = 0; j < s; ++j)
            //{
            //    _mm256_store_si256(lsbIter, lsbSum[j]);
            //    _mm256_store_si256(msbIter, msbSum[j]);
            //    ++lsbIter;
            //    ++msbIter;
            //}
        }
    }


    void sampleMod3Lookup5(PRNG& prng, span<block> msbVec, span<block> lsbVec)
    {
        if (msbVec.size() & 1)
            throw RTE_LOC;// must have even size.
        if ((u64)msbVec.data() % 32)
            throw RTE_LOC;// must be aligned.
        if ((u64)lsbVec.data() % 32)
            throw RTE_LOC;// must be aligned.


        u64 n = msbVec.size() / 2;
        auto msbIter = (__m256i*)msbVec.data();
        auto lsbIter = (__m256i*)lsbVec.data();

        oc::AlignedArray<block, 128> rands;
        prng.mAes.ecbEncCounterMode(prng.mBlockIdx, rands.size(), rands.data());
        prng.mBlockIdx += rands.size();

        u8* randsPtr = (u8*)rands.data();
        auto e = (u8*)(rands.data() + rands.size());

        oc::AlignedArray<__m256i, 4> lsb;
        oc::AlignedArray<__m256i, 4> msb;
        oc::AlignedArray<__m256i, 4> size, v_, lsb_, msb_;

        for (u64 i = 0; i < n; i += lsb.size())
        {
            for (u64 k = 0; k < lsb.size(); ++k)
            {
                lsb[k] = _mm256_setzero_si256();
                msb[k] = _mm256_setzero_si256();
                size[k] = _mm256_setzero_si256();
            }

            for (u64 k = 0; k < 8; ++k)
            {
                if (randsPtr + 8 * lsb.size() > e)
                {
                    prng.mAes.ecbEncCounterMode(prng.mBlockIdx, rands.size(), rands.data());
                    prng.mBlockIdx += rands.size();
                    randsPtr = (u8*)rands.data();
                }

                for (u64 j = 0; j < lsb.size(); ++j)
                {
                    auto indexes = _mm256_set_epi32(
                        randsPtr[7],
                        randsPtr[6],
                        randsPtr[5],
                        randsPtr[4],
                        randsPtr[3],
                        randsPtr[2],
                        randsPtr[1],
                        randsPtr[0]);

                    v_[j] = _mm256_i32gather_epi32((const i32*)mod3TableV.data(), indexes, 4);
                    lsb_[j] = _mm256_i32gather_epi32((const i32*)mod3TableLsb.data(), indexes, 4);
                    msb_[j] = _mm256_i32gather_epi32((const i32*)mod3TableMsb.data(), indexes, 4);
                    randsPtr += 8;
                }

                lsb[0] = _mm256_sllv_epi32(lsb[0], v_[0]);
                lsb[1] = _mm256_sllv_epi32(lsb[1], v_[1]);
                lsb[2] = _mm256_sllv_epi32(lsb[2], v_[2]);
                lsb[3] = _mm256_sllv_epi32(lsb[3], v_[3]);

                lsb_[0] = _mm256_srlv_epi32(lsb_[0], v_[0]);
                lsb_[1] = _mm256_srlv_epi32(lsb_[1], v_[1]);
                lsb_[2] = _mm256_srlv_epi32(lsb_[2], v_[2]);
                lsb_[3] = _mm256_srlv_epi32(lsb_[3], v_[3]);

                lsb[0] = _mm256_or_si256(lsb[0], lsb_[0]);
                lsb[1] = _mm256_or_si256(lsb[1], lsb_[1]);
                lsb[2] = _mm256_or_si256(lsb[2], lsb_[2]);
                lsb[3] = _mm256_or_si256(lsb[3], lsb_[3]);

                msb[0] = _mm256_sllv_epi32(msb[0], v_[0]);
                msb[1] = _mm256_sllv_epi32(msb[1], v_[1]);
                msb[2] = _mm256_sllv_epi32(msb[2], v_[2]);
                msb[3] = _mm256_sllv_epi32(msb[3], v_[3]);

                msb_[0] = _mm256_srlv_epi32(msb_[0], v_[0]);
                msb_[1] = _mm256_srlv_epi32(msb_[1], v_[1]);
                msb_[2] = _mm256_srlv_epi32(msb_[2], v_[2]);
                msb_[3] = _mm256_srlv_epi32(msb_[3], v_[3]);

                msb[0] = _mm256_or_si256(msb[0], msb_[0]);
                msb[1] = _mm256_or_si256(msb[1], msb_[1]);
                msb[2] = _mm256_or_si256(msb[2], msb_[2]);
                msb[3] = _mm256_or_si256(msb[3], msb_[3]);

                size[0] = _mm256_add_epi32(size[0], v_[0]);
                size[1] = _mm256_add_epi32(size[1], v_[1]);
                size[2] = _mm256_add_epi32(size[2], v_[2]);
                size[3] = _mm256_add_epi32(size[3], v_[3]);
            }

            //u32 sizes[8];
            for (u64 j = 0; j < lsb.size(); ++j)
            {
                //memcpy(sizes, &size[j], 8 * sizeof(u32));

                for (u64 k = 0; k < 8; ++k)
                {

                    u32* lsbSum32 = (u32*)&lsb[j];
                    u32* msbSum32 = (u32*)&msb[j];
                    u32* size32 = (u32*)&size[j];

                    auto& lsbk = lsbSum32[k];
                    auto& msbk = msbSum32[k];
                    auto& sizek = size32[k];
                    //auto& lsbk = lsb[j].m256i_u32[k];
                    //auto& msbk = msb[j].m256i_u32[k];
                    //auto& sizek = size[j].m256i_u32[k];
                    while (sizek < 32)
                    {
                        if (randsPtr == e)
                        {
                            prng.mAes.ecbEncCounterMode(prng.mBlockIdx, rands.size(), rands.data());
                            prng.mBlockIdx += rands.size();
                            randsPtr = (u8*)rands.data();
                        }

                        auto b = *randsPtr++;
                        auto v = mod3Table[b];
                        auto lsbj = v & 255ull;
                        auto msbj = (v >> 8) & 255ull;
                        auto flag = 5 * (v >> 16);
                        lsbk = lsbk << flag | lsbj;
                        msbk = msbk << flag | msbj;

                        sizek += flag;
                    }
                }
            }

            auto s = std::min<u64>(n - i, lsb.size());
            for (u64 j = 0; j < s; ++j)
            {
                _mm256_store_si256(lsbIter, lsb[j]);
                _mm256_store_si256(msbIter, msb[j]);
                ++lsbIter;
                ++msbIter;
            }

        }
    }


    std::string v4(block b)
    {
        std::stringstream ss;
        for (u64 i = 15; i < 16; --i)
        {
            for (u64 j = 1; j < 2; --j)
            {
                ss << (int)(b.get<u8>(i) >> (j * 4) & 0xF) << ", ";
            }
        }
        return ss.str();
    }
    std::string v32(block b)
    {
        std::stringstream ss;
        for (u64 i = 3; i < 4; --i)
        {
            ss << b.get<u32>(i) << ", ";
        }
        return ss.str();
    }

    std::string v8(block b)
    {
        std::stringstream ss;
        for (u64 i = 15; i < 16; --i)
        {
            ss << std::setw(3) << std::setfill(' ') << (int)b.get<u8>(i) << ", ";
        }
        return ss.str();
    }

    std::string vi8(block b)
    {
        std::stringstream ss;
        for (u64 i = 15; i < 16; --i)
        {
            ss << std::setw(3) << std::setfill(' ') << (int)b.get<i8>(i) << ", ";
        }
        return ss.str();
    }

//    void sampleMod3Lookup4(PRNG& prng, span<block> msbVec, span<block> lsbVec)
//    {
//
//        if (msbVec.size() & 1)
//            throw RTE_LOC;// must have even size.
//        if ((u64)msbVec.data() % 32)
//            throw RTE_LOC;// must be aligned.
//        if ((u64)lsbVec.data() % 32)
//            throw RTE_LOC;// must be aligned.
//#define SIMD(X)for (u64 X = 0; X< 8; ++X)
//
//
//        u64 n = msbVec.size();
//        auto msbIter = (__m128i*)msbVec.data();
//        auto lsbIter = (__m128i*)lsbVec.data();
//
//        oc::AlignedArray<block, 128> rands, rands2;
//        prng.mAes.ecbEncCounterMode(prng.mBlockIdx, rands.size(), rands.data());
//        prng.mBlockIdx += rands.size();
//        prng.mAes.ecbEncCounterMode(prng.mBlockIdx, rands2.size(), rands2.data());
//        prng.mBlockIdx += rands2.size();
//
//        auto randsPtr = rands.data();
//        auto rands2Ptr = (u8*)rands.data();
//        auto e = (rands.data() + rands.size());
//        auto e2 = (u8*)(rands2.data() + rands2.size());
//
//        // each byte containst two 3 bit samples. One in the lower
//        // nibble and one in the upper nibble. valid denotes if 
//        // there us a sample and takes n the value zero or three. 
//        // If a sample is valid (idx < 27), then either the lower or upper
//        // nibble is used to store the lsb and msb based on the parity of idx
//        block validTable(3518437208883, 3689348814741910323);
//        block lsbTable(69308780613, 5077321771357773840);
//        block msbTable(8136081884210, 2377918208894042368);
//        __m128i shifts[4];
//        shifts[0] = _mm_set1_epi32(0);
//        shifts[1] = _mm_set1_epi32(8);
//        shifts[2] = _mm_set1_epi32(16);
//        shifts[3] = _mm_set1_epi32(24);
//
//        for (u64 i = 0; i < 32; ++i)
//        {
//            auto vp = (u8*)&validTable;
//            auto lp = (u8*)&lsbTable;
//            auto mp = (u8*)&msbTable;
//
//            auto v = vp[i / 2] >> (4 * (i % 2));
//            auto l = lp[i / 2] >> (4 * (i % 2));
//            auto m = mp[i / 2] >> (4 * (i % 2));
//
//            if (i < 27)
//            {
//                assert(v);
//            }
//            std::array<int, 4> vals;
//            for (u64 j = 0; j < 4; ++j)
//            {
//                vals[j] = (l >> j) & 1 + ((m >> j) & 1) * 2;
//                assert(vals[j] < 3);
//            }
//        }
//
//        for (u64 i = 0; i < n; i += 8)
//        {
//
//            __m128i counts[8];// = _mm_setzero_si128();
//            __m128i lsbs[8];//= _mm_setzero_si128();
//            __m128i msbs[8];//= _mm_setzero_si128();
//
//            memset(counts, 0, sizeof(counts));
//            memset(lsbs, 0, sizeof(lsbs));
//            memset(msbs, 0, sizeof(msbs));
//
//            for (u64 tt = 0; tt < 3; ++tt)
//            {
//
//                if (randsPtr + 2 > e)
//                {
//                    prng.mAes.ecbEncCounterMode(prng.mBlockIdx, rands.size(), rands.data());
//                    prng.mBlockIdx += rands.size();
//                    randsPtr = rands.data();
//                }
//
//
//                //__m128i r_[8], b_[8];
//                //SIMD(j) r_[j] = _mm_load_si128((__m128i*)randsPtr++);
//                //SIMD(j) b_[j] = _mm_load_si128((__m128i*)randsPtr++);
//
//                //for (u64 t = 0; t < 2; ++t)
//                {
//                    __m128i bits[8], shft[8];
//                    //__m128i msb[8];
//                    __m128i vlds[8];
//                    __m128i vldsX[4][8];
//                    __m128i r[8], b[8];
//
//                    // the top and bottom 4 bits of each byte are used 
//                    // to sampled an mod 16 index.
//                    // we pack two samples in each byte. b is used to 
//                    // select which sample to use.
//                    //if (t)
//                    //{
//                    //    SIMD(j) r[j] = _mm_and_si128(r_[j], _mm_set1_epi8(0xF));
//                    //    SIMD(j) b[j] = b_[j];
//                    //}
//                    //else
//                    //{
//                    //    SIMD(j) r[j] = _mm_srli_epi16(r_[j], 4);
//                    //    SIMD(j) r[j] = _mm_and_si128(r_[j], _mm_set1_epi8(0xF));
//                    //    SIMD(j) b[j] = _mm_slli_epi16(b_[j], 1);
//                    //}
//
//                    SIMD(j) r[j] = _mm_load_si128((__m128i*)randsPtr++);
//                    SIMD(j) b[j] = _mm_load_si128((__m128i*)randsPtr++);
//
//                    SIMD(j) r[j] = _mm_and_si128(r[j], _mm_set1_epi8(31));
//                    SIMD(j) b[j] = _mm_and_si128(b[j], _mm_set1_epi8(31));
//
//                    //std::cout << "r0 " << v8(r[0]) << std::endl;
//                    //std::cout << "r1 " << v8(b[0]) << std::endl;
//
//                    // if r < 27, we take r, else we take b.
//                    SIMD(j) shft[j] = _mm_sub_epi8(r[j], _mm_set1_epi8(27));
//                    SIMD(j) r[j] = _mm_blendv_epi8(b[j], r[j], shft[j]);
//
//                    //std::cout << "s  " << vi8(shft[0]) << std::endl;
//                    //std::cout << "r  " << v8(r[0]) << std::endl;
//
//
//                    // b is the lsb of the index.
//                    // r is the rest.
//                    SIMD(j) b[j] = _mm_and_si128(r[j], _mm_set1_epi8(1));
//                    SIMD(j) r[j] = _mm_srli_epi16(r[j], 1);
//                    SIMD(j) r[j] = _mm_and_si128(r[j], _mm_set1_epi8(15));
//
//
//
//                    // use the index to sample the lsb, msb, and valid flag.
//                    SIMD(k) vlds[k] = _mm_shuffle_epi8(validTable, r[k]);
//                    SIMD(k) shft[k] = _mm_slli_epi16(vlds[k], 4);
//                    SIMD(k) vlds[k] = _mm_blendv_epi8(vlds[k], shft[k], b[k]);
//                    SIMD(k) vlds[k] = _mm_and_si128(vlds[k], _mm_set1_epi8(0xF));
//
//                    //std::cout << "vlds: " << v8(vlds[0]) << std::endl;
//
//                    // use the index to sample the lsb, msb, and valid flag.
//                    SIMD(k) bits[k] = _mm_shuffle_epi8(lsbTable, r[k]);
//                    SIMD(k) shft[k] = _mm_slli_epi16(bits[k], 4);
//                    SIMD(k) bits[k] = _mm_blendv_epi8(bits[k], shft[k], b[k]);
//                    //std::cout << "lsb: " << nibbles(bits[0]) << std::endl;
//
//                    for (u64 h = 0; h < 4; ++h)
//                    {
//
//                        SIMD(k) vldsX[h][k] = _mm_srav_epi32(vlds[k], shifts[h]);
//                        SIMD(k) vldsX[h][k] = _mm_and_si128(vldsX[h][k], _mm_set1_epi32(255));
//
//                        SIMD(k) counts[k] = _mm_add_epi32(counts[k], vldsX[h][k]);
//                        //std::cout << "vlds "<<h<<": " << v32(vldsX[h][0]) << std::endl;
//
//                        SIMD(k) shft[k] = _mm_srav_epi32(bits[k], shifts[h]);
//                        SIMD(k) shft[k] = _mm_and_si128(bits[k], _mm_set1_epi32(255));
//
//                        SIMD(k) lsbs[k] = _mm_srlv_epi32(lsbs[k], vldsX[h][k]);
//                        SIMD(k) lsbs[k] = _mm_or_si128(lsbs[k], shft[k]);
//
//
//                    }
//
//
//                    // use the index to sample the lsb, msb, and valid flag.
//                    SIMD(k) bits[k] = _mm_shuffle_epi8(msbTable, r[k]);
//                    SIMD(k) shft[k] = _mm_slli_epi16(bits[k], 4);
//                    SIMD(k) bits[k] = _mm_blendv_epi8(bits[k], shft[k], b[k]);
//                    //std::cout << "msb: " << nibbles(bits[0]) << std::endl;
//
//                    for (u64 h = 0; h < 4; ++h)
//                    {
//                        SIMD(k) shft[k] = _mm_srav_epi32(bits[k], shifts[h]);
//                        SIMD(k) shft[k] = _mm_and_si128 (bits[k], _mm_set1_epi32(255));
//
//                        SIMD(k) msbs[k] = _mm_srlv_epi32(msbs[k], vldsX[h][k]);
//                        SIMD(k) msbs[k] = _mm_or_si128(msbs[k], shft[k]);
//
//
//
//                        //{
//                        //    u32 sizes[4 * 8];
//                        //    static_assert(sizeof(sizes) == sizeof(counts), "expecting sizes to be the same size as counts");
//                        //    memcpy(sizes, &counts, sizeof(sizes));
//                        //    for(u64 w = 0; w < 4 * 8; ++w)
//                        //        assert(sizes[w] <= 3 * 12);
//
//                        //}
//                    }
//
//                    if (0)
//                    {
//                        // byte 0 for lsb and valid
//                        SIMD(k) vldsX[0][k] = _mm_and_si128 (vlds[k], _mm_set1_epi32(255));
//                        SIMD(k) shft[k] = _mm_and_si128 (bits[k], _mm_set1_epi32(255));
//                        SIMD(k) lsbs[k] = _mm_srlv_epi32(lsbs[k], vldsX[0][k]);
//                        SIMD(k) lsbs[k] = _mm_or_si128(lsbs[k], shft[k]);
//
//                        // byte 1 
//                        SIMD(k) vldsX[1][k] = _mm_srli_si128(vlds[k], 1);
//                        SIMD(k) vldsX[1][k] = _mm_and_si128 (vldsX[1][k], _mm_set1_epi32(255));
//
//                        SIMD(k) shft[k] = _mm_srli_si128(bits[k], 1);
//                        SIMD(k) shft[k] = _mm_and_si128 (bits[k], _mm_set1_epi32(255));
//
//                        SIMD(k) lsbs[k] = _mm_srlv_epi32(lsbs[k], vldsX[1][k]);
//                        SIMD(k) lsbs[k] = _mm_or_si128(lsbs[k], shft[k]);
//
//                        // byte 2
//                        SIMD(k) vldsX[2][k] = _mm_srli_si128(vlds[k], 2);
//                        SIMD(k) vldsX[2][k] = _mm_and_si128 (vldsX[2][k], _mm_set1_epi32(255));
//
//                        SIMD(k) shft[k] = _mm_srli_si128(bits[k], 2);
//                        SIMD(k) shft[k] = _mm_and_si128 (bits[k], _mm_set1_epi32(255));
//
//                        SIMD(k) lsbs[k] = _mm_srlv_epi32(lsbs[k], vldsX[2][k]);
//                        SIMD(k) lsbs[k] = _mm_or_si128(lsbs[k], shft[k]);
//
//                        // byte 3
//                        SIMD(k) vldsX[3][k] = _mm_srli_si128(vlds[k], 3);
//                        SIMD(k) vldsX[3][k] = _mm_and_si128 (vldsX[3][k], _mm_set1_epi32(255));
//
//                        SIMD(k) shft[k] = _mm_srli_si128(bits[k], 3);
//                        SIMD(k) shft[k] = _mm_and_si128 (bits[k], _mm_set1_epi32(255));
//
//                        SIMD(k) lsbs[k] = _mm_srlv_epi32(lsbs[k], vldsX[3][k]);
//                        SIMD(k) lsbs[k] = _mm_or_si128(lsbs[k], shft[k]);
//
//                        // msb
//
//                        // use the index to sample the lsb, msb, and valid flag.
//                        SIMD(k) bits[k] = _mm_shuffle_epi8(msbTable, r[k]);
//                        SIMD(k) shft[k] = _mm_slli_epi16(bits[k], 4);
//                        SIMD(k) bits[k] = _mm_blendv_epi8(bits[k], shft[k], b[k]);
//
//                        //byte 0 for msb
//                        SIMD(k) shft[k] = _mm_and_si128 (bits[k], _mm_set1_epi32(255));
//                        SIMD(k) msbs[k] = _mm_srlv_epi32(msbs[k], vldsX[0][k]);
//                        SIMD(k) msbs[k] = _mm_or_si128(msbs[k], shft[k]);
//
//
//                        // byte 1 
//                        SIMD(k) shft[k] = _mm_srli_si128(bits[k], 1);
//                        SIMD(k) shft[k] = _mm_and_si128 (bits[k], _mm_set1_epi32(255));
//
//                        SIMD(k) msbs[k] = _mm_srlv_epi32(msbs[k], vldsX[1][k]);
//                        SIMD(k) msbs[k] = _mm_or_si128(msbs[k], shft[k]);
//
//                        // byte 2 
//                        SIMD(k) shft[k] = _mm_srli_si128(bits[k], 2);
//                        SIMD(k) shft[k] = _mm_and_si128 (bits[k], _mm_set1_epi32(255));
//
//                        SIMD(k) msbs[k] = _mm_srlv_epi32(msbs[k], vldsX[2][k]);
//                        SIMD(k) msbs[k] = _mm_or_si128(msbs[k], shft[k]);
//
//                        // byte 3 
//                        SIMD(k) shft[k] = _mm_srli_si128(bits[k], 3);
//                        SIMD(k) shft[k] = _mm_and_si128 (bits[k], _mm_set1_epi32(255));
//
//                        SIMD(k) msbs[k] = _mm_srlv_epi32(msbs[k], vldsX[3][k]);
//                        SIMD(k) msbs[k] = _mm_or_si128(msbs[k], shft[k]);
//
//                        // counts
//                        SIMD(k) counts[k] = _mm_add_epi32(counts[k], vldsX[0][k]);
//                        SIMD(k) counts[k] = _mm_add_epi32(counts[k], vldsX[1][k]);
//                        SIMD(k) counts[k] = _mm_add_epi32(counts[k], vldsX[2][k]);
//                        SIMD(k) counts[k] = _mm_add_epi32(counts[k], vldsX[3][k]);
//                    }
//
//                    //// we accumulate the valid samples in 32 bits.
//                    //// but right now we have 3 bit samples in each byte.
//                    //// we need to shift the bytes and accumulate.
//                    //for (u64 j = 0; j < 4; ++j)
//                    //{
//
//                    //    // mask to only get the lower byte.
//                    //    auto lj = _mm_and_si128 (lsb[k], _mm_set1_epi32(255));
//                    //    auto mj = _mm_and_si128 (msb[k], _mm_set1_epi32(255));
//                    //    auto vj = _mm_and_si128 (valid[k], _mm_set1_epi32(255));
//
//                    //    // downshift the remaining bytes.
//                    //    lsb[k] = _mm_srli_si128(lsb[k], 1);
//                    //    msb[k] = _mm_srli_si128(msb[k], 1);
//                    //    valid[k] = _mm_srli_si128(valid[k], 1);
//
//                    //    // if the sample is valid, shift up the
//                    //    // accumulated samples and add the new sample.
//                    //    lsbs[k][j] = _mm_srlv_epi32(lsbs[k][j], vj);
//                    //    lsbs[k][j] = _mm_or_si128(lsbs[k][j], lj);
//
//                    //    msbs[k][j] = _mm_srlv_epi32(msbs[k][j], vj);
//                    //    msbs[k][j] = _mm_or_si128(msbs[k][j], mj);
//
//                    //    // increment the count if the sample is valid.
//                    //    counts[k][j] = _mm_add_epi8(counts[k][j], vj);
//                    //}
//
//                }
//
//            }
//#undef SIMD
//            //oc::AlignedArray<u32, 4> sizes;
//            //static_assert(sizeof(sizes) == sizeof(counts), "expecting sizes to be the same size as counts");
//            //memcpy(&sizes, &counts, sizeof(sizes));
//            for (u64 j = 0; j < 8; ++j)
//            {
//                for (u64 w = 0; w < 4; ++w)
//                {
//
//                    u32* lsbSum32 = (u32*)&lsbs[j];
//                    u32* msbSum32 = (u32*)&msbs[j];
//                    u32* size32 = (u32*)&size[j];
//
//                    auto& lsbk = lsbSum32[w];
//                    auto& msbk = msbSum32[w];
//
//                    auto& lsbk = lsbs[j].m128i_u32[w];
//                    auto& msbk = msbs[j].m128i_u32[w];
//                    assert(counts[j].m128i_i32[w] <= 3 * 12);
//
//                    while (counts[j].m128i_i32[w] < 32)
//                    {
//                        if (rands2Ptr == e2)
//                        {
//                            prng.mAes.ecbEncCounterMode(prng.mBlockIdx, rands2.size(), rands.data());
//                            prng.mBlockIdx += rands2.size();
//                            rands2Ptr = (u8*)rands2.data();
//                        }
//
//                        auto b = *rands2Ptr++;
//                        auto v = mod3Table[b];
//                        auto lsbj = v & 255ull;
//                        auto msbj = (v >> 8) & 255ull;
//                        auto flag = 3 * (v >> 16);
//                        lsbk = lsbk << flag | lsbj;
//                        msbk = msbk << flag | msbj;
//
//                        counts[j].m128i_i32[w] += flag;
//                    }
//                }
//                msbIter[i + j] = msbs[j];
//                lsbIter[i + j] = lsbs[j];
//            }
//        }
//    }


}