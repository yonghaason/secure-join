#pragma once
#include "secure-join/Defines.h"
#include "cryptoTools/Crypto/PRNG.h"
#include "cryptoTools/Common/Aligned.h"

namespace secJoin
{

    extern const std::array<u32, 256> mod3TableV;
    extern const std::array<u32, 256> mod3TableLsb;
    extern const std::array<u32, 256> mod3TableMsb;
    extern std::array<std::array<u8, 5>, 256> const mod3TableFull;

    // z =  x + y mod 3
    void mod3Add(
        span<block> z1, span<block> z0,
        span<block> x1, span<block> x0,
        span<block> y1, span<block> y0);

    // (ab) += y0 mod 3
    // we treat binary x1 as the MSB and binary x0 as lsb.
    // That is, for bits, x1 x0 y0, we sets 
    //   t = x1 * 2 + x0 + y0
    //   x1 = t / 2
    //   x0 = t % 2
    void mod3Add(
        span<block> z1, span<block> z0,
        span<block> x1, span<block> x0,
        span<block> y0);


    void sampleMod3(PRNG& prng, span<u8> mBuffer);
    void sampleMod3(PRNG& prng, span<block> msb, span<block> lsb, oc::AlignedUnVector<u8>& b);

    void buildMod3Table();


    //void buildMod3Table2();


    void buildMod3Table4();


    void sampleMod3Lookup(PRNG& prng, span<block> msb, span<block> lsb);

    //void sampleMod3Lookup2(PRNG& prng, span<block> msbVec, span<block> lsbVec);

    void sampleMod3Lookup3(PRNG& prng, span<block> msbVec, span<block> lsbVec);

    //void sampleMod3Lookup5(PRNG& prng, span<block> msbVec, span<block> lsbVec);

    //void sampleMod3Lookup4(PRNG& prng, span<block> msbVec, span<block> lsbVec);

}