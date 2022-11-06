#pragma once

#include <cryptoTools/Common/Defines.h>
//#include <cryptoTools/Common/MatrixView.h>
//#include <boost/multiprecision/cpp_int.hpp>


//#define BIO_ENABLE_RELIC

namespace secJoin
{
    using u8  = oc::u8;
    using u16 = oc::u16;
    using u32 = oc::u32;
    using u64 = oc::u64;

    using i8  = oc::i8;
    using i16 = oc::i16;
    using i32 = oc::i32;
    using i64 = oc::i64;

    template<typename T> using span = oc::span<T>;




    inline u64 divCeil(u64 x, u64 y)
    {
        return (x + y - 1) / y;
    }

    inline bool getSign(span<u8> val, u64 index)
    {
        u64 i = index >> 3;
        u64 o = index & 7;
        return (val[i] >> o) & 1 ;
    }

    inline void fillInplace(span<u8> val, u64 index, bool bit)
    {
        u64 i = index >> 3;
        u64 o = index & 7;

        if (o)
        {
            u8 mask = ~u8(0) << (o + 1);
            val[i] = 
                ((bit) * (val[i] | mask)) |
                ((!bit) * (val[i] & ~mask));
            ++i;
        }

        for (; i < val.size(); ++i)
        {
            val[i] = bit * -1;
        }
    }
        


    //template<typename T>
    inline i64 signExtend(i64 val, u64 bit)
    {
        using T = i64;
        bool sign = val & (T(1) << bit);

        T mask = ~T(0) << (bit + 1);

        return
            ((sign) * (val | mask)) |
            ((!sign) * (val & ~mask));
    }

    //inline i64 signExtend(i64 val, u64 bit)
    //{
    //    return _signExtend(val, bit);
    //}

    //inline i128 signExtend(i128 val, u64 bit)
    //{
    //    return _signExtend(val, bit);
    //}


    // The convertion from security parameter to 
    // the required prime factor bit count.
    // https://www.cryptopp.com/wiki/Security_level
    enum class SecLevel
    {
        sec80 = 1024,
        sec112 = 2048,
        sec128 = 3072,
        sec192 = 7680,
        sec256 = 15360
    };
}
