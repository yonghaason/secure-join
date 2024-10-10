#pragma once
#include <bitset>
#include <array>
#include "secure-join/Defines.h"
#include "cryptoTools/Crypto/PRNG.h"
#include "cryptoTools/Common/BitIterator.h"

namespace secJoin
{


    template<typename T>
    int bit(T* x, u64 i)
    {
        return  *oc::BitIterator((u8*)x, i);
    }
    template<typename T>
    int bit(T& x, u64 i)
    {
        return  *oc::BitIterator((u8*)&x, i);
    }
    template<typename T>
    int bit2(T& x, u64 i)
    {
        return  *oc::BitIterator((u8*)&x, i * 2) + 2 * *oc::BitIterator((u8*)&x, i * 2 + 1);;
    }

    inline void xorVector(span<oc::block> v, PRNG& prng)
    {
        oc::block m[8];
        auto vIter = v.data();
        auto n = v.size();
        assert(u64(v.data()) % 16 == 0);

        auto j = 0ull;
        auto main = n / 8 * 8;
        for (; j < main; j += 8)
        {
            prng.mAes.ecbEncCounterMode(prng.mBlockIdx, 8, m);
            prng.mBlockIdx += 8;
            //m[0] = prng.get();
            //m[1] = prng.get();
            //m[2] = prng.get();
            //m[3] = prng.get();
            //m[4] = prng.get();
            //m[5] = prng.get();
            //m[6] = prng.get();
            //m[7] = prng.get();

            vIter[0] = vIter[0] ^ m[0];
            vIter[1] = vIter[1] ^ m[1];
            vIter[2] = vIter[2] ^ m[2];
            vIter[3] = vIter[3] ^ m[3];
            vIter[4] = vIter[4] ^ m[4];
            vIter[5] = vIter[5] ^ m[5];
            vIter[6] = vIter[6] ^ m[6];
            vIter[7] = vIter[7] ^ m[7];
            vIter += 8;
        }
        for (; j < n; ++j)
        {
            auto m = prng.mAes.ecbEncBlock(oc::toBlock(prng.mBlockIdx++));
            //oc::block m = prng.get();
            *vIter = *vIter ^ m;
            ++vIter;
        }
        assert(vIter == v.data() + v.size());
    }



    // v = u + PRNG()
    inline void xorVectorOne(span<oc::block> v, span<const oc::block> u, PRNG& prng)
    {
        oc::block m[8];
        auto vIter = v.data();
        auto uIter = u.data();
        auto n = v.size();
        assert(u64(v.data()) % 16 == 0);

        auto j = 0ull;
        auto main = n / 8 * 8;
        for (; j < main; j += 8)
        {
            prng.mAes.ecbEncCounterMode(prng.mBlockIdx, 8, m);
            prng.mBlockIdx += 8;

            vIter[0] = uIter[0] ^ m[0];
            vIter[1] = uIter[1] ^ m[1];
            vIter[2] = uIter[2] ^ m[2];
            vIter[3] = uIter[3] ^ m[3];
            vIter[4] = uIter[4] ^ m[4];
            vIter[5] = uIter[5] ^ m[5];
            vIter[6] = uIter[6] ^ m[6];
            vIter[7] = uIter[7] ^ m[7];
            vIter += 8;
            uIter += 8;
        }
        for (; j < n; ++j)
        {
            auto m = prng.mAes.ecbEncBlock(oc::toBlock(prng.mBlockIdx++));
            //oc::block m = prng.get();

            *vIter = *uIter ^ m;
            ++vIter;
            ++uIter;
        }
        assert(vIter == v.data() + v.size());
    }

    // out = (hi0, hi1) ^ prng()
    inline void xorVectorOne(
        span<block> out1,
        span<block> out0,
        span<block> m1,
        span<block> m0,
        PRNG& prng)
    {

        xorVectorOne(out1, m1, prng);
        xorVectorOne(out0, m0, prng);
    }

    // out = (hi0, hi1) ^ prng()
    inline void xorVectorOne(
        span<block> out,
        span<block> m1,
        span<block> m0,
        PRNG& prng)
    {
        xorVectorOne(out.subspan(m0.size()), m1, prng);
        xorVectorOne(out.subspan(0, m0.size()), m0, prng);
    }



        struct block256
        {
            std::array<oc::block, 2> mData;
    
            void operator^=(const block256& x)
            {
                mData[0] = mData[0] ^ x.mData[0];
                mData[1] = mData[1] ^ x.mData[1];
            }
            block256 operator&(const block256& x) const
            {
                block256 r;
                r.mData[0] = mData[0] & x.mData[0];
                r.mData[1] = mData[1] & x.mData[1];
                return r;
            }
    
            block256 operator^(const block256& x) const
            {
                auto r = *this;
                r ^= x;
                return r;
            }
    
            block256 rotate(u64 i) const
            {
                auto xx = *(std::bitset<256>*)this;
                auto low = xx >> i;
                auto hgh = xx << (256 - i);
    
                auto m = hgh ^ low;
                block256 r;
                memcpy(&r, &m, sizeof(r));
                return r;
            }
    
            bool operator==(const block256& x) const
            {
                return std::memcmp(this, &x, sizeof(x)) == 0;
            }
            bool operator!=(const block256& x) const
            {
                return std::memcmp(this, &x, sizeof(x)) != 0;
            }
    
            oc::block& operator[](u64 i) { return mData[i]; }
        };
    
        inline std::ostream& operator<<(std::ostream& o, const block256& x)
        {
            o << x.mData[1] << x.mData[0];
            return o;
        }
    
        struct block256m3
        {
            //std::array<oc::block, 2> mData;
            std::array<u8, 256> mData;
            void operator^=(const block256& x)
            {
                //oc::BitIterator iter((u8*)&x);
                //for (u64 i = 0; i < 256; ++i, ++iter)
                //{
                //    assert((mData[i] == 255 && *iter) == false);
    
                //    mData[i] += *iter;
                //}
                oc::block block1 = oc::block::allSame<u8>(1);
                oc::block X[8], v[8];
                for (u64 j = 0; j < 2; ++j)
                {
    
                    X[0] = x.mData[j];
                    X[1] = x.mData[j] >> 1;
                    X[2] = x.mData[j] >> 2;
                    X[3] = x.mData[j] >> 3;
                    X[4] = x.mData[j] >> 4;
                    X[5] = x.mData[j] >> 5;
                    X[6] = x.mData[j] >> 6;
                    X[7] = x.mData[j] >> 7;
    
                    auto xIter = (u8*)X;
                    u8* v8 = v[0].data();
                    for (u64 t = 0; t < 8; ++t)
                    {
                        for (u64 kk = 0; kk < 2; ++kk)
                        {
    
                            for (u64 k = 0; k < 8; ++k)
                            {
                                v8[k] = xIter[sizeof(oc::block) * k];
                                //if (v != *oc::BitIterator((u8*)&x, i))
                                //    throw RTE_LOC;
                                //mData[i] += v;
                            }
                            v8 += 8;
                            ++xIter;
                        }
                    }
                    auto d = (oc::block*)&mData[j * 128];
    
                    v[0] = v[0] & block1;
                    v[1] = v[1] & block1;
                    v[2] = v[2] & block1;
                    v[3] = v[3] & block1;
                    v[4] = v[4] & block1;
                    v[5] = v[5] & block1;
                    v[6] = v[6] & block1;
                    v[7] = v[7] & block1;
    
                    d[0] = d[0] + v[0];
                    d[1] = d[1] + v[1];
                    d[2] = d[2] + v[2];
                    d[3] = d[3] + v[3];
                    d[4] = d[4] + v[4];
                    d[5] = d[5] + v[5];
                    d[6] = d[6] + v[6];
                    d[7] = d[7] + v[7];
    
    
                }
    
                //u64* iter = (u64*)&x;
                //for (u64 i = 0; i < 256;)
                //{
                //    auto d = i + 64;
                //    auto xx = *iter;
                //    auto s = 0;
                //    while (i < d)
                //    {
    
                //        auto xd = xx >> s;
                //        mData[i] += (xd & 1);
                //        ++s;
                //        ++i;
                //    }
                //    ++iter;
                //}
            }
    
            block256 mod2()
            {
                block256 r;
                //oc::BitIterator iter((u8*)&r);
    
                //
                //for (u64 i = 0; i < 256; ++i)
                //{
                //    mData[i] %= 3;
                //    *iter = mData[i] % 2;
                //}
    
                u64* iter = (u64*)&r;
                for (u64 i = 0; i < 256;)
                {
                    auto d = i + 64;
                    auto s = 0;
                    *iter = 0;
                    while (i < d)
                    {
    
                        mData[i] %= 3;
                        *iter |= u64(mData[i] % 2) << s;
                        ++i;
                        ++s;
                    }
                    ++iter;
                }
                return r;
            }
        };
}