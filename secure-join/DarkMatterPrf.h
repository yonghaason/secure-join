#pragma once
#include "secure-join/Defines.h"
#include "cryptoTools/Common/BitIterator.h"
#include <bitset>
#include "libOTe/Tools/Tools.h"
#include "libOTe/TwoChooseOne/Silent/SilentOtExtSender.h"
#include "libOTe/TwoChooseOne/Silent/SilentOtExtReceiver.h"

namespace secJoin
{
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
            xx = hgh ^ low;
            return *(block256*)&xx;
        }

        bool operator==(const block256& x) const
        {
            return std::memcmp(this, &x, sizeof(x)) == 0;
        }
        bool operator!=(const block256& x) const
        {
            return std::memcmp(this, &x, sizeof(x)) != 0;
        }
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
            oc::BitIterator iter((u8*)&x);
            for (u64 i = 0; i < 256; ++i, ++iter)
            {
                assert((mData[i] == 255 && *iter) == false);

                mData[i] += *iter;
            }
        }

        block256 mod2()
        {
            block256 r;
            oc::BitIterator iter((u8*)&r);

            for (u64 i = 0; i < 256; ++i, ++iter)
            {
                mData[i] %= 3;
                *iter = mData[i] % 2;
            }
            return r;
        }
    };


    class DarkMatterPrf
    {
    public:
        block256 mKey;

        std::array<block256, 256> mKeyMask;

        static const std::array<block256, 128> mB;

        void setKey(block256 k)
        {
            mKey = k;
            std::array<block256, 2> zeroOne;
            memset(&zeroOne[0], 0, sizeof(zeroOne[0]));
            memset(&zeroOne[1], -1, sizeof(zeroOne[1]));

            for (u64 i = 0; i < 256; ++i)
                mKeyMask[i] = zeroOne[*oc::BitIterator((u8*)&k, i)];
        }



        oc::block eval(block256 x)
        {
            block256 v;
            block256m3 u;
            memset(&v, 0, sizeof(v));
            memset(&u, 0, sizeof(u));
            for (u64 i = 0; i < mKeyMask.size(); ++i)
            {
                auto xi = x.rotate(i) & mKeyMask[i];
                v ^= xi;
                u ^= xi;
            }

            block256 u2 = u.mod2();
            block256 w = v ^ u2;

            alignas(32) std::array<std::array<oc::block, 128>, 2> bw;
            for (u64 i = 0; i < 128; ++i)
            {
                bw[0][i] = mB[i].mData[0] & w.mData[0];
                bw[1][i] = mB[i].mData[1] & w.mData[1];
            }
            oc::transpose128(bw[0].data());
            oc::transpose128(bw[1].data());

            oc::block r;
            memset(&r, 0, sizeof(r));
            for (u64 i = 0; i < 128; ++i)
                r = r ^ bw[0][i];
            for (u64 i = 0; i < 128; ++i)
                r = r ^ bw[1][i];
            return r;
        }
    };

    inline __m128i nonz_index(__m128i x, u64& count) {
        /* Set some constants that will (hopefully) be hoisted out of a loop after inlining. */
        uint64_t  indx_const = 0xFEDCBA9876543210;                       /* 16 4-bit integers, all possible indices from 0 o 15                                                            */
        __m128i   cntr = _mm_set_epi8(64, 60, 56, 52, 48, 44, 40, 36, 32, 28, 24, 20, 16, 12, 8, 4);
        __m128i   pshufbcnst = _mm_set_epi8(0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x0E, 0x0C, 0x0A, 0x08, 0x06, 0x04, 0x02, 0x00);
        __m128i   cnst0F = _mm_set1_epi8(0x0F);

        __m128i   msk = _mm_cmpeq_epi8(x, _mm_setzero_si128());    /* Generate 16x8 bit mask.                                                                                        */
        msk = _mm_srli_epi64(msk, 4);                    /* Pack 16x8 bit mask to 16x4 bit mask.                                                                           */
        msk = _mm_shuffle_epi8(msk, pshufbcnst);         /* Pack 16x8 bit mask to 16x4 bit mask, continued.                                                                */
        uint64_t  msk64 = ~_mm_cvtsi128_si64x(msk);                 /* Move to general purpose register and invert 16x4 bit mask.                                                     */

                                                                           /* Compute the termination byte nonzmsk separately.                                                               */
        int64_t   nnz64 = _mm_popcnt_u64(msk64);                    /* Count the nonzero bits in msk64.                                                                               */
        __m128i   nnz = _mm_set1_epi8(nnz64);                     /* May generate vmovd + vpbroadcastb if AVX2 is enabled.                                                          */
        __m128i   nonzmsk = _mm_cmpgt_epi8(cntr, nnz);                 /* nonzmsk is a mask of the form 0xFF, 0xFF, ..., 0xFF, 0, 0, ...,0 to mark the output positions without an index */
        uint64_t  indx64 = _pext_u64(indx_const, msk64);              /* parallel bits extract. pext shuffles indx_const such that indx64 contains the nnz64 4-bit indices that we want.*/
        //std::cout << "nnz64 " << nnz64 << std::endl;
        __m128i   indx = _mm_cvtsi64x_si128(indx64);               /* Use a few integer instructions to unpack 4-bit integers to 8-bit integers.                                     */
        __m128i   indx_024 = indx;                                     /* Even indices.                                                                                                  */
        __m128i   indx_135 = _mm_srli_epi64(indx, 4);                   /* Odd indices.                                                                                                   */
        indx = _mm_unpacklo_epi8(indx_024, indx_135);     /* Merge odd and even indices.                                                                                    */
        indx = _mm_and_si128(indx, cnst0F);               /* Mask out the high bits 4,5,6,7 of every byte.                                                                  */

        count = nnz64 / 8;
        return _mm_or_si128(indx, nonzmsk);                       /* Merge indx with nonzmsk .                                                                                      */
    }

    inline void sampleMod3(oc::PRNG& prng, span<u16> mBuffer)
    {
        auto n = mBuffer.size();
        auto dst = mBuffer.data();
        oc::block m[8], t[8], eq[9], ss[8];
        eq[8] = oc::ZeroBlock;
        oc::block block1 = std::array<u16, 8>{1, 1, 1, 1, 1, 1, 1, 1};
        oc::block block3 = std::array<u16, 8>{3, 3, 3, 3, 3, 3, 3, 3};
        oc::block I = std::array<u16, 8>{0, 1, 2, 3, 4, 5, 6, 7};

        static constexpr int batchSize = 8;
        std::array<std::array<oc::block, batchSize>, 64> buffer;
        std::array<u16 * __restrict, 64> iters;

        for (u64 i = 0; i < n;)
        {
            for (u64 j = 0; j < 64; ++j)
                iters[j] = (u16*)buffer[j].data();


            for (u64 bb = 0; bb < batchSize; ++bb)
            {

                prng.mAes.ecbEncCounterMode(prng.mBlockIdx, 8, m);
                prng.mBlockIdx += 8;
                //for (auto k = 0; k < 16 && i < n; ++k)
                //{
                //    u64 t = ((u64*)m)[k];
                //    auto min = std::min<u64>(32, n - i);
                //    for (u64 j = 0; j < min; ++j)
                //    {
                //        auto b = t & 3;
                //        dst[i] = b;
                //        i += (b != 3);
                //        t >>= 2;
                //    }
                //}
                for (u64 j = 0; j < 8 && i < n; ++j)
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

                    eq[0] = eq[0] ^ oc::AllOneBlock;
                    eq[1] = eq[1] ^ oc::AllOneBlock;
                    eq[2] = eq[2] ^ oc::AllOneBlock;
                    eq[3] = eq[3] ^ oc::AllOneBlock;
                    eq[4] = eq[4] ^ oc::AllOneBlock;
                    eq[5] = eq[5] ^ oc::AllOneBlock;
                    eq[6] = eq[6] ^ oc::AllOneBlock;
                    eq[7] = eq[7] ^ oc::AllOneBlock;

                        eq[0] = eq[0] & block1;
                        eq[1] = eq[1] & block1;
                        eq[2] = eq[2] & block1;
                        eq[3] = eq[3] & block1;
                        eq[4] = eq[4] & block1;
                        eq[5] = eq[5] & block1;
                        eq[6] = eq[6] & block1;
                        eq[7] = eq[7] & block1;

                        auto t16 = (u16*)t;
                        auto e16 = (u16*)eq;
                        for (u64 j = 0; j < 64; ++j)
                        {
                            iters[j][0] = t16[j];
                            iters[j] += e16[j];
                        }

                }


            }
            for (u64 j = 0; j < 64 && i < n; ++j)
            {
                auto b = (u16*)buffer[j].data();

                auto size = iters[j] - b;
                auto min = std::min<u64>(size, n - i);
                if (min)
                {
                    memcpy(dst + i, b, min * 2);
                    i += min;
                }
            }
        }

        //for (u64 q = 0; q < mBuffer.size(); ++q)
        //{
        //    //mBuffer[q] = prng.get<u64>() % 3;
        //    std::cout << int(mBuffer[q]) << " ";
        //    assert(mBuffer[q] < 3);
        //}
        //std::cout << std::endl;

    }

    inline oc::AlignedUnVector<u16> sampleMod3(oc::PRNG& prng, u64 n)
    {
        oc::AlignedUnVector<u16> mBuffer(n);
        sampleMod3(prng, mBuffer);
        return mBuffer;
    }

    inline void compressMod3(span<u8> dst, span<const u16> src)
    {
        if (dst.size() * 4 != src.size())
            throw RTE_LOC;

        u64* d = (u64*)dst.data();
        auto s = (const u16*)src.data();
        auto n = src.size();
        for (u64 i = 0; i < n;)
        {
            assert(d < (u64*)(dst.data() + dst.size()));

            u64 x[4];
            u8* x8 = (u8*)x;
            //auto si = s + i;
            for (u64 j = 0; j < 8; ++j)
            {
                x8[0 + j] = *s++;
                x8[8 + j] = *s++;
                x8[16 + j] = *s++;
                x8[24 + j] = *s++;
                //si += 4;
            }
            x[1] <<= 2;
            x[2] <<= 4;
            x[3] <<= 6;

            *d++ = x[0] ^ x[1] ^ x[2] ^ x[3];

            assert(s <= src.data() + src.size());
            i += 32;

            //*d = 0;
            //for (u64 j = 0; j < 64; j += 2, ++i)
            //{
            //    assert(s[i] < 3);
            //    *d |= u64(s[i]) << j;
            //}
            //++d;
        }
    }

    inline void decompressMod3(span<u16> dst, span<const u8> src)
    {
        if (dst.size() != src.size() * 4)
            throw RTE_LOC;

        const u64* s = (const u64*)src.data();
        auto d = dst.data();
        for (u64 i = 0; i < dst.size();)
        {
            auto ss = *s;
            assert(s < (u64*)(src.data() + src.size()));
            for (u64 j = 0; j < 32; ++j, ++i)
            {
                auto& dsti = d[i];
                dsti = ss & 3;
                assert(dsti < 3);
                ss >>= 2;
            }
            ++s;
        }
    }

    inline std::string hex(span<u8> d)
    {
        std::stringstream ss;
        for (u64 i = 0; i < d.size(); ++i)
        {
            ss << std::setw(2) << std::setfill('0') << std::hex << int(d[i]);
        }

        return ss.str();
    }


    inline void xorVector(span<oc::block> v, oc::PRNG& prng)
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

    inline void xorVector(span<u8> ui, oc::PRNG& prng)
    {
        assert(ui.size() % sizeof(oc::block) == 0);
        auto uiBlk = span<oc::block>((oc::block*)ui.data(), ui.size() / sizeof(oc::block));
        xorVector(uiBlk, prng);
    }

    inline void xorVector(span<block256> v, oc::PRNG& prng)
    {
        auto vv = span<oc::block>((oc::block*)v.data(), v.size() * 2);
        xorVector(vv, prng);
    }

    inline void xorVector(span<oc::block> v, span<const oc::block> u, oc::PRNG& prng)
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
            //m[0] = prng.get();
            //m[1] = prng.get();
            //m[2] = prng.get();
            //m[3] = prng.get();
            //m[4] = prng.get();
            //m[5] = prng.get();
            //m[6] = prng.get();
            //m[7] = prng.get();

            vIter[0] = vIter[0] ^ uIter[0] ^ m[0];
            vIter[1] = vIter[1] ^ uIter[1] ^ m[1];
            vIter[2] = vIter[2] ^ uIter[2] ^ m[2];
            vIter[3] = vIter[3] ^ uIter[3] ^ m[3];
            vIter[4] = vIter[4] ^ uIter[4] ^ m[4];
            vIter[5] = vIter[5] ^ uIter[5] ^ m[5];
            vIter[6] = vIter[6] ^ uIter[6] ^ m[6];
            vIter[7] = vIter[7] ^ uIter[7] ^ m[7];
            vIter += 8;
            uIter += 8;
        }
        for (; j < n; ++j)
        {
            auto m = prng.mAes.ecbEncBlock(oc::toBlock(prng.mBlockIdx++));
            //oc::block m = prng.get();

            *vIter = *vIter ^ *uIter ^ m;
            ++vIter;
            ++uIter;
        }
        assert(vIter == v.data() + v.size());
    }

    inline void xorVector(span<block256> v, span<const block256> u, oc::PRNG& prng)
    {
        auto vv = span<oc::block>(v[0].mData.data(), v.size() * 2);
        auto uu = span<const oc::block>(u[0].mData.data(), u.size() * 2);
        xorVector(vv, uu, prng);
    }

    class DarkMatterPrfSender
    {
        std::vector<oc::PRNG> mKeyOTs;
    public:
        block256 mKey;
        oc::SilentOtExtSender mOtSender;

        std::vector<block256> mV, mU2, mW;
        std::vector<std::array<u16, 256>> mU;

        void setKeyOts(span<oc::block> ots)
        {
            if (ots.size() != 256)
                throw RTE_LOC;
            mKeyOTs.resize(256);
            for (u64 i = 0; i < 256; ++i)
            {
                //mKeyOTs[i].mAes.setKey(ots[i]);
                //mKeyOTs[i].mBlockIdx = 0;
                mKeyOTs[i].SetSeed(ots[i]);
            }
        }

        void setKey(block256 k)
        {
            mKey = k;
        }

        coproto::task<> evaluate(span<oc::block> y, coproto::Socket& sock, oc::PRNG& prng)
        {
            static constexpr auto compSize = 256 / 4;

            MC_BEGIN(coproto::task<>, y, this, &sock, &prng,
                vi = oc::AlignedUnVector<block256>{},
                ui = oc::AlignedUnVector<u8>{},
                uui = oc::AlignedUnVector<u16>{},
                f = oc::BitVector{},
                diff = oc::BitVector{},
                i = u64{});

            mV.resize(y.size());
            mU.resize(y.size());
            uui.resize(y.size() * 256);
            for (i = 0; i < 256; ++i)
            {
                vi.resize(y.size()); // y.size() * 256 bits
                ui.resize(y.size() * compSize); // y.size() * 256 * 2 bits

                MC_AWAIT(sock.recv(vi));
                MC_AWAIT(sock.recv(ui));

                u8 ki = *oc::BitIterator((u8*)&mKey, i);
                if (ki)
                {
                    // mV = mV ^ vi ^ H(mKeyOTs[i])
                    xorVector(mV, vi, mKeyOTs[i]);

                    // ui = ui ^ H(mKeyOTs[i])
                    xorVector(ui, mKeyOTs[i]);

                    decompressMod3(uui, ui);
                }
                else
                {
                    sampleMod3(mKeyOTs[i], uui);

                    xorVector(mV, mKeyOTs[i]);
                    //for (u64 j = 0; j < y.size(); ++j)
                    //{
                    //    mV[j] = mV[j] ^ mKeyOTs[i].get<block256>();
                    //}
                }

                auto u = (oc::block*)mU.data();
                auto ui = (oc::block*)uui.data();
                for (u64 j = 0; j < y.size(); ++j)
                {
                    for (u64 k = 0; k < 4; ++k)
                    {
                        u[0] = _mm_adds_epu16(u[0], ui[0]);
                        u[1] = _mm_adds_epu16(u[1], ui[1]);
                        u[2] = _mm_adds_epu16(u[2], ui[2]);
                        u[3] = _mm_adds_epu16(u[3], ui[3]);
                        u[4] = _mm_adds_epu16(u[4], ui[4]);
                        u[5] = _mm_adds_epu16(u[5], ui[5]);
                        u[6] = _mm_adds_epu16(u[6], ui[6]);
                        u[7] = _mm_adds_epu16(u[7], ui[7]);
                        u += 8;
                        ui += 8;
                    }
                    //auto uij = uui.subspan(j * 256, 256);
                    //for (u64 k = 0; k < 256; ++k)
                    //{
                    //    mU[j][k] += uij[k];
                    //}
                }
            }

            for (u64 j = 0; j < y.size(); ++j)
            {
                for (u64 k = 0; k < 256; ++k)
                {
                    mU[j][k] = mU[j][k] % 3;
                }
            }


            // mod 2
            diff.resize(y.size() * 512);
            //MC_AWAIT(mOtSender.silentSendInplace(prng.get(),diff.size(), prng, sock));
            mOtSender.mB.resize(diff.size());
            memset(mOtSender.mB.data(), 0, mOtSender.mB.size() * sizeof(oc::block));
            MC_AWAIT(sock.recv(diff));
            {

                mU2.resize(y.size());
                mW.resize(y.size());
                f.resize(y.size() * 256 * 2);
                auto mask = oc::AllOneBlock ^ oc::OneBlock;
                auto uIter = oc::BitIterator((u8*)mU2.data());
                auto dIter = diff.begin();
                auto bIter = mOtSender.mB.begin();
                auto fIter = f.begin();
                //auto rIter = rKeys.begin();
                for (u64 i = 0; i < y.size(); ++i)
                {
                    for (u64 j = 0; j < 256; ++j)
                    {
                        std::array<oc::block, 2> s0{ { *bIter, *bIter } };
                        ++bIter;
                        std::array<oc::block, 2> s1{ { *bIter, *bIter } };
                        ++bIter;

                        auto d0 = *dIter++ ^ 1;
                        auto d1 = *dIter++ ^ 1;
                        s0[d0] = s0[d0] ^ mOtSender.mDelta;
                        s1[d1] = s1[d1] ^ mOtSender.mDelta;

                        s0[0] = oc::mAesFixedKey.hashBlock(s0[0] & mask);
                        s0[1] = oc::mAesFixedKey.hashBlock(s0[1] & mask);
                        s1[0] = oc::mAesFixedKey.hashBlock(s1[0] & mask);
                        s1[1] = oc::mAesFixedKey.hashBlock(s1[1] & mask);

                        auto q0 = (s0[0].get<u8>(1) ^ s1[0].get<u8>(1)) & 1;
                        auto q1 = (s0[1].get<u8>(1) ^ s1[0].get<u8>(1)) & 1;
                        auto q2 = (s0[0].get<u8>(1) ^ s1[1].get<u8>(1)) & 1;

                        //  them       us
                        //         0   1   2
                        //        ___________
                        //  0    | 0   1   0
                        //  1    | 1   0   0
                        //  2    | 0   0   1

                        //  0   -> u==1
                        //  1   -> u==0
                        //  2   -> u==2

                        auto t0 = q0 ^ (mU[i][j] == 1);
                        auto t1 = t0 ^ (mU[i][j] == 0);
                        auto t2 = t0 ^ (mU[i][j] == 2);
                        *uIter++ = t0;
                        *fIter++ = q1 ^ t1;
                        *fIter++ = q2 ^ t2;

                    }

                    auto w = mU2[i] ^ mV[i];

                    alignas(32) std::array<std::array<oc::block, 128>, 2> bw;

                    for (u64 i = 0; i < 128; ++i)
                    {
                        bw[0][i] = DarkMatterPrf::mB[i].mData[0] & w.mData[0];
                        bw[1][i] = DarkMatterPrf::mB[i].mData[1] & w.mData[1];
                    }
                    oc::transpose128(bw[0].data());
                    oc::transpose128(bw[1].data());

                    oc::block& r = y[i];
                    memset(&r, 0, sizeof(r));
                    for (u64 i = 0; i < 128; ++i)
                        r = r ^ bw[0][i];
                    for (u64 i = 0; i < 128; ++i)
                        r = r ^ bw[1][i];
                }

            }
            MC_AWAIT(sock.send(std::move(f)));


            MC_END();
        }

    };

    class DarkMatterPrfReceiver
    {
        std::vector<std::array<oc::PRNG, 2>> mKeyOTs;
    public:
        oc::SilentOtExtReceiver mOtReceiver;


        std::vector<block256> mV, mU2, mW;
        std::vector<std::array<u16, 256>> mU;


        void setKeyOts(span<std::array<oc::block, 2>> ots)
        {
            if (ots.size() != 256)
                throw RTE_LOC;
            mKeyOTs.resize(256);
            for (u64 i = 0; i < 256; ++i)
            {
                //mKeyOTs[i][0].mAes.setKey(ots[i][0]);
                //mKeyOTs[i][1].mAes.setKey(ots[i][1]);
                //mKeyOTs[i][0].mBlockIdx = 0;
                //mKeyOTs[i][1].mBlockIdx = 0;
                mKeyOTs[i][0].SetSeed(ots[i][0]);
                mKeyOTs[i][1].SetSeed(ots[i][1]);
            }
        }


        coproto::task<> evaluate(span<block256> x, span<oc::block> y, coproto::Socket& sock, oc::PRNG& prng)
        {
            MC_BEGIN(coproto::task<>, x, y, this, &sock, &prng,
                X = oc::AlignedUnVector<std::array<u16, 512>>{},
                vi = oc::AlignedUnVector<block256>{},
                ui = oc::AlignedUnVector<u8>{},
                rKeys = oc::AlignedUnVector<oc::block>{},
                mod3 = oc::AlignedUnVector<u16>{},
                mod3i = (u16*)nullptr,
                diff = oc::BitVector{},
                i = u64{},
                block3 = oc::block{}
            );

            block3 = std::array<u16, 8>{3, 3, 3, 3, 3, 3, 3, 3};
            mV.resize(x.size());
            mU.resize(x.size());
            mod3.resize(x.size() * 256);
            X.resize(x.size());
            for (u64 j = 0; j < x.size(); ++j)
            {
                auto iter = oc::BitIterator((u8*)&x[j]);
                for (i = 0; i < 256; ++i)
                {
                    X[j][i] = *iter++;
                    X[j][i + 256] = X[j][i];
                }
            }
            for (i = 0; i < 256; ++i)
            {
                vi.resize(x.size()); // x.size() * 256 bits
                ui.resize(x.size() * 256 / 4); // x.size() * 256 * 2 bits

                sampleMod3(mKeyOTs[i][0], mod3);
                mod3i = mod3.data();

                //for (u64 j = 0; j < x.size(); ++j)
                //{
                //    auto xji = x[j].rotate(i);
                //    auto vij0 = mKeyOTs[i][0].get<block256>();
                //    mV[j] = mV[j] ^ vij0;
                //    vi[j] = vij0 ^ xji ^ mKeyOTs[i][1].get<block256>();
                //}
                {
                    u64 j = 0;
                    auto main = x.size() / 4 * 4;
                    block256 xji[4];
                    block256* xj = x.data();
                    //oc::block m0[8];
                    oc::block m1[8];
                    auto vIter = (oc::block*)mV.data();
                    auto viIter = (oc::block*)vi.data();
                    for (; j < main; j += 4)
                    {
                        xji[0] = xj[0].rotate(i);
                        xji[1] = xj[1].rotate(i);
                        xji[2] = xj[2].rotate(i);
                        xji[3] = xj[3].rotate(i);
                        xj += 4;

                        mKeyOTs[i][0].mAes.ecbEncCounterMode(mKeyOTs[i][0].mBlockIdx, 8, viIter);
                        mKeyOTs[i][0].mBlockIdx += 8;
                        //viIter[0] = mKeyOTs[i][0].get();
                        //viIter[1] = mKeyOTs[i][0].get();
                        //viIter[2] = mKeyOTs[i][0].get();
                        //viIter[3] = mKeyOTs[i][0].get();
                        //viIter[4] = mKeyOTs[i][0].get();
                        //viIter[5] = mKeyOTs[i][0].get();
                        //viIter[6] = mKeyOTs[i][0].get();
                        //viIter[7] = mKeyOTs[i][0].get();

                        vIter[0] = vIter[0] ^ viIter[0];
                        vIter[1] = vIter[1] ^ viIter[1];
                        vIter[2] = vIter[2] ^ viIter[2];
                        vIter[3] = vIter[3] ^ viIter[3];
                        vIter[4] = vIter[4] ^ viIter[4];
                        vIter[5] = vIter[5] ^ viIter[5];
                        vIter[6] = vIter[6] ^ viIter[6];
                        vIter[7] = vIter[7] ^ viIter[7];

                        mKeyOTs[i][1].mAes.ecbEncCounterMode(mKeyOTs[i][1].mBlockIdx, 8, m1);
                        mKeyOTs[i][1].mBlockIdx += 8;

                        //m1[0] = mKeyOTs[i][1].get();
                        //m1[1] = mKeyOTs[i][1].get();
                        //m1[2] = mKeyOTs[i][1].get();
                        //m1[3] = mKeyOTs[i][1].get();
                        //m1[4] = mKeyOTs[i][1].get();
                        //m1[5] = mKeyOTs[i][1].get();
                        //m1[6] = mKeyOTs[i][1].get();
                        //m1[7] = mKeyOTs[i][1].get();

                        auto xji128 = (oc::block*)xji;
                        viIter[0] = viIter[0] ^ xji128[0] ^ m1[0];
                        viIter[1] = viIter[1] ^ xji128[1] ^ m1[1];
                        viIter[2] = viIter[2] ^ xji128[2] ^ m1[2];
                        viIter[3] = viIter[3] ^ xji128[3] ^ m1[3];
                        viIter[4] = viIter[4] ^ xji128[4] ^ m1[4];
                        viIter[5] = viIter[5] ^ xji128[5] ^ m1[5];
                        viIter[6] = viIter[6] ^ xji128[6] ^ m1[6];
                        viIter[7] = viIter[7] ^ xji128[7] ^ m1[7];

                        vIter += 8;
                        viIter += 8;

                        //auto vij0 = mKeyOTs[i][0].get<block256>();
                        //mV[j] = mV[j] ^ vij0;
                        //vi[j] = vij0 ^ xji ^ mKeyOTs[i][1].get<block256>();
                    }
                }


                for (u64 j = 0; j < x.size(); ++j)
                {
                    oc::AlignedArray<oc::block, 32> xij;
                    memcpy(&xij, &X[j][i], sizeof(xij));
                    auto uj = mU[j].data();
                    auto xij128 = (oc::block*)&xij;
                    auto uj128 = (oc::block*)uj;
                    auto mod3i128 = (oc::block*)mod3i;
                    assert(u64(xij128) % 16 == 0);
                    assert(u64(uj128) % 16 == 0);
                    assert(u64(mod3i128) % 16 == 0);
                    for (u64 k = 0; k < 4; ++k)
                    {
                        //assert(*mod3i < 3);
                        //uj[k] += mod3i[k];
                        //mod3i[k] = (mod3i[k] + xij[k]);
                        //mod3i[k] *= (mod3i[k] != 3);

                        //uj128[k] = _mm_adds_epu16(uj128[k], mod3i128[k]);
                        //mod3i128[k] = _mm_adds_epu16(mod3i128[k], xij128[k]);
                        //auto eq = _mm_cmpeq_epi16(mod3i128[k], block3);
                        //mod3i128[k] = _mm_andnot_si128(eq, mod3i128[k]);

                        uj128[0] = _mm_adds_epu16(uj128[0], mod3i128[0]);
                        uj128[1] = _mm_adds_epu16(uj128[1], mod3i128[1]);
                        uj128[2] = _mm_adds_epu16(uj128[2], mod3i128[2]);
                        uj128[3] = _mm_adds_epu16(uj128[3], mod3i128[3]);
                        uj128[4] = _mm_adds_epu16(uj128[4], mod3i128[4]);
                        uj128[5] = _mm_adds_epu16(uj128[5], mod3i128[5]);
                        uj128[6] = _mm_adds_epu16(uj128[6], mod3i128[6]);
                        uj128[7] = _mm_adds_epu16(uj128[7], mod3i128[7]);

                        mod3i128[0] = _mm_adds_epu16(mod3i128[0], xij128[0]);
                        mod3i128[1] = _mm_adds_epu16(mod3i128[1], xij128[1]);
                        mod3i128[2] = _mm_adds_epu16(mod3i128[2], xij128[2]);
                        mod3i128[3] = _mm_adds_epu16(mod3i128[3], xij128[3]);
                        mod3i128[4] = _mm_adds_epu16(mod3i128[4], xij128[4]);
                        mod3i128[5] = _mm_adds_epu16(mod3i128[5], xij128[5]);
                        mod3i128[6] = _mm_adds_epu16(mod3i128[6], xij128[6]);
                        mod3i128[7] = _mm_adds_epu16(mod3i128[7], xij128[7]);

                        auto eq0 = _mm_cmpeq_epi16(mod3i128[0], block3);
                        auto eq1 = _mm_cmpeq_epi16(mod3i128[1], block3);
                        auto eq2 = _mm_cmpeq_epi16(mod3i128[2], block3);
                        auto eq3 = _mm_cmpeq_epi16(mod3i128[3], block3);
                        auto eq4 = _mm_cmpeq_epi16(mod3i128[4], block3);
                        auto eq5 = _mm_cmpeq_epi16(mod3i128[5], block3);
                        auto eq6 = _mm_cmpeq_epi16(mod3i128[6], block3);
                        auto eq7 = _mm_cmpeq_epi16(mod3i128[7], block3);

                        mod3i128[0] = _mm_andnot_si128(eq0, mod3i128[0]);
                        mod3i128[1] = _mm_andnot_si128(eq1, mod3i128[1]);
                        mod3i128[2] = _mm_andnot_si128(eq2, mod3i128[2]);
                        mod3i128[3] = _mm_andnot_si128(eq3, mod3i128[3]);
                        mod3i128[4] = _mm_andnot_si128(eq4, mod3i128[4]);
                        mod3i128[5] = _mm_andnot_si128(eq5, mod3i128[5]);
                        mod3i128[6] = _mm_andnot_si128(eq6, mod3i128[6]);
                        mod3i128[7] = _mm_andnot_si128(eq7, mod3i128[7]);

                        xij128 += 8;
                        uj128 += 8;
                        mod3i128 += 8;
                    }
                    mod3i += 256;
                    //for (u64 k = 0; k < 256; ++k)
                    //{
                    //    assert(*mod3i < 3);
                    //    auto& uijk = *mod3i++;
                    //    mU[j][k] += uijk;
                    //    auto xijk = X[j][u8(i + k)];
                    //    uijk = (uijk + xijk);
                    //    uijk *= (uijk != 3);
                    //}
                }
                compressMod3(ui, mod3);


                //ui = ui ^ H(mKeyOTs[i][1])
                xorVector(ui, mKeyOTs[i][1]);
                //for (u64 j = 0; j < ui.size(); ++j)
                //{
                //    ui[j] = ui[j] ^ mKeyOTs[i][1].get<u8>();
                //}

                MC_AWAIT(sock.send(std::move(vi)));
                MC_AWAIT(sock.send(std::move(ui)));
            }
            X = {};

            for (u64 j = 0; j < x.size(); ++j)
            {
                for (u64 k = 0; k < 256; ++k)
                {
                    mU[j][k] = mU[j][k] % 3;

                    //bool(mU[j][k]) * (i64(1 - mU[j][k]) * 2) + 1);
                    switch (mU[j][k])
                    {
                    case 1:
                        mU[j][k] = 2;
                        break;
                    case 2:
                        mU[j][k] = 1;
                        break;
                    default:
                        break;
                    }
                }
            }

            // mod 2
            diff.resize(x.size() * 512);
            rKeys.resize(x.size() * 256);
            //MC_AWAIT(mOtReceiver.silentReceiveInplace(diff.size(), prng, sock, oc::ChoiceBitPacking::True));
            mOtReceiver.mA.resize(diff.size());
            memset(mOtReceiver.mA.data(), 0, mOtReceiver.mA.size() * sizeof(oc::block));

            {
                auto mask = oc::AllOneBlock ^ oc::OneBlock;
                auto dIter = diff.begin();
                auto aIter = mOtReceiver.mA.begin();
                auto rIter = rKeys.begin();
                for (u64 i = 0; i < x.size(); ++i)
                {
                    for (u64 j = 0; j < 256; ++j)
                    {
                        auto uij = mU[i][j];
                        auto a0 = uij & 1;
                        auto a1 = (uij >> 1);
                        assert(a1 < 2);

                        auto h0 = oc::mAesFixedKey.hashBlock(aIter[0] & mask);
                        auto h1 = oc::mAesFixedKey.hashBlock(aIter[1] & mask);

                        *rIter++ = h0 ^ h1;// (aIter[0] ^ aIter[1])& mask;

                        *dIter++ = ((*aIter++).get<u8>(0) ^ a0) & 1;
                        *dIter++ = ((*aIter++).get<u8>(0) ^ a1) & 1;
                    }
                }
            }
            MC_AWAIT(sock.send(std::move(diff)));

            //oc::mAesFixedKey.hashBlocks(rKeys, rKeys);
            ui.resize(0);
            ui.resize(x.size() * 256 / 4);

            MC_AWAIT(sock.recv(ui));

            {
                mU2.resize(x.size());
                mW.resize(x.size());
                auto uIter = oc::BitIterator((u8*)mU2.data());
                auto fIter = oc::BitIterator((u8*)ui.data());
                auto rIter = rKeys.begin();
                for (i = 0; i < x.size(); ++i)
                {
                    for (u64 j = 0; j < 256; ++j)
                    {

                        auto u = (rIter++->get<u8>(1) & 1);
                        if (mU[i][j])
                        {
                            u ^= *(fIter + (mU[i][j] - 1));
                        }
                        fIter = fIter + 2;
                        *uIter++ = u;
                        //switch (mU[i][j])
                        //{
                        //case 0:
                        //{
                        //    // u mod 2 = lsb(*rIter++) = q0
                        //    break;
                        //}
                        //case 1:
                        //    // u mod 2 = lsb(*rIter++) ^ *fIter

                        //    break;
                        //case 2:
                        //    // u mod 2 = lsb(*rIter++) ^ *(fIter + 1)

                        //    break;
                        //default:
                        //    __assume(0);
                        //    break;
                        //}
                    }

                    auto w = mU2[i] ^ mV[i];

                    alignas(32) std::array<std::array<oc::block, 128>, 2> bw;

                    for (u64 i = 0; i < 128; ++i)
                    {
                        bw[0][i] = DarkMatterPrf::mB[i].mData[0] & w.mData[0];
                        bw[1][i] = DarkMatterPrf::mB[i].mData[1] & w.mData[1];
                    }
                    oc::transpose128(bw[0].data());
                    oc::transpose128(bw[1].data());

                    oc::block& r = y[i];
                    memset(&r, 0, sizeof(r));
                    for (u64 i = 0; i < 128; ++i)
                        r = r ^ bw[0][i];
                    for (u64 i = 0; i < 128; ++i)
                        r = r ^ bw[1][i];
                }


            }

            MC_END();
        }

    };
}
