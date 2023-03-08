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


    inline void sampleMod3(oc::PRNG& prng, span<u8> mBuffer)
    {
        auto n = mBuffer.size();
        auto dst = mBuffer.data();
        for (u64 i = 0; i < n;)
        {
            u64 t = prng.get();
            auto min = std::min<u64>(32, n - i);
            for (u64 j = 0; j < min; ++j)
            {
                auto b = t & 3;
                dst[i] = b;
                i += (b != 3);
                t >>= 2;
            }
        }
    }

    inline oc::AlignedUnVector<u8> sampleMod3(oc::PRNG& prng, u64 n)
    {
        oc::AlignedUnVector<u8> mBuffer(n);
        sampleMod3(prng, mBuffer);
        return mBuffer;
    }

    inline void compressMod3(span<u8> dst, span<const u8> src)
    {
        if (dst.size() * 4 != src.size())
            throw RTE_LOC;

        u64* d = (u64*)dst.data();
        for (u64 i = 0; i < src.size();)
        {
            assert(d < (u64*)(dst.data() + dst.size()));
            *d = 0;
            for (u64 j = 0; j < 64; j += 2, ++i)
            {
                assert(src[i] < 3);
                *d |= u64(src[i]) << j;
            }
            ++d;
        }
    }

    inline void decompressMod3(span<u8> dst, span<const u8> src)
    {
        if (dst.size() != src.size() * 4)
            throw RTE_LOC;

        const u64* s = (const u64*)src.data();
        for (u64 i = 0; i < dst.size();)
        {
            auto ss = *s;
            assert(s < (u64*)(src.data() + src.size()));
            for (u64 j = 0; j < 32; ++j, ++i)
            {
                auto& dsti = dst[i];
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


    class DarkMatterPrfSender
    {
    public:
        block256 mKey;
        std::vector<oc::PRNG> mKeyOTs;
        oc::SilentOtExtSender mOtSender;

        std::vector<block256> mV, mU2, mW;
        std::vector<std::array<u64, 256>> mU;

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
                uui = oc::AlignedUnVector<u8>{},
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
                    for (u64 j = 0; j < y.size(); ++j)
                    {
                        mV[j] = mV[j] ^ vi[j] ^ mKeyOTs[i].get<block256>();
                    }
                    
                    for (u64 k = 0; k < ui.size(); ++k)
                    {
                        ui[k] ^= mKeyOTs[i].get<u8>();
                    }
                    
                    decompressMod3(uui, ui);
                }
                else
                {
                    sampleMod3(mKeyOTs[i], uui);
                    for (u64 j = 0; j < y.size(); ++j)
                    {
                        mV[j] = mV[j] ^ mKeyOTs[i].get<block256>();
                    }
                }

                for (u64 j = 0; j < y.size(); ++j)
                {
                    auto uij = uui.subspan(j * 256, 256);
                    for (u64 k = 0; k < 256; ++k)
                    {
                        mU[j][k] += uij[k];
                    }
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
            MC_AWAIT(mOtSender.silentSendInplace(prng.get(), y.size() * 512, prng, sock));
            diff.resize(y.size() * 512);
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
                        std::array<oc::block, 2> s0 { { *bIter, *bIter } };
                        ++bIter;
                        std::array<oc::block, 2> s1 { { *bIter, *bIter } };
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
    public:
        std::vector<std::array<oc::PRNG, 2>> mKeyOTs;
        oc::SilentOtExtReceiver mOtReceiver;


        std::vector<block256> mV, mU2, mW;
        std::vector<std::array<u64, 256>> mU;

        coproto::task<> evaluate(span<block256> x, span<oc::block> y, coproto::Socket& sock, oc::PRNG& prng)
        {
            MC_BEGIN(coproto::task<>, x, y, this, &sock, &prng,
                vi = oc::AlignedUnVector<block256>{},
                ui = oc::AlignedUnVector<u8>{},
                rKeys = oc::AlignedUnVector<oc::block>{},
                mod3 = oc::AlignedUnVector<u8>{},
                mod3i = oc::AlignedUnVector<u8>::iterator{},
                diff = oc::BitVector{},
                i = u64{}
            );

            mV.resize(x.size());
            mU.resize(x.size());
            mod3.resize(x.size() * 256);

            for (i = 0; i < 256; ++i)
            {
                vi.resize(x.size()); // x.size() * 256 bits
                ui.resize(x.size() * 256 / 4); // x.size() * 256 * 2 bits
                //prng.get(vi.data(), x.size());

                sampleMod3(mKeyOTs[i][0], mod3);
                mod3i = mod3.begin();

                for (u64 j = 0; j < x.size(); ++j)
                {
                    auto xji = x[j].rotate(i);
                    auto vij0 = mKeyOTs[i][0].get<block256>();
                    mV[j] = mV[j] ^ vij0;
                    vi[j] = vij0 ^ xji ^ mKeyOTs[i][1].get<block256>();

                    for (u64 k = 0; k < 256; ++k)
                    {
                        assert(*mod3i < 3);
                        auto& uijk = *mod3i++;
                        mU[j][k] += uijk;
                        uijk = (uijk + *oc::BitIterator((u8*)&xji, k)) % 3;
                    }
                }
                compressMod3(ui, mod3);

                for (u64 j = 0; j < ui.size(); ++j)
                {
                    ui[j] = ui[j] ^ mKeyOTs[i][1].get<u8>();
                }

                MC_AWAIT(sock.send(std::move(vi)));
                MC_AWAIT(sock.send(std::move(ui)));
            }

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
            MC_AWAIT(mOtReceiver.silentReceiveInplace(diff.size(), prng, sock, oc::ChoiceBitPacking::True));
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
