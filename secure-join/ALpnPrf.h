#pragma once
#include "secure-join/config.h"
#include "secure-join/Defines.h"
#include "cryptoTools/Common/BitIterator.h"
#include <bitset>
#include "libOTe/Tools/Tools.h"
#include "libOTe/TwoChooseOne/Silent/SilentOtExtSender.h"
#include "libOTe/TwoChooseOne/Silent/SilentOtExtReceiver.h"
#include "libOTe/TwoChooseOne/SoftSpokenOT/SoftSpokenShOtExt.h"
#include "DarkMatter22Prf.h"

namespace secJoin
{




    class ALpnPrf
    {
    public:
        static constexpr int KeySize = 256;
        oc::AlignedUnVector<u16> mKey;

        void setKey(oc::block k)
        {
            mKey = sampleMod3(oc::PRNG(k, 1), KeySize);
        }

        oc::block eval(oc::block x)
        {
            std::array<u16, KeySize> h;
            auto X = sampleMod3(oc::PRNG(x, 1), KeySize);
            block256 w;
            for (u64 i = 0; i < KeySize; ++i)
            {
                X[i] = (X[i] + mKey[i]) % 3;
                *oc::BitIterator((u8*)&w, i) = X[i] % 2;
            }
            return compress(w);
        }

        static inline oc::block compress(block256& w)
        {
            return DarkMatter22Prf::compress(w);
        }
    };

    class ALpnPrfSender : public oc::TimerAdapter
    {
        //std::vector<oc::PRNG> mKeyOTs;
    public:
#ifdef SECUREJOIN_DK_USE_SILENT
        oc::SilentOtExtSender mOtSender;
#else
        oc::SoftSpokenShOtSender<> mSoftSender;
#endif

        static constexpr auto StepSize = 32;
        static constexpr auto n = ALpnPrf::KeySize;
        static constexpr auto m = n;
        static constexpr auto t = 128;

        ALpnPrf mPrf;
        //oc::AlignedUnVector<std::array<u16, m>> mU;


        //void setKeyOts(span<oc::block> ots)
        //{
        //    if (ots.size() != mPrf.KeySize)
        //        throw RTE_LOC;
        //    mKeyOTs.resize(mPrf.KeySize);
        //    for (u64 i = 0; i < mPrf.KeySize; ++i)
        //    {
        //        mKeyOTs[i].SetSeed(ots[i]);
        //    }
        //}

        void setKey(oc::block k)
        {
            mPrf.setKey(k);
        }


        coproto::task<> evaluate(span<oc::block> y, coproto::Socket& sock, oc::PRNG& prng)
        {

            MC_BEGIN(coproto::task<>, y, this, &sock, &prng,
                buffer = oc::AlignedUnVector<u8>{},
                //uu = oc::AlignedUnVector<u16>{},
                f = oc::BitVector{},
                diff = oc::BitVector{},
                ots = oc::AlignedUnVector<std::array<oc::block, 2>>{},
                i = u64{}
            );

            setTimePoint("DarkMatter.sender.begin");
            //mU.resize(y.size());

            // mod 2

#ifdef SECUREJOIN_DK_USE_SILENT
            diff.resize(y.size() * m);
            MC_AWAIT(mOtSender.silentSendInplace(prng.get(), diff.size(), prng, sock));
            MC_AWAIT(sock.recv(diff));
            setTimePoint("DarkMatter.sender.silent");
#else
            ots.resize(y.size() * m * 2);
            setTimePoint("DarkMatter.sender.alloc");
#ifdef SECUREJOIN_ENABLE_FAKE_GEN
            memset(ots.data(), 0, sizeof(ots[0]) * ots.size());
            setTimePoint("DarkMatter.sender.memset");
#else
            MC_AWAIT(mSoftSender.send(ots, prng, sock));
            setTimePoint("DarkMatter.sender.soft");
#endif
#endif

            {
                f.resize(y.size() * m * 2);
                auto mask = oc::AllOneBlock ^ oc::OneBlock;
                auto f16Iter = (u16*)f.data();
#if defined(SECUREJOIN_DK_USE_SILENT)
                static_assert(0, "not impl");
                auto d16Iter = (u16*)diff.data();
                auto bIter = mOtSender.mB.begin();

                //auto fIter = f.begin();
                //auto rIter = rKeys.begin();
                for (u64 i = 0; i < y.size(); ++i)
                {
                    block256 w;
                    auto u8Iter = (u8*)&w;

                    for (u64 j = 0; j < 256; )
                    {
                        *u8Iter = 0;
                        *f16Iter = 0;
                        auto di = *d16Iter++;
                        for (u64 k = 0; k < 8; ++k, ++j)
                        {

                            std::array<oc::block, 4> s;
                            s[0] = *bIter;
                            s[1] = *bIter; ++bIter;
                            s[2] = *bIter;
                            s[3] = *bIter; ++bIter;

                            auto d0 = ((di) ^ 1) & 1;
                            auto d1 = ((di >> 1) ^ 1) & 1;
                            di = di >> 2;

                            s[d0] = s[d0] ^ mOtSender.mDelta;
                            s[d1 + 2] = s[d1 + 2] ^ mOtSender.mDelta;

                            s[0] = s[0] & mask;
                            s[1] = s[1] & mask;
                            s[2] = s[2] & mask;
                            s[3] = s[3] & mask;

                            oc::mAesFixedKey.hashBlocks<4>(s.data(), s.data());

                            auto q0 = (s[0].get<u8>(1) ^ s[2].get<u8>(1)) & 1;
                            auto q1 = (s[1].get<u8>(1) ^ s[2].get<u8>(1)) & 1;
                            auto q2 = (s[0].get<u8>(1) ^ s[3].get<u8>(1)) & 1;

                            //  them       us
                            //         0   1   2
                            //        ___________
                            //  0    | 0   1   0
                            //  1    | 1   0   0
                            //  2    | 0   0   1

                            //  0   -> u==1
                            //  1   -> u==0
                            //  2   -> u==2

                            auto uij = mU.data()[i].data()[j];
                            auto t0 = q0 ^ (uij == 1);
                            auto t1 = t0 ^ (uij == 0);
                            auto t2 = t0 ^ (uij == 2);
                            assert(t0 < 2);
                            *u8Iter |= t0 << k;
                            //*uIter++ = t0;
                            //*fIter++ = q1 ^ t1;
                            //*fIter++ = q2 ^ t2;
                            auto b1 = q1 ^ t1;
                            auto b2 = (q2 ^ t2) << 1;
                            *f16Iter |= (b1 ^ b2) << (2 * k);

                        }

                        ++f16Iter;
                        ++u8Iter;
                    }

                    y[i] = DarkMatter22Prf::compress(w);
                }
#else
                auto bIter = ots.data();

                for (u64 i = 0; i < y.size(); ++i)
                {

                    block256 w;
                    auto u8Iter = (u8*)&w;
                    for (u64 j = 0; j < 256; )
                    {
                        *u8Iter = 0;
                        *f16Iter = 0;
                        for (u64 k = 0; k < 8; ++k, ++j)
                        {
                            auto s = (oc::block*)bIter; bIter += 2;

                            auto q0 = (s[0] ^ s[2]).get<u8>(0) & 1;
                            auto q1 = (s[1] ^ s[2]).get<u8>(0) & 1;
                            auto q2 = (s[0] ^ s[3]).get<u8>(0) & 1;

                            //  them       us
                            //         0   1   2
                            //        ___________
                            //  0    | 0   1   0
                            //  1    | 1   0   0
                            //  2    | 0   0   1

                            //  0   -> u==1
                            //  1   -> u==0
                            //  2   -> u==2
                            auto uij = mPrf.mKey[j];
                            auto t0 = q0 ^ (uij == 1);
                            auto t1 = t0 ^ (uij == 0);
                            auto t2 = t0 ^ (uij == 2);

                            *u8Iter |= t0 << k;
                            auto b1 = q1 ^ t1;
                            auto b2 = (q2 ^ t2) << 1;
                            *f16Iter |= (b1 ^ b2) << (2 * k);
                        }

                        ++f16Iter;
                        ++u8Iter;
                    }


                    y[i] = DarkMatter22Prf::compress(w);
                }
#endif

            }
            MC_AWAIT(sock.send(std::move(f)));

            setTimePoint("DarkMatter.sender.derand");

            MC_END();
        }

    };

    class ALpnPrfReceiver : public oc::TimerAdapter
    {
        std::vector<std::array<oc::PRNG, 2>> mKeyOTs;
    public:
        oc::SilentOtExtReceiver mOtReceiver;
        oc::SoftSpokenShOtReceiver<> mSoftReceiver;


        static constexpr auto StepSize = 32;
        static constexpr auto n = ALpnPrf::KeySize;
        static constexpr auto m = n;
        static constexpr auto t = 128;

        coproto::task<> evaluate(span<oc::block> x, span<oc::block> y, coproto::Socket& sock, oc::PRNG& prng)
        {
            MC_BEGIN(coproto::task<>, x, y, this, &sock, &prng,
                X = oc::AlignedUnVector<std::array<u16, n>>{},
                buffer = oc::AlignedUnVector<u8>{},
                //h = oc::AlignedUnVector<u16>{},
                rKeys = oc::AlignedUnVector<oc::block>{},
                mod3 = oc::AlignedUnVector<u16>{},
                diff = oc::BitVector{},
                i = u64{},
                ots = oc::AlignedUnVector<oc::block>{},
                block3 = oc::block{},
                xPtr = (u32*)nullptr,
                compressedSize = u64{}
            );
            setTimePoint("DarkMatter.recver.begin");

            block3 = std::array<u16, 8>{3, 3, 3, 3, 3, 3, 3, 3};


            X.resize(x.size());
            for (u64 j = 0; j < x.size(); ++j)
            {
                sampleMod3(oc::PRNG(x[j], 1), X[j]);
            }
            setTimePoint("DarkMatter.recver.xMod3");

            // mod 2
            diff.resize(x.size() * m * 2);
            rKeys.resize(x.size() * m);

#ifdef SECUREJOIN_DK_USE_SILENT
            static_assert(0, "...");
            MC_AWAIT(mOtReceiver.silentReceiveInplace(diff.size(), prng, sock, oc::ChoiceBitPacking::True));
            setTimePoint("DarkMatter.recver.silent");

            {
                auto mask = oc::AllOneBlock ^ oc::OneBlock;
                auto dIter = diff.begin();
                auto aIter = mOtReceiver.mA.begin();
                auto rIter = rKeys.begin();
                for (u64 i = 0; i < x.size(); ++i)
                {
                    for (u64 j = 0; j < 256; ++j)
                    {
                        auto uij = mU.data()[i][j];
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

#else
            setTimePoint("DarkMatter.recver.choice");

            {
                auto dIter = diff.begin();
                for (u64 i = 0; i < x.size(); ++i)
                {
                    for (u64 j = 0; j < m; ++j)
                    {
                        auto uij = X.data()[i][j];
                        auto a0 = uij & 1;
                        auto a1 = (uij >> 1);
                        assert(a1 < 2);

                        *dIter++ = a0;
                        *dIter++ = a1 & 1;
                    }
                }
            }
            setTimePoint("DarkMatter.recver.diff");


            ots.resize(diff.size());
#ifdef SECUREJOIN_ENABLE_FAKE_GEN
            memset(ots.data(), 0, sizeof(ots[0]) * ots.size());
            setTimePoint("DarkMatter.recver.memset");
#else
            MC_AWAIT(mSoftReceiver.receive(diff, ots, prng, sock));
            setTimePoint("DarkMatter.recver.soft");
#endif
            for (u64 i = 0; i < rKeys.size(); ++i)
            {
                rKeys[i] = ots[i * 2] ^ ots[i * 2 + 1];
            }
            setTimePoint("DarkMatter.recver.rKey");

#endif

            buffer.resize(0);
            buffer.resize(x.size() * 256 / 4);

            MC_AWAIT(sock.recv(buffer));

            {
                //mU2.resize(x.size());
                auto fIter = oc::BitIterator((u8*)buffer.data());
                auto rIter = rKeys.begin();
                for (i = 0; i < x.size(); ++i)
                {
                    auto uij = X[i].data();
                    block256 w;
                    auto uIter = oc::BitIterator((u8*)&w);

                    for (u64 j = 0; j < 256; ++j, ++uij)
                    {
                        auto u = (rIter++->get<u8>(0) & 1);
                        assert(*uij < 3);

                        if (*uij)
                        {
                            u ^= *(fIter + (*uij - 1));
                        }

                        fIter = fIter + 2;
                        *uIter++ = u;
                    }

                    y[i] = DarkMatter22Prf::compress(w);
                }
            }
            setTimePoint("DarkMatter.recver.derand");

            MC_END();
        }

    };
}