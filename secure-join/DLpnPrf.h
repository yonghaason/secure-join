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




    class DLpnPrf
    {
    public:
        static constexpr int KeySize = 128;
        std::array<oc::block, KeySize / 128> mKey;
        //oc::AlignedUnVector<u16> mPi;

        //std::array<oc::block, 1024> mKeyMask;

        void setKey(oc::block k)
        {
            mKey = oc::PRNG(k).get();
            //std::array<block256, 2> zeroOne;
            //memset(&zeroOne[0], 0, sizeof(zeroOne[0]));
            //memset(&zeroOne[1], -1, sizeof(zeroOne[1]));

            //for (u64 i = 0; i < 256; ++i)
            //    mKeyMask[i] = zeroOne[*oc::BitIterator((u8*)&k, i)];

            //mPi = samplePerm(oc::ZeroBlock, KeySize);
        }

        void compressH(std::array<u16, KeySize>& hj, block256m3& uj)
        {
            //for (u64 k = 0; k < KeySize; ++k)
            //{
            //    uj.mData[k] = hj[k];
            //}


            //assert(mPi.size() != 0);
            if constexpr (KeySize == 128)
            {
                uj.mData[0] = hj[0];
                for (u64 k = 1; k < KeySize; ++k)
                {
                    uj.mData[k] = hj[k] + uj.mData[k - 1];
                    uj.mData[k] = uj.mData[k] % 3;
                }

                for (u64 k = 128; k < 256; ++k)
                {
                    //uj.mData[k] = hj[k-128] + uj.mData[k-128];
                    uj.mData[k] = uj.mData[k-128];
                }

            }
            else if constexpr (KeySize == 256)
            {


                uj.mData[0] = hj[0];
                for (u64 k = 1; k < KeySize; ++k)
                {
                    uj.mData[k] = hj[k] + uj.mData[k - 1];
                    uj.mData[k] = uj.mData[k] % 3;
                }
            }
            else if constexpr (KeySize == 512)
            {
                assert(0);
                //auto pik = mPi.data();
                //for (u64 k = 0; k < 256; ++k)
                //{
                //    uj.mData[k] = (
                //        hj[pik[0]] +
                //        hj[pik[1]]
                //        ) % 3;
                //    pik += 2;
                //}
            }
            else
            {
                assert(0);
            }
        }

        oc::block eval(oc::block x)
        {
            std::array<u16, KeySize> h;
            std::array<oc::block, KeySize / 128> X;
            for (u64 i = 0; i < X.size(); ++i)
                X[i] = x ^ oc::block(i, i);
            oc::mAesFixedKey.hashBlocks<X.size()>(X.data(), X.data());

            auto kIter = oc::BitIterator((u8*)mKey.data());
            auto xIter = oc::BitIterator((u8*)X.data());
            for (u64 i = 0; i < KeySize; ++i)
            {
                h[i] = *kIter & *xIter;

                //if (i < 20)
                //    std::cout << "h[" << i << "] = " << h[i] 
                //    << " = " << *kIter 
                //    <<" & " << *xIter <<std::endl;

                ++kIter;
                ++xIter;
            }

            block256m3 u;
            compressH(h, u);

            block256 w;
            for (u64 i = 0; i < u.mData.size(); ++i)
            {
                //if (i < 10)
                //    std::cout << "u[" << i << "] = " << (int)u.mData[i] << std::endl;

                *oc::BitIterator((u8*)&w, i) = u.mData[i] % 2;
            }
            return compress(w);
        }

        static inline oc::block compress(block256& w)
        {
            return DarkMatter22Prf::compress(w);
        }
    };

    template<int keySize>
    inline void compressH(
        oc::span<const u16> mH,
        oc::AlignedUnVector<std::array<u16, 256>>& mU
    )
    {
        if constexpr (keySize == 256)
        {

            auto n = mH.size() / keySize;
            auto& h2 = mH;

            for (u64 j = 0; j < n; ++j)
            {
                mU.data()[j].data()[0] = h2.data()[j];
            }
            for (u64 k = 1; k < keySize; ++k)
            {
                auto hk = h2.data() + k * n;
                auto hk1 = h2.data() + ((k - 1) * n);

                for (u64 j = 0; j < n; ++j)
                {
                    hk[j] += hk1[j];
                    hk[j] %= 3;

                    mU.data()[j].data()[k] = hk[j];
                }
            }
        }
        else if constexpr (keySize == 128)
        {

            auto n = mH.size() / keySize;
            auto& h2 = mH;

            for (u64 j = 0; j < n; ++j)
            {
                mU.data()[j].data()[0] = h2.data()[j];
            }
            for (u64 k = 1; k < keySize; ++k)
            {
                auto hk = h2.data() + k * n;
                //auto hk1 = h2.data() + ((k - 1) * n);

                for (u64 j = 0; j < n; ++j)
                {
                    //assert(hk[j] < 3);
                    assert(hk[j] < 3);

                    auto prev = mU.data()[j].data()[k-1];
                    auto cur = prev + hk[j];

                    assert(cur < 6);
                    __assume(cur < 6);
                    cur %= 3;

                    mU.data()[j].data()[k] = cur;
                }
            }

            for (u64 k = 128; k < 256; ++k)
            {
                //auto hk = h2.data() + (k) * n;
                //auto hk1 = h2.data() + (k - 128) * n;

                for (u64 j = 0; j < n; ++j)
                {
                    //hk[j] = hk1[j] + mU.data()[j].data()[k-128];

                    //assert(hk[j] < 6);
                    //__assume(hk[j] < 6);
                    //hk[j] %= 3;

                    mU.data()[j].data()[k] = mU.data()[j].data()[k-128];

                }
            }
        }
        else
        {
            assert(0);

            //auto& uj = mU[j];
            //auto pik = mPrf.mPi.data();
            //for (u64 k = 0; k < m; ++k)
            //{
            //    auto h0 = h2.data() + pik[0] * y.size();
            //    auto h1 = h2.data() + pik[1] * y.size();
            //    pik += 2;
            //    for (u64 j = 0; j < y.size(); ++j)
            //    {
            //        auto& ujk = mU.data()[j].data()[k];
            //        ujk = (h0[j] + h1[j]) % 3;
            //        //mU[j][k] = (3 - mU[j][k]) % 3;

            //        ujk =
            //            ((ujk & 2) >> 1) |
            //            ((ujk & 1) << 1);

            //    }
            //}
        }
    }

    class DLpnPrfSender : public oc::TimerAdapter
    {
        std::vector<oc::PRNG> mKeyOTs;
    public:
#ifdef SECUREJOIN_DK_USE_SILENT
        oc::SilentOtExtSender mOtSender;
#else
        oc::SoftSpokenShOtSender<> mSoftSender;
#endif

        static constexpr auto StepSize = 32;
        static constexpr auto n = DLpnPrf::KeySize;
        static constexpr auto m = 256;
        static constexpr auto t = 128;
        DLpnPrf mPrf;
        //std::vector<block256> mU2;
        oc::AlignedUnVector<std::array<u16, m>> mU;
        oc::AlignedUnVector<u16> mH;


        void setKeyOts(span<oc::block> ots)
        {
            if (ots.size() != mPrf.KeySize)
                throw RTE_LOC;
            mKeyOTs.resize(mPrf.KeySize);
            for (u64 i = 0; i < mPrf.KeySize; ++i)
            {
                mKeyOTs[i].SetSeed(ots[i]);
            }
        }

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
                i = u64{},
                compressedSizeAct = u64{},
                compressedSize = u64{}
            );

            setTimePoint("DarkMatter.sender.begin");
            mU.resize(y.size());

            //xk
            //uu.resize(y.size());

            // y.size() rows, each of size 1024
            mH.resize(y.size() * mPrf.KeySize);
            compressedSizeAct = oc::divCeil(y.size(), 4);
            compressedSize = oc::roundUpTo(compressedSizeAct, sizeof(oc::block));
            for (i = 0; i < mPrf.KeySize;)
            {
                buffer.resize(compressedSize * StepSize); // y.size() * 256 * 2 bits

                MC_AWAIT(sock.recv(buffer));
                for (u64 k = 0; k < StepSize; ++i, ++k)
                {
                    auto ui = buffer.subspan(compressedSize * k, compressedSizeAct);
                    auto hh = mH.subspan(i * y.size(), y.size());

                    u8 ki = *oc::BitIterator((u8*)&mPrf.mKey, i);
                    if (ki)
                    {
                        // ui = ui ^ H(mKeyOTs[i])
                        //std::cout << "recv ui " << int(ui[0]) << std::endl;
                        xorVector(ui, mKeyOTs[i]);
                        //std::cout << "recv ui " << int(ui[0]) << std::endl;
                        decompressMod3(hh, ui);
                    }
                    else
                    {
                        sampleMod3(mKeyOTs[i], hh);
                    }

                    //for (u64 j = 0; j < y.size(); ++j)
                    //{

                    //    if (j == 1)
                    //    {
                    //        std::cout << i << " r " << hh[j] << std::endl;
                    //    }
                    //}
                }
            }

            //if (mPrf.mPi.size() == 0)
            //{
            //    mPrf.mPi = samplePerm(oc::ZeroBlock, mPrf.KeySize);
            //}

            compressH<DLpnPrf::KeySize>(mH, mU);


            setTimePoint("DarkMatter.sender.kxMult");

            // mod 2

#ifdef SECUREJOIN_DK_USE_SILENT
            diff.resize(y.size() * m);
            MC_AWAIT(mOtSender.silentSendInplace(prng.get(), diff.size(), prng, sock));
            MC_AWAIT(sock.recv(diff));
            setTimePoint("DarkMatter.sender.silent");
#else
            ots.resize(y.size() * m * 2);
#ifdef SECUREJOIN_ENABLE_FAKE_GEN
            //memset(ots.data(), 0, sizeof(ots[0]) * ots.size());
#else
            MC_AWAIT(mSoftSender.send(ots, prng, sock));
#endif
            setTimePoint("DarkMatter.sender.soft");
#endif

            {
                f.resize(y.size() * m * 2);
                auto mask = oc::AllOneBlock ^ oc::OneBlock;
                auto f16Iter = (u16*)f.data();
#if defined(SECUREJOIN_DK_USE_SILENT)
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



                            auto Q0 = (s[0] ^ s[2]) & oc::OneBlock;
                            auto Q1 = (s[1] ^ s[2]) & oc::OneBlock;
                            auto Q2 = (s[0] ^ s[3]) & oc::OneBlock;

                            auto q0 = ((u8*)&Q0)[0];
                            auto q1 = ((u8*)&Q1)[0];
                            auto q2 = ((u8*)&Q2)[0];

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

    class DLpnPrfReceiver : public oc::TimerAdapter
    {
        std::vector<std::array<oc::PRNG, 2>> mKeyOTs;
    public:
        oc::SilentOtExtReceiver mOtReceiver;
        oc::SoftSpokenShOtReceiver<> mSoftReceiver;

        //std::vector<block256> mH, ;
        oc::AlignedUnVector<std::array<u16, 256>> mU;
        oc::AlignedUnVector<u16> mH;


        static constexpr auto StepSize = 32;
        static constexpr auto n = DLpnPrf::KeySize;
        static constexpr auto m = 256;
        static constexpr auto t = 128;
        DLpnPrf mPrf;
        //oc::AlignedUnVector<u16> mPi;

        void setKeyOts(span<std::array<oc::block, 2>> ots)
        {
            if (ots.size() != mPrf.KeySize)
                throw RTE_LOC;
            mKeyOTs.resize(mPrf.KeySize);
            for (u64 i = 0; i < mPrf.KeySize; ++i)
            {
                mKeyOTs[i][0].SetSeed(ots[i][0]);
                mKeyOTs[i][1].SetSeed(ots[i][1]);
            }
        }


        coproto::task<> evaluate(span<oc::block> x, span<oc::block> y, coproto::Socket& sock, oc::PRNG& prng)
        {
            MC_BEGIN(coproto::task<>, x, y, this, &sock, &prng,
                X = oc::AlignedUnVector<std::array<oc::block, DLpnPrf::KeySize / 128>>{},
                buffer = oc::AlignedUnVector<u8>{},
                //h = oc::AlignedUnVector<u16>{},
                rKeys = oc::AlignedUnVector<oc::block>{},
                mod3 = oc::AlignedUnVector<u16>{},
                diff = oc::BitVector{},
                i = u64{},
                ots = oc::AlignedUnVector<oc::block>{},
                block3 = oc::block{},
                xPtr = (u32*)nullptr,
                compressedSizeAct = u64{},
                compressedSize = u64{}
            );
            setTimePoint("DarkMatter.recver.begin");

            block3 = std::array<u16, 8>{3, 3, 3, 3, 3, 3, 3, 3};
            mU.resize(x.size());


            X.resize(x.size());
            for (u64 j = 0; j < x.size(); ++j)
            {
                for (i = 0; i < DLpnPrf::KeySize/128; ++i)
                {
                    X[j][i] = x[j] ^ oc::block(i, i);
                }
                oc::mAesFixedKey.hashBlocks<DLpnPrf::KeySize / 128>(X[j].data(), X[j].data());
            }
            ////xk
            //uu.resize(y.size() * 4);

            //// y.size() rows, each of size 1024
            //h.resize(uu.size() * 256);
            assert(mPrf.KeySize % StepSize == 0);
            mod3.resize(y.size());
            mH.resize(y.size() * mPrf.KeySize);
            compressedSizeAct = oc::divCeil(y.size(), 4);
            compressedSize = oc::roundUpTo(compressedSizeAct, sizeof(oc::block));
            for (i = 0; i < mPrf.KeySize;)
            {
                static_assert(StepSize == sizeof(*xPtr) * 8, "failed static_assert: StepSize == sizeof(*xPtr) * 8");
                buffer.resize(compressedSize * StepSize);
                for (u64 k = 0; k < StepSize; ++i, ++k)
                {
                    auto ui = buffer.subspan(compressedSize * k, compressedSizeAct);
                    auto hi = mH.subspan(y.size() * i, y.size());
                    xPtr = (u32*)X.data() + i / StepSize;

                    sampleMod3(mKeyOTs[i][0], hi);
                    for (u64 j = 0; j < y.size(); ++j)
                    {
                        assert(hi.data()[j] < 3);
                        //assert()

                        //assert((*xPtr & 1) == *oc::BitIterator((u8*)&X[j], i));

                        mod3.data()[j] = hi.data()[j] + (*xPtr & 1);
                        mod3[j] %= 3;

                        auto neg = ((hi.data()[j] << 1) | (hi.data()[j] >> 1)) & 3 ;
                        assert(neg == ((3 - hi.data()[j]) % 3));

                        //if (j == 1)
                        //{
                        //    std::cout << i << " s " << neg << " vs " << hi.data()[j] << " " << mod3[j] << "   x " << (*xPtr & 1) << std::endl;
                        //}
                        hi.data()[j] = neg;


                        *xPtr >>= 1;
                        xPtr += mPrf.KeySize / StepSize;
                    }

                    compressMod3(ui, mod3);
                    xorVector(ui, mKeyOTs[i][1]);
                }
                MC_AWAIT(sock.send(std::move(buffer)));
            }

            compressH<DLpnPrf::KeySize>(mH, mU);

            setTimePoint("DarkMatter.recver.mod2");

            // mod 2
            diff.resize(x.size() * m * 2);
            rKeys.resize(x.size() * m);

#ifdef SECUREJOIN_DK_USE_SILENT
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
                auto d64Iter = (u64*)diff.data();
                for (u64 i = 0; i < x.size(); ++i)
                {
                    for (u64 j = 0; j < m;)
                    {
                        *d64Iter = 0;
                        for (u64 k = 0; k < 64; k += 2, ++j)
                        {

                            u64 uij = mU.data()[i][j];
                            auto a0 = uij & 1;
                            auto a1 = (uij >> 1);
                            assert(a1 < 2);

                            *d64Iter |= a0 << (k);
                            *d64Iter |= a1 << (k + 1);;
                        }

                        ++d64Iter;
                    }
                }
            }

            ots.resize(diff.size());
#ifdef SECUREJOIN_ENABLE_FAKE_GEN
            //memset(ots.data(), 0, sizeof(ots[0]) * ots.size());
#else
            MC_AWAIT(mSoftReceiver.receive(diff, ots, prng, sock));
#endif
            {
                auto otIter = ots.data();
                for (u64 i = 0; i < rKeys.size(); ++i)
                {
                    rKeys.data()[i] = otIter[0] ^ otIter[1];
                    otIter += 2;
                }
            }
            setTimePoint("DarkMatter.recver.soft");

#endif
            buffer.resize(0);
            buffer.resize(x.size() * 256 / 4);

            MC_AWAIT(sock.recv(buffer));

            {
                auto f16Iter = (u16*)buffer.data();
                auto rIter = rKeys.begin();
                for (i = 0; i < x.size(); ++i)
                {
                    auto uij = mU[i].data();
                    block256 w;
                    auto u8Iter = (u8*)&w;

                    for (u64 j = 0; j < 256;)
                    {
                        *u8Iter = 0;
                        for (u64 k = 0; k < 8; ++k, ++j, ++uij)
                        {
                            auto u = (rIter++->get<u8>(0) & 1);
                            assert(*uij < 3);

                            if (*uij)
                            {
                                u ^= (*f16Iter >> (*uij - 1)) & 1;
                            }

                            *f16Iter = *f16Iter >> 2;
                            *u8Iter ^= u << k;
                        }


                        ++f16Iter;
                        ++u8Iter;
                    }

                    y[i] = DarkMatter22Prf::compress(w);
                }
            }
            setTimePoint("DarkMatter.recver.derand");

            MC_END();
}

    };
}
