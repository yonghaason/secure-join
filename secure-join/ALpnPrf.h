#pragma once
#include "secure-join/config.h"
#include "secure-join/Defines.h"
#include "cryptoTools/Common/BitIterator.h"
#include <bitset>
#include "libOTe/Tools/Tools.h"
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
        std::vector<oc::PRNG> mKeyOTs;
    public:

        static constexpr auto n = ALpnPrf::KeySize;
        static constexpr auto t = 128;

        ALpnPrf mPrf;

        oc::BitVector getKeyChoiceBits()
        {
            oc::BitVector ret(n * 2);
            for (u64 i = 0; i < n; ++i)
            {
                ret[i * 2] = mPrf.mKey[i] == 1;
                ret[i * 2 + 1] = mPrf.mKey[i] == 2;
            }
            return ret;
        }

        void setKeyOts(span<oc::block> ots)
        {
            if (ots.size() != n * 2)
                throw RTE_LOC;

            mKeyOTs.resize(n);
            for (u64 i = 0; i < n; ++i)
            {
                mKeyOTs[i].SetSeed(ots[i * 2] ^ ots[i * 2 + 1]);
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
                i = u64{}
            );

            setTimePoint("DarkMatter.sender.begin");
            //mU.resize(y.size());

            // mod 2

            buffer.resize(0);
            buffer.resize(y.size() * 256 / 4);

            MC_AWAIT(sock.recv(buffer));

            {
                //mU2.resize(x.size());
                //auto fIter = oc::BitIterator((u8*)buffer.data());
                auto f16Iter = (u16*)buffer.data();
                std::array<u64, 256> kBuff;


                for (i = 0; i < y.size(); ++i)
                {
                    auto s = i % 64;
                    if (s == 0)
                    {
                        for (u64 j = 0; j < 256; ++j)
                        {
                            kBuff[j] = mKeyOTs[j].get<u64>();
                        }
                    }

                    auto uij = mPrf.mKey.data();
                    block256 w;
                    auto u8Iter = (u8*)&w;

                    for (u64 j = 0; j < n;)
                    {
                        //auto u = mKeyOTs[j].get<u8>();
                        //u &= 1;
                        *u8Iter = 0;
                        for (u64 k = 0; k < 8; ++k, ++j, ++uij)
                        {

                            auto u = (kBuff[j] >> s) & 1;

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

    class ALpnPrfReceiver : public oc::TimerAdapter
    {
        std::vector<std::array<oc::PRNG, 3>> mKeyOTs;
    public:
        static constexpr auto n = ALpnPrf::KeySize;
        static constexpr auto t = 128;

        void setKeyOts(span<std::array<oc::block, 2>> ots)
        {
            if (ots.size() != n * 2)
                throw RTE_LOC;

            mKeyOTs.resize(n);
            for (u64 i = 0; i < n; ++i)
            {
                mKeyOTs[i][0].SetSeed(ots[i * 2][0] ^ ots[i * 2 + 1][0]);
                mKeyOTs[i][1].SetSeed(ots[i * 2][1] ^ ots[i * 2 + 1][0]);
                mKeyOTs[i][2].SetSeed(ots[i * 2][0] ^ ots[i * 2 + 1][1]);
            }
        }

        coproto::task<> evaluate(span<oc::block> x, span<oc::block> y, coproto::Socket& sock, oc::PRNG& prng)
        {
            MC_BEGIN(coproto::task<>, x, y, this, &sock, &prng,
                X = oc::AlignedUnVector<std::array<u16, n>>{},
                f = oc::BitVector{},
                i = u64{}
            );
            setTimePoint("DarkMatter.recver.begin");

            X.resize(x.size());
            for (u64 j = 0; j < x.size(); ++j)
            {
                sampleMod3(oc::PRNG(x[j], 1), X[j]);
            }
            setTimePoint("DarkMatter.recver.xMod3");

            {
                f.resize(y.size() * n * 2);
                auto mask = oc::AllOneBlock ^ oc::OneBlock;
                auto f16Iter = (u16*)f.data();

                std::array<std::array<u64, 3>, 256> kBuff;


                for (u64 i = 0; i < y.size(); ++i)
                {
                    auto s = i % 64;
                    if (s == 0)
                    {
                        for (u64 j = 0; j < 256; ++j)
                        {
                            kBuff[j][0] = mKeyOTs[j][0].get<u64>();
                            kBuff[j][1] = mKeyOTs[j][1].get<u64>();
                            kBuff[j][2] = mKeyOTs[j][2].get<u64>();
                        }
                    }

                    block256 w;
                    auto u8Iter = (u8*)&w;
                    for (u64 j = 0; j < 256; )
                    {
                        *u8Iter = 0;
                        *f16Iter = 0;
                        for (u64 k = 0; k < 8; ++k, ++j)
                        {

                            auto q0 = (kBuff[j][0] >> s) & 1;
                            auto q1 = (kBuff[j][1] >> s) & 1;
                            auto q2 = (kBuff[j][2] >> s) & 1;

                            //  them       us
                            //         0   1   2
                            //        ___________
                            //  0    | 0   1   0
                            //  1    | 1   0   0
                            //  2    | 0   0   1

                            //  0   -> u==1
                            //  1   -> u==0
                            //  2   -> u==2
                            auto uij = X[i][j];
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

            }
            MC_AWAIT(sock.send(std::move(f)));

            setTimePoint("DarkMatter.sender.derand");

            MC_END();
        }

    };
}