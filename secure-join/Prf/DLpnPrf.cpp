

#include "DLpnPrf.h"


namespace secJoin
{


    const std::array<block256, 128> DLpnPrf::mB = oc::PRNG(oc::block(2134, 5437)).get<std::array<block256, 128>>();
    const std::array<block256, 128> DLpnPrf::mBShuffled = []() {

        std::array<block256, 128> shuffled;
        for (u64 i = 0; i < shuffled.size(); ++i)
        {
            auto iter0 = oc::BitIterator((u8*)&mB[i].mData[0]);
            auto iter1 = oc::BitIterator((u8*)&mB[i].mData[1]);
            auto dest = oc::BitIterator((u8*)&shuffled[i]);
            for (u64 j = 0; j < 128; ++j)
            {
                *dest++ = *iter0++;
                *dest++ = *iter1++;
            }
        }
        return shuffled;
    }();



    void  DLpnPrf::setKey(oc::block k)
    {
        mKey[0] = k;
    }

    void  DLpnPrf::compressH(const std::array<u16, KeySize>& hj, block256m3& uj)
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
                uj.mData[k] = uj.mData[k - 128];
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

    oc::block  DLpnPrf::eval(oc::block x)
    {
        std::array<u16, KeySize> h;
        std::array<oc::block, KeySize / 128> X;
        if constexpr (DLpnPrf::KeySize / 128 > 1)
        {

            for (u64 i = 0; i < X.size(); ++i)
                X[i] = x ^ oc::block(i, i);
            oc::mAesFixedKey.hashBlocks<X.size()>(X.data(), X.data());
        }
        else
            X[0] = x;

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

    oc::block  DLpnPrf::compress(block256& w)
    {
        return compress(w, mB);
    }

    oc::block  DLpnPrf::shuffledCompress(block256& w)
    {
        return compress(w, mBShuffled);
    }

    oc::block  DLpnPrf::compress(block256& w, const std::array<block256, 128>& B)
    {
        alignas(32) std::array<std::array<oc::block, 128>, 2> bw;

        for (u64 i = 0; i < 128; ++i)
        {
            bw[0][i] = B[i].mData[0] & w.mData[0];
            bw[1][i] = B[i].mData[1] & w.mData[1];
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



    template<int keySize>
    inline void compressH(
        oc::Matrix<u16>&& mH,
        oc::Matrix<u16>& mU
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
                    auto v = hk[j] + hk1[j];
                    v %= 3;

                    mU.data()[j].data()[k] = v;
                }
            }
        }
        else if constexpr (keySize == 128)
        {

            auto n = mH.size() / keySize;
            auto& h2 = mH;

            for (u64 i = 1; i < keySize; ++i)
            {
                auto h0 = h2.data() + n * (i - 1);
                auto h1 = h2.data() + n * (i);
                for (u64 j = 0; j < n; ++j)
                {
                    auto h0j = h0[j];
                    auto h1j = h1[j];
                    //__assume(h0j < 3);
                    //__assume(h1j < 3);
                    // 000 0
                    // 001 1
                    // 010 2
                    // 011 3
                    // 100 4

                    auto s = (h0j + h1j);
                    __assume(s < 5);
                    auto q = s == 3 || s == 4;
                    h1[j] = s - 3 * q;
                    assert(h1[j] == (h0j + h1j) % 3);
                }
            }

            for (u64 i = 0; i < keySize; ++i)
            {
                auto hi = mH[i];
                for (u64 j = 0; j < n; ++j)
                {
                    mU[j][i] = hi[j];
                    mU[j][i + keySize] = hi[j];
                }
            }
            //for (u64 k = 1; k < keySize; ++k)
            //{
            //    auto hk = h2.data() + k * n;
            //    //auto hk1 = h2.data() + ((k - 1) * n);

            //    for (u64 j = 0; j < n; ++j)
            //    {
            //        //assert(hk[j] < 3);
            //        assert(hk[j] < 3);

            //        auto prev = mU.data()[j].data()[k-1];
            //        auto cur = prev + hk[j];

            //        assert(cur < 6);
            //        //__assume(cur < 6);
            //        cur %= 3;

            //        mU.data()[j].data()[k] = cur;
            //    }
            //}

            //for (u64 k = 128; k < 256; ++k)
            //{
            //    //auto hk = h2.data() + (k) * n;
            //    //auto hk1 = h2.data() + (k - 128) * n;

            //    for (u64 j = 0; j < n; ++j)
            //    {
            //        //hk[j] = hk1[j] + mU.data()[j].data()[k-128];

            //        //assert(hk[j] < 6);
            //        //__assume(hk[j] < 6);
            //        //hk[j] %= 3;

            //        mU.data()[j].data()[k] = mU.data()[j].data()[k-128];

            //    }
            //}
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

        mH = {};
    }

    template<int keySize>
    inline void compressH2(
        oc::Matrix<u16>&& mH,
        oc::Matrix<u16>& mU
    )
    {
        static_assert(keySize == 128);
        assert(mH.rows() % keySize == 0);
        assert(mU.rows() % keySize == 0);
        {
            auto n = mH.size() / keySize;
            auto& h2 = mH;

            for (u64 i = 1; i < keySize; ++i)
            {
                auto h0 = h2.data() + n * (i - 1);
                auto h1 = h2.data() + n * (i);
                for (u64 j = 0; j < n; ++j)
                {
                    auto h0j = h0[j];
                    auto h1j = h1[j];
                    //__assume(h0j < 3);
                    //__assume(h1j < 3);
                    // 000 0
                    // 001 1
                    // 010 2
                    // 011 3
                    // 100 4

                    auto s = (h0j + h1j);
                    __assume(s < 5);
                    auto q = s == 3 || s == 4;
                    h1[j] = s - 3 * q;
                    assert(h1[j] == (h0j + h1j) % 3);
                }
            }

            for (u64 i = 0; i < keySize; ++i)
            {
                auto hi = &mH[i * n];
                for (u64 j = 0; j < n; ++j)
                {
                    mU[j][i] = hi[j];
                    mU[j][i + keySize] = hi[j];
                }
            }
        }

        mH = {};
    }



    macoro::task<> DLpnPrfSender::genKeyOts(OleGenerator& ole)
    {
        MC_BEGIN(macoro::task<>, this, &ole,
            totalSize = u64(),

            ots = OtRecv(),
            req = Request<OtRecv>(),
            keyBlock = oc::block());

        totalSize = 128;

        MC_AWAIT_SET(req, ole.otRecvRequest(totalSize));

        MC_AWAIT_SET(ots, req.get());

        assert(ots.size() == totalSize);

        keyBlock = ots.mChoice.getSpan<oc::block>()[0];
        setKey(keyBlock);
        setKeyOts(ots.mMsg);

        MC_END();
    }

    void DLpnPrfSender::setKeyOts(span<oc::block> ots)
    {
        if (ots.size() != mPrf.KeySize)
            throw RTE_LOC;
        mKeyOTs.resize(mPrf.KeySize);
        for (u64 i = 0; i < mPrf.KeySize; ++i)
        {
            //auto ki = *oc::BitIterator((u8*) &mPrf.mKey, i);
            //std::cout << "r" <<i << " " << ots[i] << " " << ki << std::endl;
            mKeyOTs[i].SetSeed(ots[i]);
        }
        mIsKeyOTsSet = true;
    }

    void DLpnPrfSender::setKey(oc::block k)
    {
        mPrf.setKey(k);
        mIsKeySet = true;
    }


    coproto::task<> DLpnPrfSender::evaluate(
        span<oc::block> y,
        coproto::Socket& sock,
        oc::PRNG& _,
        OleGenerator& gen)
    {

        MC_BEGIN(coproto::task<>, y, this, &sock, &gen,
            buffer = oc::AlignedUnVector<u8>{},
            //uu = oc::AlignedUnVector<u16>{},
            f = oc::BitVector{},
            diff = oc::BitVector{},
            ots = oc::AlignedUnVector<std::array<oc::block, 2>>{},
            i = u64{},
            compressedSizeAct = u64{},
            compressedSize = u64{},
            ole = Request<BinOle>{}
        );

        if (!mIsKeyOTsSet)
            MC_AWAIT(genKeyOts(gen));

        if (mDebug)
        {
            ots.resize(mKeyOTs.size());
            MC_AWAIT(sock.recv(ots));
            for (u64 i = 0; i < ots.size(); ++i)
            {
                auto ki = *oc::BitIterator((u8*)&mPrf.mKey, i);
                if (ots[i][ki] != mKeyOTs[i].getSeed())
                {
                    std::cout << "bad key ot " << i << "\nki=" << ki << " " << mKeyOTs[i].getSeed() << " vs \n"
                        << ots[i][0] << " " << ots[i][1] << std::endl;

                    throw RTE_LOC;
                }
            }
        }

        setTimePoint("DarkMatter.sender.begin");

        MC_AWAIT_SET(ole, gen.binOleRequest(y.size() * m * 2));

        //xk
        //uu.resize(y.size());

        // y.size() rows, each of size 1024
        mH.resize(mPrf.KeySize, y.size());
        compressedSizeAct = oc::divCeil(y.size(), 4);
        compressedSize = oc::roundUpTo(compressedSizeAct, sizeof(oc::block));
        for (i = 0; i < mPrf.KeySize;)
        {
            buffer.resize(compressedSize * StepSize); // y.size() * 256 * 2 bits

            MC_AWAIT(sock.recv(buffer));
            for (u64 k = 0; k < StepSize; ++i, ++k)
            {
                auto ui = buffer.subspan(compressedSize * k, compressedSizeAct);
                auto hh = mH[i];

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

        if (1)
        {
            mU.resize(y.size(), m, oc::AllocType::Uninitialized);

            if (mDebug)
            {
                compressH<DLpnPrf::KeySize>(coproto::copy(mH), mU);
            }
            else
            {
                compressH<DLpnPrf::KeySize>(std::move(mH), mU);
            }


            setTimePoint("DarkMatter.sender.kxMult");

            // mod 2
            MC_AWAIT(mod2Compress(mU, y, sock, ole));
        }
        else
        {

            mU.resize(m, y.size());
        }

        MC_END();
    }

    macoro::task<> DLpnPrfSender::mod2Compress(
        oc::MatrixView<u16> u,
        span<oc::block> out,
        coproto::Socket& sock,
        Request<BinOle>& ole)
    {
        MC_BEGIN(macoro::task<>, u, out, &sock, &ole,
            triple = BinOle{},
            tIter = std::vector<BinOle>::iterator{},
            tIdx = u64{},
            tSize = u64{},
            i = u64{},
            step = u64{},
            buff = oc::AlignedUnVector<oc::block>{},
            buffW = oc::AlignedUnVector<oc::block>{},
            mask0 = oc::block{},
            mask1 = oc::block{}
        );

        memset(&mask0, 0b01010101, sizeof(mask0));
        memset(&mask1, 0b10101010, sizeof(mask0));

        if (mDebug)
            MC_AWAIT(sock.send(u));

        tIdx = 0;
        tSize = 0;
        for (i = 0; i < u.rows();)
        {
            MC_AWAIT_SET(triple, ole.get());


            tSize = triple.mAdd.size();
            tIdx = 0;
            buff.resize(tSize);
            MC_AWAIT(sock.recv(buff));

            if (mDebug)
                buffW.resize(buff.size() / 2);

            step = std::min<u64>(u.rows() - i, tSize / mNumOlePer);
            assert(tSize % mNumOlePer == 0);
            for (u64 j = 0; j < step; ++j, ++i, tIdx += 4)
            {
                auto x = &triple.mAdd[tIdx];
                auto y = &triple.mMult[tIdx];
                auto d = &buff[tIdx];

                for (u64 k = 0; k < 4; ++k)
                {
                    x[k] = x[k] ^ (y[k] & d[k]);
                }

                std::array<oc::block, mNumOlePer> packedU;
                block256 q0, q1, q2, t0, t1, t2;
                q0[0] = x[0] ^ x[2];
                q0[1] = x[1] ^ x[3];
                q1[0] = q0[0] ^ y[0];
                q1[1] = q0[1] ^ y[1];
                q2[0] = q0[0] ^ y[2];
                q2[1] = q0[1] ^ y[3];

                std::array<oc::block, mNumOlePer> t;
                auto iter = (u8*)&t;
                for (u64 k = 0; k < m; k += 4)
                {
                    *iter++ =
                        (u[i][k + 0] << 0) |
                        (u[i][k + 1] << 2) |
                        (u[i][k + 2] << 4) |
                        (u[i][k + 3] << 6);
                }

                if (mDebug)
                {
                    auto iter = oc::BitIterator((u8*)&t);
                    for (u64 k = 0; k < m; ++k)
                    {
                        if (*iter++ != (u[i][k] & 1))
                            throw RTE_LOC;
                        if (*iter++ != (u[i][k] >> 1))
                            throw RTE_LOC;
                    }
                }
                // even bits in perfect shuffled order
                // eg: 0 128 2 130 4 132 6 134 ... 126 254
                packedU[0] =
                    (t[0] & mask0) |
                    ((t[2] & mask0) << 1);
                packedU[1] =
                    (t[1] & mask0) |
                    ((t[3] & mask0) << 1);

                // odd bits in perfect shuffled order
                // eg: 1 9 3 11 5 13 7 15
                packedU[2] =
                    ((t[0] & mask1) >> 1) |
                    (t[2] & mask1);
                packedU[3] =
                    ((t[1] & mask1) >> 1) |
                    (t[3] & mask1);


                if (mDebug)
                {
                    auto s0 = oc::BitIterator((u8*)&t[0]);
                    auto s1 = oc::BitIterator((u8*)&t[2]);
                    auto d0 = oc::BitIterator((u8*)&packedU[0]);
                    auto d1 = oc::BitIterator((u8*)&packedU[2]);
                    for (u64 k = 0; k < m / 2; ++k)
                    {
                        if (*d0++ != *s0++)
                            throw RTE_LOC;
                        if (*d0++ != *s1++)
                            throw RTE_LOC;
                        if (*d1++ != *s0++)
                            throw RTE_LOC;
                        if (*d1++ != *s1++)
                            throw RTE_LOC;
                    }
                }

                // if (mDebug && i == ii)
                // {
                //     std::cout << "s u " << bit2(t[0], jj) <<" = " << u[i][jj] << std::endl;
                //     auto jj2 = jj / 128 + (jj % 128) * 2;
                //     std::cout << "    " 
                //         << bit(packedU[0], jj2) << " "  
                //         << bit(packedU[2], jj2) << std::endl;
                // }


                t0[0] = q0[0] ^ packedU[0];
                t0[1] = q0[1] ^ packedU[1];
                t1[0] = t0[0] ^ q1[0] ^ packedU[0] ^ packedU[2] ^ oc::AllOneBlock;
                t1[1] = t0[1] ^ q1[1] ^ packedU[1] ^ packedU[3] ^ oc::AllOneBlock;
                t2[0] = t0[0] ^ q2[0] ^ packedU[2];
                t2[1] = t0[1] ^ q2[1] ^ packedU[3];

                d[0] = t1[0];
                d[1] = t1[1];
                d[2] = t2[0];
                d[3] = t2[1];


                //buff2[j * 4 + 0] = packedU[0];
                //buff2[j * 4 + 1] = packedU[1];
                //buff2[j * 4 + 2] = packedU[2];
                //buff2[j * 4 + 3] = packedU[3];

                if (mDebug)
                {
                    buffW[j * 2 + 0] = t0[0];
                    buffW[j * 2 + 1] = t0[1];

                    // if (i == ii)
                    // {
                    //     auto jj2 = jj / 128 + (jj % 128) * 2;
                    //     std::cout << "s w " << bit(t0[0], jj2) <<" = q " <<bit(q0[0], jj2) << " ^ u " << bit(packedU[0] , jj2) << std::endl;
                    //     std::cout << "    " << bit(t1[0], jj2) << std::endl;
                    //     std::cout << "    " << bit(t2[0], jj2) << std::endl;
                    // }
                }

                out[i] = DLpnPrf::shuffledCompress(t0);
            }

            MC_AWAIT(sock.send(std::move(buff)));
            //MC_AWAIT(sock.send(std::move(buff2)));

            if (mDebug)
                MC_AWAIT(sock.send(std::move(buffW)));

        }
        MC_END();
    }




    macoro::task<> DLpnPrfReceiver::genKeyOts(OleGenerator& ole)
    {
        MC_BEGIN(macoro::task<>, this, &ole,
            totalSize = u64(),

            ots = OtSend(),
            req = Request<OtSend>());

        totalSize = 128;


        MC_AWAIT_SET(req, ole.otSendRequest(totalSize));

        MC_AWAIT_SET(ots, req.get());

        assert(ots.size() == totalSize);

        // for(u64 i =0; i < totalSize; ++i)
        // {
        //     std::cout << "s" <<i << " " << ots.mMsg[i][0] << " " << ots.mMsg[i][1] << std::endl;
        // }
        setKeyOts(ots.mMsg);
        MC_END();
    }

    void DLpnPrfReceiver::setKeyOts(span<std::array<oc::block, 2>> ots)
    {
        if (ots.size() != mPrf.KeySize)
            throw RTE_LOC;
        mKeyOTs.resize(mPrf.KeySize);
        for (u64 i = 0; i < mPrf.KeySize; ++i)
        {
            mKeyOTs[i][0].SetSeed(ots[i][0]);
            mKeyOTs[i][1].SetSeed(ots[i][1]);
        }
        mIsKeyOTsSet = true;
    }

    coproto::task<> DLpnPrfReceiver::evaluate(
        span<oc::block> x,
        span<oc::block> y,
        coproto::Socket& sock,
        oc::PRNG&,
        OleGenerator& gen)
    {
        MC_BEGIN(coproto::task<>, x, y, this, &sock, &gen,
            X = oc::AlignedUnVector<std::array<oc::block, DLpnPrf::KeySize / 128>>{},
            buffer = oc::AlignedUnVector<u8>{},
            //h = oc::AlignedUnVector<u16>{},
            rKeys = oc::AlignedUnVector<oc::block>{},
            mod3 = oc::AlignedUnVector<u16>{},
            diff = oc::BitVector{},
            i = u64{},
            ots = oc::AlignedUnVector<oc::block>{},
            kk = oc::block{},
            baseOts = oc::AlignedUnVector<std::array<oc::block, 2>>{},
            block3 = oc::block{},
            xPtr = (u32*)nullptr,
            compressedSizeAct = u64{},
            compressedSize = u64{},
            ole = Request<BinOle>{}
        );
        if (!mIsKeyOTsSet)
            MC_AWAIT(genKeyOts(gen));

        if (mDebug)
        {
            baseOts.resize(mKeyOTs.size());
            for (u64 i = 0; i < baseOts.size(); ++i)
            {
                baseOts[i][0] = mKeyOTs[i][0].getSeed();
                baseOts[i][1] = mKeyOTs[i][1].getSeed();
            }
            MC_AWAIT(sock.send(std::move(baseOts)));
        }

        setTimePoint("DarkMatter.recver.begin");

        MC_AWAIT_SET(ole, gen.binOleRequest(y.size() * m * 2));
        block3 = std::array<u16, 8>{3, 3, 3, 3, 3, 3, 3, 3};


        if constexpr (DLpnPrf::KeySize / 128 > 1)
        {
            X.resize(x.size());
            for (u64 j = 0; j < x.size(); ++j)
            {
                for (i = 0; i < DLpnPrf::KeySize / 128; ++i)
                {
                    X[j][i] = x[j] ^ oc::block(i, i);
                }
                oc::mAesFixedKey.hashBlocks<DLpnPrf::KeySize / 128>(X[j].data(), X[j].data());
            }
        }

        assert(mPrf.KeySize % StepSize == 0);
        mod3.resize(y.size());
        mH.resize(mPrf.KeySize, y.size(), oc::AllocType::Uninitialized);
        compressedSizeAct = oc::divCeil(y.size(), 4);
        compressedSize = oc::roundUpTo(compressedSizeAct, sizeof(oc::block));
        for (i = 0; i < mPrf.KeySize;)
        {
            static_assert(StepSize == sizeof(*xPtr) * 8, "failed static_assert: StepSize == sizeof(*xPtr) * 8");
            buffer.resize(compressedSize * StepSize);
            for (u64 k = 0; k < StepSize; ++i, ++k)
            {
                auto ui = buffer.subspan(compressedSize * k, compressedSizeAct);
                auto hi = mH[i];
                if constexpr (DLpnPrf::KeySize / 128 > 1)
                    xPtr = (u32*)X.data() + i / StepSize;
                else
                    xPtr = (u32*)x.data() + i / StepSize;

                sampleMod3(mKeyOTs[i][0], hi);
                for (u64 j = 0; j < y.size(); ++j)
                {
                    assert(hi.data()[j] < 3);

                    mod3.data()[j] = hi.data()[j] + ((*xPtr >> k) & 1);
                    mod3[j] %= 3;

                    auto neg = ((hi.data()[j] << 1) | (hi.data()[j] >> 1)) & 3;
                    assert(neg == ((3 - hi.data()[j]) % 3));

                    hi.data()[j] = neg;

                    xPtr += mPrf.KeySize / StepSize;
                }

                compressMod3(ui, mod3);
                xorVector(ui, mKeyOTs[i][1]);
            }
            MC_AWAIT(sock.send(std::move(buffer)));
        }

        if (1)
        {
            mU.resize(x.size(), m, oc::AllocType::Uninitialized);

            if (mDebug)
            {
                compressH<DLpnPrf::KeySize>(coproto::copy(mH), mU);
            }
            else
            {
                compressH<DLpnPrf::KeySize>(std::move(mH), mU);
            }
            //compressH<DLpnPrf::KeySize>(mH, mU);

            setTimePoint("DarkMatter.recver.mod2");

            // mod 2
            MC_AWAIT(mod2Compress(mU, y, sock, ole));
        }
        else
        {
            mU.resize(m, x.size(), oc::AllocType::Uninitialized);

        }

        MC_END();
    }


    macoro::task<> DLpnPrfReceiver::mod2Compress(
        oc::MatrixView<u16> u,
        span<oc::block> out,
        coproto::Socket& sock,
        Request<BinOle>& ole)
    {
        MC_BEGIN(macoro::task<>, u, out, &sock, &ole,
            triple = std::vector<BinOle>{},
            tIter = std::vector<BinOle>::iterator{},
            tIdx = u64{},
            tSize = u64{},
            i = u64{},
            step = u64{},
            buff = oc::AlignedUnVector<oc::block>{},
            packedU = oc::AlignedUnVector<std::array<oc::block, mNumOlePer>>{},
            u2 = oc::Matrix<u16>{},
            ww = oc::AlignedUnVector<block256>{},
            mask0 = oc::block{},
            mask1 = oc::block{}
        );

        if (mDebug)
        {
            u2.resize(u.rows(), u.cols());
            MC_AWAIT(sock.recv(u2));

        }

        memset(&mask0, 0b01010101, sizeof(mask0));
        memset(&mask1, 0b10101010, sizeof(mask1));

        triple.reserve(ole.mCorrelations.size());
        tIdx = 0;
        tSize = 0;
        packedU.resize(u.rows());
        for (i = 0; i < u.rows();)
        {
            triple.emplace_back();
            MC_AWAIT_SET(triple.back(), ole.get());

            tSize = triple.back().mAdd.size();
            tIdx = 0;
            buff.resize(tSize);

            step = std::min<u64>(u.rows() - i, tSize / mNumOlePer);
            assert(tSize % mNumOlePer == 0);
            for (u64 j = 0; j < step; ++j, ++i)
            {
                std::array<oc::block, mNumOlePer> t;
                auto iter = (u8*)&t;
                for (u64 k = 0; k < m; k += 4)
                {
                    *iter++ =
                        (u[i][k + 0] << 0) |
                        (u[i][k + 1] << 2) |
                        (u[i][k + 2] << 4) |
                        (u[i][k + 3] << 6);
                }

                // even bits in perfect shuffled order
                // eg: 0 8 2 10 4 12 6 14
                packedU[i][0] =
                    (t[0] & mask0) |
                    ((t[2] & mask0) << 1);
                packedU[i][1] =
                    (t[1] & mask0) |
                    ((t[3] & mask0) << 1);

                // odd bits in perfect shuffled order
                // eg: 1 9 3 11 5 13 7 15
                packedU[i][2] =
                    ((t[0] & mask1) >> 1) |
                    (t[2] & mask1);
                packedU[i][3] =
                    ((t[1] & mask1) >> 1) |
                    (t[3] & mask1);

                for (u64 k = 0; k < packedU[i].size(); ++k, ++tIdx)
                {
                    buff[tIdx] = triple.back().mMult[tIdx] ^ packedU[i][k];
                }
            }

            MC_AWAIT(sock.send(std::move(buff)));
        }


        tIter = triple.begin();
        for (i = 0; i < u.rows(); ++tIter)
        {
            tIdx = 0;
            tSize = tIter->mAdd.size();
            buff.resize(tSize);
            MC_AWAIT(sock.recv(buff));

            if (mDebug)
            {
                ww.resize(tSize / 4);
                MC_AWAIT(sock.recv(ww));
            }

            step = std::min<u64>(u.rows() - i, tSize / mNumOlePer);
            for (u64 j = 0; j < step; ++j, ++i, tIdx += 4)
            {
                block256 w;
                w[0] =
                    (packedU[i][0] & buff[tIdx + 0]) ^
                    (packedU[i][2] & buff[tIdx + 2]) ^
                    tIter->mAdd[tIdx + 0] ^
                    tIter->mAdd[tIdx + 2];
                w[1] =
                    (packedU[i][1] & buff[tIdx + 1]) ^
                    (packedU[i][3] & buff[tIdx + 3]) ^
                    tIter->mAdd[tIdx + 1] ^
                    tIter->mAdd[tIdx + 3];

                if (mDebug)
                {
                    block256 W = w ^ ww[j];
                    for (u64 k = 0; k < m; ++k)
                    {
                        auto U0 = u[i][k];
                        auto U1 = u2[i][k];
                        auto U = (U0 + U1) % 3;
                        auto kk2 = k / 128 + (k % 128) * 2;
                        auto wk = bit(W, kk2);
                        if ((U % 2) != wk)
                            throw RTE_LOC;;
                    }
                }
                out[i] = DLpnPrf::shuffledCompress(w);
            }
        }

        MC_END();
    }
}