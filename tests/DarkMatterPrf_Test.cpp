#include "DarkMatterPrf_Test.h"
#include "secure-join/DarkMatter22Prf.h"
#include "secure-join/DarkMatter32Prf.h"
#include "secure-join/DLpnPrf.h"
#include "secure-join/ALpnPrf.h"
#include "cryptoTools/Crypto/PRNG.h"
#include "cryptoTools/Common/Matrix.h"
using namespace secJoin;

void DarkMatter22Prf_plain_test()
{

    oc::PRNG prng(oc::ZeroBlock);
    block256 k = prng.get();
    block256 x = prng.get();

    DarkMatter22Prf prf;
    prf.setKey(k);

    auto y = prf.eval(x);

    oc::Matrix<u64> K(256, 256), B(128, 256);
    std::vector<u64> X(256);
    for (u64 i = 0; i < 256; ++i)
    {
        X[i] = *oc::BitIterator((u8*)&x, i);

        u8 ki = *oc::BitIterator((u8*)&k, i);
        for (u64 j = 0; j < 256; ++j)
        {
            auto jj = (j + i) % 256;
            K(j, jj) = ki;
        }
    }
    for (u64 i = 0; i < 128; ++i)
    {
        for (u64 j = 0; j < 256; ++j)
        {
            B(i, j) = *oc::BitIterator((u8*)&prf.mB[i], j);
        }
    }

    //std::cout << "K\n";
    //for (u64 i = 0; i < 256; ++i)
    //{
    //    for (u64 j = 0; j < 256; ++j)
    //    {
    //        std::cout << K(i, j) << " ";
    //    }
    //    std::cout << std::endl;
    //}

    std::vector<u64> KX(256);

    //std::cout << "KX ";
    for (u64 i = 0; i < 256; ++i)
    {
        for (u64 j = 0; j < 256; ++j)
        {
            assert(K(i, j) < 2);
            assert(X[j] < 2);
            KX[i] += K(i, j) * X[j];
        }
        //std::cout << KX[i] << " ";
    }
    //std::cout << std::endl;


    std::vector<u64> v(256), u(256), w(256), Y(128);
    for (u64 i = 0; i < 256; ++i)
    {
        v[i] = KX[i] % 2;
        u[i] = (KX[i] % 3) % 2;
        w[i] = v[i] ^ u[i];
    }
    //std::cout << "W  ";
    //for (u64 i = 0; i < 256; ++i)
    //{
    //    std::cout << w[i] << " ";
    //}
    //std::cout << std::endl;

    for (u64 i = 0; i < 128; ++i)
    {
        for (u64 j = 0; j < 256; ++j)
        {
            Y[i] ^= B(i, j) * w[j];
        }

        if (Y[i] != (u8)*oc::BitIterator((u8*)&y, i))
        {
            throw RTE_LOC;
        }
    }



}


void DarkMatter32Prf_plain_test()
{

    oc::PRNG prng(oc::ZeroBlock);
    block256 k = prng.get();
    block256 x = prng.get();

    DarkMatter32Prf prf;
    prf.setKey(k);

    auto y = prf.eval(x);

    oc::Matrix<u64> K(256, 256), B(128, 256);
    std::vector<u64> X(256);
    for (u64 i = 0; i < 256; ++i)
    {
        X[i] = *oc::BitIterator((u8*)&x, i);

        u8 ki = *oc::BitIterator((u8*)&k, i);
        for (u64 j = 0; j < 256; ++j)
        {
            auto jj = (j + i) % 256;
            K(j, jj) = ki;
        }
    }
    for (u64 i = 0; i < 128; ++i)
    {
        for (u64 j = 0; j < 256; ++j)
        {
            B(i, j) = *oc::BitIterator((u8*)&DarkMatter22Prf::mB[i], j);
        }
    }

    //std::cout << "K\n";
    //for (u64 i = 0; i < 256; ++i)
    //{
    //    for (u64 j = 0; j < 256; ++j)
    //    {
    //        std::cout << K(i, j) << " ";
    //    }
    //    std::cout << std::endl;
    //}

    std::vector<u64> KX(256);

    //std::cout << "KX ";
    for (u64 i = 0; i < 256; ++i)
    {
        for (u64 j = 0; j < 256; ++j)
        {
            assert(K(i, j) < 2);
            assert(X[j] < 2);
            KX[i] += K(i, j) * X[j];
        }
        //std::cout << KX[i] << " ";
    }
    //std::cout << std::endl;


    std::vector<u64> w(256), Y(128);
    for (u64 i = 0; i < 256; ++i)
    {
        w[i] = (KX[i] % 3) % 2;
    }
    //std::cout << "W  ";
    //for (u64 i = 0; i < 256; ++i)
    //{
    //    std::cout << w[i] << " ";
    //}
    //std::cout << std::endl;

    for (u64 i = 0; i < 128; ++i)
    {
        for (u64 j = 0; j < 256; ++j)
        {
            Y[i] ^= B(i, j) * w[j];
        }

        if (Y[i] != (u8)*oc::BitIterator((u8*)&y, i))
        {
            throw RTE_LOC;
        }
    }
}

void DarkMatter22Prf_util_test()
{
    auto n = 234 * 256;
    oc::PRNG prng(oc::ZeroBlock);
    auto m3 = sampleMod3(prng, n);

    if (m3.size() != n)
        throw RTE_LOC;

    std::vector<u64> counts(3);
    for (auto i = 0; i < n; ++i)
    {
        if (m3[i] > 2)
            throw RTE_LOC;

        //std::cout << int(m3[i]) << " ";
        ++counts[m3[i]];
    }
    //std::cout << std::endl;

    std::vector<u8> dst(n / 4);
    oc::AlignedUnVector<u16> mm(n);
    compressMod3(dst, m3);
    decompressMod3(mm, dst);

    if (std::equal(mm.begin(), mm.end(), m3.begin()) == false)
        throw RTE_LOC;
    //std::cout << counts[0] << " " << counts[1] << " " << counts[2] << std::endl;

}

void DarkMatter22Prf_proto_test(const oc::CLP& cmd)
{

    u64 n = cmd.getOr("n", 100);
    bool noCheck = cmd.isSet("nc");

    oc::Timer timer;

    DarkMatter22PrfSender sender;
    DarkMatter22PrfReceiver recver;

    sender.setTimer(timer);
    recver.setTimer(timer);

    std::vector<block256> x(n);
    std::vector<oc::block> y0(n), y1(n);

    auto sock = coproto::LocalAsyncSocket::makePair();

    oc::PRNG prng0(oc::ZeroBlock);
    oc::PRNG prng1(oc::OneBlock);

    DarkMatter22Prf dm;
    block256 k;
    k = prng0.get();
    dm.setKey(k);
    sender.setKey(k);


    prng0.get(x.data(), x.size());
    //memset(x.data(), -1, n * sizeof(block256));
    std::vector<oc::block> rk(256);
    std::vector<std::array<oc::block, 2>> sk(256);
    for (u64 i = 0; i < 256; ++i)
    {
        sk[i][0] = oc::block(i, 0);
        sk[i][1] = oc::block(i, 1);
        rk[i] = oc::block(i, *oc::BitIterator((u8*)&k, i));
    }
    sender.setKeyOts(rk);
    recver.setKeyOts(sk);

    auto r = coproto::sync_wait(coproto::when_all_ready(
        sender.evaluate(y0, sock[0], prng0),
        recver.evaluate(x, y1, sock[1], prng1)
    ));

    std::get<0>(r).result();
    std::get<1>(r).result();

    if (cmd.isSet("v"))
    {
        std::cout << timer << std::endl;
        std::cout << sock[0].bytesReceived() / 1000.0 << " " << sock[0].bytesSent() / 1000.0 << " kB " << std::endl;
    }

    if (noCheck)
        return;

    for (u64 ii = 0; ii < n; ++ii)
    {
        block256 v;
        block256m3 u;
        memset(&v, 0, sizeof(v));
        memset(&u, 0, sizeof(u));
        for (u64 i = 0; i < dm.mKeyMask.size(); ++i)
        {
            auto xi = x[ii].rotate(i) & dm.mKeyMask[i];
            v ^= xi;
            u ^= xi;
        }

        block256 u2 = u.mod2();
        block256 w = v ^ u2;

        alignas(32) std::array<std::array<oc::block, 128>, 2> bw;
        for (u64 i = 0; i < 128; ++i)
        {
            bw[0][i] = dm.mB[i].mData[0] & w.mData[0];
            bw[1][i] = dm.mB[i].mData[1] & w.mData[1];
        }
        oc::transpose128(bw[0].data());
        oc::transpose128(bw[1].data());

        oc::block y;
        memset(&y, 0, sizeof(y));
        for (u64 i = 0; i < 128; ++i)
            y = y ^ bw[0][i];
        for (u64 i = 0; i < 128; ++i)
            y = y ^ bw[1][i];

        if ((sender.mV[ii] ^ recver.mV[ii]) != v)
            throw RTE_LOC;

        for (u64 j = 0; j < 256; ++j)
        {
            auto act = (sender.mU[ii][j] + recver.mU[ii][j]) % 3;
            if (act != u.mData[j])
                throw RTE_LOC;
        }


        auto act = (sender.mU2[ii] ^ recver.mU2[ii]);
        if (act != u2)
            throw RTE_LOC;


        auto yy = (y0[ii] ^ y1[ii]);
        if (yy != y)
            throw RTE_LOC;
    }
}



void DarkMatter32Prf_proto_test(const oc::CLP& cmd)
{

    u64 n = cmd.getOr("n", 100);
    bool noCheck = cmd.isSet("nc");

    oc::Timer timer;

    DarkMatter32PrfSender sender;
    DarkMatter32PrfReceiver recver;

    sender.setTimer(timer);
    recver.setTimer(timer);

    std::vector<block256> x(n);
    std::vector<oc::block> y0(n), y1(n);

    auto sock = coproto::LocalAsyncSocket::makePair();

    oc::PRNG prng0(oc::ZeroBlock);
    oc::PRNG prng1(oc::OneBlock);

    DarkMatter32Prf dm;
    block256 k;
    k = prng0.get();
    dm.setKey(k);
    sender.setKey(k);


    prng0.get(x.data(), x.size());
    //memset(x.data(), -1, n * sizeof(block256));
    std::vector<oc::block> rk(256);
    std::vector<std::array<oc::block, 2>> sk(256);
    for (u64 i = 0; i < 256; ++i)
    {
        sk[i][0] = oc::block(i, 0);
        sk[i][1] = oc::block(i, 1);
        rk[i] = oc::block(i, *oc::BitIterator((u8*)&k, i));
    }
    sender.setKeyOts(rk);
    recver.setKeyOts(sk);

    auto r = coproto::sync_wait(coproto::when_all_ready(
        sender.evaluate(y0, sock[0], prng0),
        recver.evaluate(x, y1, sock[1], prng1)
    ));

    std::get<0>(r).result();
    std::get<1>(r).result();

    if (cmd.isSet("v"))
    {
        std::cout << timer << std::endl;
        std::cout << sock[0].bytesReceived() / 1000.0 << " " << sock[0].bytesSent() / 1000.0 << " kB " << std::endl;
    }

    if (noCheck)
        return;

    for (u64 ii = 0; ii < n; ++ii)
    {
        block256m3 u;
        memset(&u, 0, sizeof(u));
        for (u64 i = 0; i < dm.mKeyMask.size(); ++i)
        {
            auto xi = x[ii].rotate(i) & dm.mKeyMask[i];
            u ^= xi;
        }

        block256 w = u.mod2();

        auto y = DarkMatter32Prf::compress(w);



        for (u64 j = 0; j < 256; ++j)
        {
            auto act = (sender.mU[ii][j] + recver.mU[ii][j]) % 3;
            if (act != u.mData[j])
                throw RTE_LOC;
        }


        auto act = (sender.mU2[ii] ^ recver.mU2[ii]);
        if (act != w)
            throw RTE_LOC;


        auto yy = (y0[ii] ^ y1[ii]);
        if (yy != y)
            throw RTE_LOC;
    }
}

void mult(oc::DenseMtx& C, std::vector<u64>& X, std::vector<u64>& Y)
{
    for (u64 i = 0; i < C.rows(); ++i)
    {
        Y[i] = 0;
        for (u64 j = 0; j < C.cols(); ++j)
        {
            Y[i] += C(i, j) * X[j];
        }
    }
}
void DLpnPrf_plain_test()
{


    auto n = 512;
    auto m = 256;
    auto t = 128;
    oc::PRNG prng(oc::ZeroBlock);
    oc::block kk = prng.get();
    oc::block xx = prng.get();

    std::array<oc::block, DLpnPrf::KeySize / 128> x;
    for (u64 i = 0; i < x.size(); ++i)
        x[i] = xx ^ oc::block(i, i);
    oc::mAesFixedKey.hashBlocks<4>(x.data(), x.data());

    DLpnPrf prf;

    prf.setKey(kk);


    auto y = prf.eval(xx);

    oc::Matrix<u64> B(t, m);
    std::vector<u64> X(n), K(n), H(n), U(m), W(m), Y(t);
    for (u64 i = 0; i < n; ++i)
    {
        X[i] = *oc::BitIterator((u8*)&x, i);
        K[i] = *oc::BitIterator((u8*)&prf.mKey, i);
        H[i] = X[i] & K[i];

        //if (i < 20)
        //    std::cout << "H[" << i << "] = " << (H[i]) << std::endl;

    }
    for (u64 i = 0; i < t; ++i)
    {
        for (u64 j = 0; j < m; ++j)
        {
            B(i, j) = *oc::BitIterator((u8*)&DarkMatter22Prf::mB[i], j);
        }
    }

    //oc::DenseMtx Accumulator(X.size(), X.size());
    //oc::DenseMtx Expander(X.size() / 2, X.size());

    //for (u64 i = 0; i < X.size(); ++i)
    //{
    //    for (u64 j = 0; j <= i; ++j)
    //    {
    //        Accumulator(i, j) = 1;
    //    }

    //    Expander(i / 2, prf.mPi[i]) = 1;
    //}

    //auto C = Expander * Accumulator;

    //std::cout << "C\n" << C << std::endl;

    //mult(C, H, U);
    {
        //assert(mPi.size() != 0);

        for (u64 k = 1; k < prf.KeySize; ++k)
        {
            H[k] += H[k - 1];
        }

        auto pik = prf.mPi.data();
        for (u64 k = 0; k < m; ++k)
        {
            U[k] = (
                H[pik[0]] +
                H[pik[1]]
                ) % 3;
            pik += 2;
        }
    }
    for (u64 i = 0; i < m; ++i)
    {
        //if (i < 20)
        //    std::cout << "U[" << i << "] = " << (U[i] % 3) << std::endl;

        W[i] = (U[i] % 3) % 2;
    }
    for (u64 i = 0; i < t; ++i)
    {
        for (u64 j = 0; j < m; ++j)
        {
            Y[i] ^= B(i, j) * W[j];
        }

        if (Y[i] != (u8)*oc::BitIterator((u8*)&y, i))
        {
            throw RTE_LOC;
        }
    }

}

void DLpnPrf_proto_test(const oc::CLP& cmd)
{


    u64 n = cmd.getOr("n", 100);
    bool noCheck = cmd.isSet("nc");

    oc::Timer timer;

    DLpnPrfSender sender;
    DLpnPrfReceiver recver;

    sender.setTimer(timer);
    recver.setTimer(timer);

    std::vector<oc::block> x(n);
    std::vector<oc::block> y0(n), y1(n);

    auto sock = coproto::LocalAsyncSocket::makePair();

    oc::PRNG prng0(oc::ZeroBlock);
    oc::PRNG prng1(oc::OneBlock);

    DLpnPrf dm;
    oc::block kk;
    kk = prng0.get();
    dm.setKey(kk);
    sender.setKey(kk);


    prng0.get(x.data(), x.size());
    //memset(x.data(), -1, n * sizeof(block256));
    std::vector<oc::block> rk(sender.mPrf.KeySize);
    std::vector<std::array<oc::block, 2>> sk(sender.mPrf.KeySize);
    for (u64 i = 0; i < sender.mPrf.KeySize; ++i)
    {
        sk[i][0] = oc::block(i, 0);
        sk[i][1] = oc::block(i, 1);
        rk[i] = oc::block(i, *oc::BitIterator((u8*)&sender.mPrf.mKey, i));
    }
    sender.setKeyOts(rk);
    recver.setKeyOts(sk);

    auto r = coproto::sync_wait(coproto::when_all_ready(
        sender.evaluate(y0, sock[0], prng0),
        recver.evaluate(x, y1, sock[1], prng1)
    ));

    std::get<0>(r).result();
    std::get<1>(r).result();

    if (cmd.isSet("v"))
    {
        std::cout << timer << std::endl;
        std::cout << sock[0].bytesReceived() / 1000.0 << " " << sock[0].bytesSent() / 1000.0 << " kB " << std::endl;
    }

    if (noCheck)
        return;

    for (u64 ii = 0; ii < n; ++ii)
    {
        oc::block y;
        {
            std::array<u16, sender.mPrf.KeySize> h;
            std::array<oc::block, sender.mPrf.KeySize / 128> X;
            for (u64 i = 0; i < X.size(); ++i)
                X[i] = x[ii] ^ oc::block(i, i);
            oc::mAesFixedKey.hashBlocks<X.size()>(X.data(), X.data());
            auto kIter = oc::BitIterator((u8*)sender.mPrf.mKey.data());
            auto xIter = oc::BitIterator((u8*)X.data());
            for (u64 i = 0; i < sender.mPrf.KeySize; ++i)
            {
                u8 xi = *xIter;
                u8 ki = *kIter;
                h[i] = ki & xi;

                auto r = recver.mH[i * x.size() + ii];
                auto s = sender.mH[i * x.size() + ii];
                auto neg = (3 - r)%3;
                auto act = (s + neg) % 3;
                if (act != h[i])
                    throw RTE_LOC;
                //if (i < 20)
                //    std::cout << "h[" << i << "] = " << h[i] 
                //    << " = " << *kIter 
                //    <<" ^ " << *xIter <<std::endl;

                ++kIter;
                ++xIter;
            }

            block256m3 u;
            sender.mPrf.compressH(h, u);

            for (u64 i = 0; i < 256; ++i)
                if ((sender.mU[ii][i] + recver.mU[ii][i])%3 != u.mData[i])
                    throw RTE_LOC;

            block256 w;
            for (u64 i = 0; i < u.mData.size(); ++i)
            {
                //if (i < 10)
                //    std::cout << "u[" << i << "] = " << (int)u.mData[i] << std::endl;

                *oc::BitIterator((u8*)&w, i) = u.mData[i] % 2;
            }
            y = sender.mPrf.compress(w);
        }
        //auto y = sender.mPrf.eval(x[ii]);

        auto yy = (y0[ii] ^ y1[ii]);
        if (yy != y)
            throw RTE_LOC;
    }
}

void ALpnPrf_plain_test()
{



    auto n = 256;
    auto m = 256;
    auto t = 128;
    oc::PRNG prng(oc::ZeroBlock);
    oc::block kk = prng.get();
    oc::block xx = prng.get();


    ALpnPrf prf;

    prf.setKey(kk);


    auto y = prf.eval(xx);

    oc::Matrix<u64> B(t, m);
    std::vector<u64> U(m), Y(t);
    auto X = sampleMod3(oc::PRNG(xx,1), n);
    auto K = sampleMod3(oc::PRNG(kk,1), n);

    for (u64 i = 0; i < n; ++i)
    {
        U[i] = ((X[i] + K[i]) % 3) % 2;
    }
    for (u64 i = 0; i < t; ++i)
    {
        for (u64 j = 0; j < m; ++j)
        {
            B(i, j) = *oc::BitIterator((u8*)&DarkMatter22Prf::mB[i], j);
        }
    }
    for (u64 i = 0; i < t; ++i)
    {
        for (u64 j = 0; j < m; ++j)
        {
            Y[i] ^= B(i, j) * U[j];
        }

        if (Y[i] != (u8)*oc::BitIterator((u8*)&y, i))
        {
            throw RTE_LOC;
        }
    }

}

void ALpnPrf_proto_test(const oc::CLP& cmd)
{


    u64 n = cmd.getOr("n", 100);
    bool noCheck = cmd.isSet("nc");

    oc::Timer timer;

    ALpnPrfSender sender;
    ALpnPrfReceiver recver;

    sender.setTimer(timer);
    recver.setTimer(timer);

    std::vector<oc::block> x(n);
    std::vector<oc::block> y0(n), y1(n);

    auto sock = coproto::LocalAsyncSocket::makePair();

    oc::PRNG prng0(oc::ZeroBlock);
    oc::PRNG prng1(oc::OneBlock);

    ALpnPrf dm;
    oc::block kk;
    kk = prng0.get();
    dm.setKey(kk);
    sender.setKey(kk);

    prng0.get(x.data(), x.size());

    auto r = coproto::sync_wait(coproto::when_all_ready(
        sender.evaluate(y0, sock[0], prng0),
        recver.evaluate(x, y1, sock[1], prng1)
    ));

    std::get<0>(r).result();
    std::get<1>(r).result();

    if (cmd.isSet("v"))
    {
        std::cout << timer << std::endl;
        std::cout << sock[0].bytesReceived() / 1000.0 << " " << sock[0].bytesSent() / 1000.0 << " kB " << std::endl;
    }

    if (noCheck)
        return;

    for (u64 ii = 0; ii < n; ++ii)
    {
        oc::block y;
        //{
        //    std::array<u16, sender.mPrf.KeySize> h;
        //    std::array<oc::block, sender.mPrf.KeySize / 128> X;
        //    for (u64 i = 0; i < X.size(); ++i)
        //        X[i] = x[ii] ^ oc::block(i, i);
        //    oc::mAesFixedKey.hashBlocks<X.size()>(X.data(), X.data());
        //    auto kIter = oc::BitIterator((u8*)sender.mPrf.mKey.data());
        //    auto xIter = oc::BitIterator((u8*)X.data());
        //    for (u64 i = 0; i < sender.mPrf.KeySize; ++i)
        //    {
        //        u8 xi = *xIter;
        //        u8 ki = *kIter;
        //        h[i] = ki & xi;

        //        auto r = recver.mH[i * x.size() + ii];
        //        auto s = sender.mH[i * x.size() + ii];
        //        auto neg = (3 - r) % 3;
        //        auto act = (s + neg) % 3;
        //        if (act != h[i])
        //            throw RTE_LOC;
        //        //if (i < 20)
        //        //    std::cout << "h[" << i << "] = " << h[i] 
        //        //    << " = " << *kIter 
        //        //    <<" ^ " << *xIter <<std::endl;

        //        ++kIter;
        //        ++xIter;
        //    }

        //    block256m3 u;
        //    sender.mPrf.compressH(h, u);

        //    for (u64 i = 0; i < 256; ++i)
        //        if ((sender.mU[ii][i] + recver.mU[ii][i]) % 3 != u.mData[i])
        //            throw RTE_LOC;

        //    block256 w;
        //    for (u64 i = 0; i < u.mData.size(); ++i)
        //    {
        //        //if (i < 10)
        //        //    std::cout << "u[" << i << "] = " << (int)u.mData[i] << std::endl;

        //        *oc::BitIterator((u8*)&w, i) = u.mData[i] % 2;
        //    }
        //    y = sender.mPrf.compress(w);
        //}
        y = sender.mPrf.eval(x[ii]);

        auto yy = (y0[ii] ^ y1[ii]);
        if (yy != y)
            throw RTE_LOC;
    }
}


