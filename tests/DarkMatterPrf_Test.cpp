#include "DarkMatterPrf_Test.h"
#include "secure-join/DarkMatterPrf.h"
#include "cryptoTools/Crypto/PRNG.h"
#include "cryptoTools/Common/Matrix.h"
using namespace secJoin;

void DarkMatterPrf_plain_test()
{

    oc::PRNG prng(oc::ZeroBlock);
    block256 k = prng.get();
    block256 x = prng.get();

    DarkMatterPrf prf;
    prf.setKey(k);

    auto y = prf.eval(x);
    std::cout << y << std::endl;

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

void DarkMatterPrf_util_test()
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

void DarkMatterPrf_proto_test(const oc::CLP& cmd)
{

    u64 n = cmd.getOr("n", 100);
    bool noCheck = cmd.isSet("nc");

    oc::Timer timer;

    DarkMatterPrfSender sender;
    DarkMatterPrfReceiver recver;

    sender.setTimer(timer);
    recver.setTimer(timer);

    std::vector<block256> x(n);
    std::vector<oc::block> y0(n), y1(n);

    auto sock = coproto::LocalAsyncSocket::makePair();

    oc::PRNG prng0(oc::ZeroBlock);
    oc::PRNG prng1(oc::OneBlock);

    DarkMatterPrf dm;
    block256 k;
    k = prng0.get();
    dm.setKey(k);
    sender.setKey(k);


    prng0.get(x.data(), x.size());
    //memset(x.data(), -1, n * sizeof(block256));
    std::vector<oc::block> rk(256);
    std::vector<std::array<oc::block,2>> sk(256);
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
        std::cout << timer << std::endl;

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

