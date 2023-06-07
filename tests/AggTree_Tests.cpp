#include "secure-join/AggTree/AggTree.h"

#include "secure-join/AggTree/PlainAggTree.h"
#include "secure-join/AggTree/PerfectShuffle.h"
#include "cryptoTools/Common/TestCollection.h"

//#include "helper.h"
//#include "AggTreeTests.h"
//#include "BinEval_Tests.h"
using namespace oc;
using namespace secJoin;
using secJoin::span;

void perfectShuffle_32_Test()
{
    u64 n = 100;
    PRNG prng(ZeroBlock);

    for (u64 i = 0; i < n; ++i)
    {
        std::array<u16, 2> x = prng.get();

        auto y = cPerfectShuffle(x[0], x[1]);

        BitVector X((u8*)&x, 32);
        BitVector Y((u8*)&y, 32);

        // abcd efgh ijkl mnop ABCD EFGH IJKL MNOP,
        // aAbB cCdD eEfF gGhH iIjJ kKlL mMnN oOpP
        for (u64 j = 0; j < 32; ++j)
            if (X[j] != Y[(j * 2) % 32 + (j * 2) / 32])
                throw RTE_LOC;


        if (x != cPerfectUnshuffle(y))
            throw RTE_LOC;

    }

}

void perfectShuffle_span_Test()
{
    u64 n = 100, m = 132;
    PRNG prng(ZeroBlock);

    for (u64 i = 0; i < n; ++i)
    {
        BitVector X[2];
        X[0].resize(m - m / 2); X[0].randomize(prng);
        X[1].resize(m / 2);	 X[1].randomize(prng);
        BitVector Y(m);

        BitVector XX[2];
        XX[0].resize(X[0].size());
        XX[1].resize(X[1].size());
        cPerfectShuffle(X[0].getSpan<u8>(), X[1].getSpan<u8>(), Y.getSpan<u8>());

        // X0 = abcd efgh ijkl mnop 
        // X1 = ABCD EFGH IJKL MNOP,
        // Y  = aAbB cCdD eEfF gGhH iIjJ kKlL mMnN oOpP
        for (u64 j = 0; j < m; ++j)
        {
            if (Y[j] != X[j & 1][j / 2])
                throw RTE_LOC;
        }

        cPerfectUnshuffle(Y.getSpan<u8>(), XX[0].getSpan<u8>(), XX[1].getSpan<u8>());

        if (XX[0] != X[0])
            throw RTE_LOC;
        if (XX[1] != X[1])
            throw RTE_LOC;
    }
}

void perfectShuffle_128_Test()
{
#ifdef ENABLE_SSE
    u64 n = 100;
    PRNG prng(ZeroBlock);

    u64 m = 128;
    for (u64 i = 0; i < n; ++i)
    {
        std::array<u64, 2> x = prng.get();

        auto y = ssePerfectShuffle(x[0], x[1]);

        BitVector X((u8*)&x, m);
        BitVector Y((u8*)&y, m);

        // abcd efgh ijkl mnop ABCD EFGH IJKL MNOP,
        // aAbB cCdD eEfF gGhH iIjJ kKlL mMnN oOpP
        for (u64 j = 0; j < m; ++j)
            if (X[j] != Y[(j * 2) % m + (j * 2) / m])
                throw RTE_LOC;


        if (x != ssePerfectUnshuffle(y))
            throw RTE_LOC;

    }
#endif
}

void perfectShuffle_1024_Test()
{
#ifdef ENABLE_SSE

    u64 n = 100;
    PRNG prng(ZeroBlock);

    u64 m = 1024;
    for (u64 i = 0; i < n; ++i)
    {
        std::array<std::array<oc::block, 4>, 2> x = prng.get(), x2;
        std::array<oc::block, 8> y;
        ssePerfectShuffle(x[0].data(), x[1].data(), y.data());

        BitVector X((u8*)&x, m);
        BitVector Y((u8*)&y, m);

        // abcd efgh ijkl mnop ABCD EFGH IJKL MNOP,
        // aAbB cCdD eEfF gGhH iIjJ kKlL mMnN oOpP
        for (u64 j = 0; j < m; ++j)
            if (X[j] != Y[(j * 2) % m + (j * 2) / m])
                throw RTE_LOC;

        ssePerfectUnshuffle(y.data(), x2[0].data(), x2[1].data());
        if (x != x2)
            throw RTE_LOC;
    }
#endif
}


void perfectShuffle_sseSpan_Test()
{
#ifdef ENABLE_SSE
    u64 n = 40, m = 13203;
    PRNG prng(ZeroBlock);

    for (u64 i = 0; i < n; ++i)
    {
        BitVector X[2];
        X[0].resize(m - m / 2); X[0].randomize(prng);
        X[1].resize(m / 2);	 X[1].randomize(prng);
        BitVector Y(m);

        BitVector XX[2];
        XX[0].resize(X[0].size());
        XX[1].resize(X[1].size());
        ssePerfectShuffle(X[0].getSpan<u8>(), X[1].getSpan<u8>(), Y.getSpan<u8>());

        // X0 = abcd efgh ijkl mnop 
        // X1 = ABCD EFGH IJKL MNOP,
        // Y  = aAbB cCdD eEfF gGhH iIjJ kKlL mMnN oOpP
        for (u64 j = 0; j < m; ++j)
        {
            if (Y[j] != X[j & 1][j / 2])
                throw RTE_LOC;
        }

        ssePerfectUnshuffle(Y.getSpan<u8>(), XX[0].getSpan<u8>(), XX[1].getSpan<u8>());

        if (XX[0] != X[0])
        {
            std::cout << X[0] << std::endl;
            std::cout << XX[0] << std::endl;
            std::cout << (X[0] ^ XX[0]) << std::endl;
            throw RTE_LOC;
        }
        if (XX[1] != X[1])
            throw RTE_LOC;
    }
#endif
}


//namespace
//{
//    bool operator!=(oc::span<i64> l, oc::span<i64> r)
//    {
//        return l.size() != r.size() ||
//            std::memcmp(l.data(), r.data(), l.size()) != 0;
//    }
//
//    //std::string hex(oc::span<i64> d)
//    //{
//    //    std::stringstream ss;
//    //    for (auto dd : d)
//    //        ss << std::hex << std::setw(2 * sizeof(i64)) << std::setfill('0') << dd;
//    //    return ss.str();
//    //}
//}

using Level = AggTree::Level;
using SplitLevel = AggTree::SplitLevel;


void AggTree_levelReveal_Test()
{

    PRNG prng(ZeroBlock);

    //auto op = [](
    //    const oc::BitVector& left,
    //    const oc::BitVector& right)
    //{
    //    return left ^ right;
    //};


    //u64 n = oc::roundUpTo(361, 16);
    for (u64 n : { 8ull, 256ull, 361ull, 24223ull })
    {
        u64 m = 11;

        {
            BinMatrix preBits(n, 1);
            BinMatrix preVals(n, m);
            BinMatrix sufBits(n, 1);
            BinMatrix sufVals(n, m);

            BinMatrix preBitsEven(oc::divCeil(n, 2), 1);
            BinMatrix preValsEven(oc::divCeil(n, 2), m);
            BinMatrix sufBitsEven(oc::divCeil(n, 2), 1);
            BinMatrix sufValsEven(oc::divCeil(n, 2), m);

            BinMatrix preBitsOdd(n - preBitsEven.numEntries(), 1);
            BinMatrix preValsOdd(n - preValsEven.numEntries(), m);
            BinMatrix sufBitsOdd(n - sufBitsEven.numEntries(), 1);
            BinMatrix sufValsOdd(n - sufValsEven.numEntries(), m);

            prng.get(preBits.data(), preBits.size()); preBits.trim();
            prng.get(preVals.data(), preVals.size()); preVals.trim();
            prng.get(sufBits.data(), sufBits.size()); sufBits.trim();
            prng.get(sufVals.data(), sufVals.size()); sufVals.trim();

            for (u64 i = 0; i < n; i += 2)
            {
                preBitsEven(i / 2) = preBits(i);
                sufBitsEven(i / 2) = sufBits(i);
                if (i + 1 != n)
                {
                    preBitsOdd(i / 2) = preBits(i + 1);
                    sufBitsOdd(i / 2) = sufBits(i + 1);
                }

                for (u64 j = 0; j < preVals.bytesPerEnrty(); ++j)
                {
                    preValsEven(i / 2, j) = preVals(i, j);
                    sufValsEven(i / 2, j) = sufVals(i, j);
                    if (i + 1 != n)
                    {
                        preValsOdd(i / 2, j) = preVals(i + 1, j);
                        sufValsOdd(i / 2, j) = sufVals(i + 1, j);
                    }
                }
            }

            auto preBitsEvenShare = share(preBitsEven, prng);
            auto preValsEvenShare = share(preValsEven, prng);
            auto sufBitsEvenShare = share(sufBitsEven, prng);
            auto sufValsEvenShare = share(sufValsEven, prng);

            auto preBitsOddShare = share(preBitsOdd, prng);
            auto preValsOddShare = share(preValsOdd, prng);
            auto sufBitsOddShare = share(sufBitsOdd, prng);
            auto sufValsOddShare = share(sufValsOdd, prng);

            std::array<SplitLevel, 2> tvs;

            for (u64 p = 0; p < 2; ++p)
            {
                tvs[p][0].mPreBit = preBitsEvenShare[p].transpose();
                tvs[p][0].mPreVal = preValsEvenShare[p].transpose();
                tvs[p][0].mSufBit = sufBitsEvenShare[p].transpose();
                tvs[p][0].mSufVal = sufValsEvenShare[p].transpose();
                tvs[p][1].mPreBit = preBitsOddShare[p].transpose();
                tvs[p][1].mPreVal = preValsOddShare[p].transpose();
                tvs[p][1].mSufBit = sufBitsOddShare[p].transpose();
                tvs[p][1].mSufVal = sufValsOddShare[p].transpose();
            }

            PLevel leaves;
            PLevel even;
            even.reveal(tvs[0][0], tvs[1][0]);
            leaves.reveal(tvs[0], tvs[1]);


            for (u64 i = 0; i < n; ++i)
            {
                if (leaves.mPreBit[i] != preBits(i))
                    throw RTE_LOC;
                if (leaves.mSufBit[i] != sufBits(i))
                    throw RTE_LOC;

                if (i < preValsEven.numEntries())
                {
                    for (u64 j = 0; j < preVals.bytesPerEnrty(); ++j)
                    {
                        if (even.mPreVal[i].getSpan<u8>()[j] != preValsEven(i, j))
                        {
                            std::cout << "exp " << oc::BitVector(&preValsEven(i, 0), m) << std::endl;
                            std::cout << "act " << even.mPreVal[i] << std::endl;
                            throw RTE_LOC;
                        }
                        if (even.mSufVal[i].getSpan<u8>()[j] != sufValsEven(i, j))
                            throw RTE_LOC;
                    }
                }

                for (u64 j = 0; j < preVals.bytesPerEnrty(); ++j)
                {
                    if (leaves.mPreVal[i].getSpan<u8>()[j] != preVals(i, j))
                    {
                        std::cout << "exp " << oc::BitVector(&preVals(i, 0), m) << std::endl;
                        std::cout << "act " << leaves.mPreVal[i] << std::endl;
                        throw RTE_LOC;
                    }
                    if (leaves.mSufVal[i].getSpan<u8>()[j] != sufVals(i, j))
                        throw RTE_LOC;
                }
            }

        }
    }
}


void AggTree_toPackedBin_Test()
{

    PRNG prng(ZeroBlock);

    //auto op = [](
    //    const oc::BitVector& left,
    //    const oc::BitVector& right)
    //{
    //    return left ^ right;
    //};


    //u64 n = oc::roundUpTo(361, 16);
    for (u64 n : { 8ull, 256ull, 361ull, 24223ull })
    {
        u64 startIdx = n / 2;
        auto numRows = n;
        u64 m = 11;
        AggTree tree;

        BinMatrix in(n + startIdx, m);
        TBinMatrix dst(n, m);

        prng.get(in.data(), in.size());
        in.trim();

        tree.toPackedBin(in, dst, startIdx, numRows);

        auto act = dst.transpose();

        for (u64 i = 0; i < n; ++i)
        {

            for (u64 j = 0; j < in.bytesPerEnrty(); ++j)
            {
                if (act(i, j) != in(i + startIdx, j))
                    throw RTE_LOC;
            }
        }
    }
}

BinMatrix perfectShuffle(const BinMatrix& x0, const BinMatrix& x1)
{
    if (x0.numEntries() != x1.numEntries() &&
        x0.numEntries() != (x1.numEntries() + 1))
        throw RTE_LOC;
    if (x0.bitsPerEntry() != x1.bitsPerEntry())
        throw RTE_LOC;

    BinMatrix r(x0.numEntries() + x1.numEntries(), x0.bitsPerEntry());
    for (u64 i = 0; i < x0.numEntries(); ++i)
        memcpy(r.data(i * 2), x0.data(i), r.bytesPerEnrty());
    for (u64 i = 0; i < x1.numEntries(); ++i)
        memcpy(r.data(i * 2 + 1), x1.data(i), r.bytesPerEnrty());
    return r;
}


void AggTree_dup_pre_levelReveal_Test()
{

    PRNG prng(ZeroBlock);

    u64 m = 11;
    for (u64 n : { 8ull, 256ull, 361ull, 24223ull })
    {

        BinMatrix preBits(n, 1);
        BinMatrix preVals(n, m);
        BinMatrix sufBits(n, 1);
        BinMatrix sufVals(n, m);

        BinMatrix preBitsEven(oc::divCeil(n, 2), 1);
        BinMatrix preValsEven(oc::divCeil(n, 2), m);
        BinMatrix sufBitsEven(oc::divCeil(n, 2), 1);
        BinMatrix sufValsEven(oc::divCeil(n, 2), m);

        BinMatrix preBitsOdd(n - preBitsEven.numEntries(), 1);
        BinMatrix preValsOdd(n - preValsEven.numEntries(), m);
        BinMatrix sufBitsOdd(n - sufBitsEven.numEntries(), 1);
        BinMatrix sufValsOdd(n - sufValsEven.numEntries(), m);

        prng.get(preBits.data(), preBits.size()); preBits.trim();
        prng.get(preVals.data(), preVals.size()); preVals.trim();
        prng.get(sufBits.data(), sufBits.size()); sufBits.trim();
        prng.get(sufVals.data(), sufVals.size()); sufVals.trim();

        for (u64 i = 0; i < n; i += 2)
        {
            preBitsEven(i / 2) = preBits(i);
            sufBitsEven(i / 2) = sufBits(i);
            if (i + 1 != n)
            {
                preBitsOdd(i / 2) = preBits(i + 1);
                sufBitsOdd(i / 2) = sufBits(i + 1);
            }

            for (u64 j = 0; j < preVals.bytesPerEnrty(); ++j)
            {
                preValsEven(i / 2, j) = preVals(i, j);
                sufValsEven(i / 2, j) = sufVals(i, j);
                if (i + 1 != n)
                {
                    preValsOdd(i / 2, j) = preVals(i + 1, j);
                    sufValsOdd(i / 2, j) = sufVals(i + 1, j);
                }
            }
        }

        auto preBitsEvenShare = share(preBitsEven, prng);
        auto preValsEvenShare = share(preValsEven, prng);
        auto sufBitsEvenShare = share(sufBitsEven, prng);
        auto sufValsEvenShare = share(sufValsEven, prng);

        auto preBitsOddShare = share(preBitsOdd, prng);
        auto preValsOddShare = share(preValsOdd, prng);
        auto sufBitsOddShare = share(sufBitsOdd, prng);
        auto sufValsOddShare = share(sufValsOdd, prng);

        std::array<SplitLevel, 2> tvs;

        for (u64 p = 0; p < 2; ++p)
        {
            tvs[p][0].mPreBit = preBitsEvenShare[p].transpose();
            tvs[p][0].mPreVal = preValsEvenShare[p].transpose();
            tvs[p][0].mSufBit = sufBitsEvenShare[p].transpose();
            tvs[p][0].mSufVal = sufValsEvenShare[p].transpose();
            tvs[p][1].mPreBit = preBitsOddShare[p].transpose();
            tvs[p][1].mPreVal = preValsOddShare[p].transpose();
            tvs[p][1].mSufBit = sufBitsOddShare[p].transpose();
            tvs[p][1].mSufVal = sufValsOddShare[p].transpose();
        }

        PLevel leaves;
        PLevel even;
        even.reveal(tvs[0][0], tvs[1][0]);
        leaves.reveal(tvs[0], tvs[1]);


        for (u64 i = 0; i < n; ++i)
        {
            if (leaves.mPreBit[i] != preBits(i))
                throw RTE_LOC;
            if (leaves.mSufBit[i] != sufBits(i))
                throw RTE_LOC;

            if (i < preValsEven.numEntries())
            {
                for (u64 j = 0; j < preVals.bytesPerEnrty(); ++j)
                {
                    if (even.mPreVal[i].getSpan<u8>()[j] != preValsEven(i, j))
                    {
                        std::cout << "exp " << oc::BitVector(&preValsEven(i, 0), m) << std::endl;
                        std::cout << "act " << even.mPreVal[i] << std::endl;
                        throw RTE_LOC;
                    }
                    if (even.mSufVal[i].getSpan<u8>()[j] != sufValsEven(i, j))
                        throw RTE_LOC;
                }
            }

            for (u64 j = 0; j < preVals.bytesPerEnrty(); ++j)
            {
                if (leaves.mPreVal[i].getSpan<u8>()[j] != preVals(i, j))
                {
                    std::cout << "exp " << oc::BitVector(&preVals(i, 0), m) << std::endl;
                    std::cout << "act " << leaves.mPreVal[i] << std::endl;
                    throw RTE_LOC;
                }
                if (leaves.mSufVal[i].getSpan<u8>()[j] != sufVals(i, j))
                    throw RTE_LOC;
            }
        }
    }
}



void AggTree_dup_singleSetLeaves_Test()
{

    PRNG prng(ZeroBlock);


    u64 m = 11;
    u64 logn, logfn, n16, r, n0;;
    for (u64 n : { 8ull, 256ull, 361ull, 24223ull })
    {
        {
            n16 = n;
            logn = oc::log2ceil(n);
            logfn = oc::log2floor(n);
            if (logn != logfn)
            {
                n16 = oc::roundUpTo(n, 16);
                logn = oc::log2ceil(n16);
                logfn = oc::log2floor(n16);

            }

            r = n16 - (1ull << logfn);
            n0 = r ? 2 * r : n16;
            //n1 = n16 - n0;

        }
         
        for (auto type : { AggTree::Type::Prefix, AggTree::Type::Suffix,AggTree::Type::Full })
        {
            //auto nPow = 1ull << oc::log2ceil(n);

            for (auto level : {0,1})
            {
                SplitLevel tvs;

                BinMatrix s(n, m), expS;
                BinMatrix c(n, 1), expPreC, expSufC;
                prng.get(s.data(), s.size());
                s.trim();
                for (u64 i = 1; i < n; ++i)
                    c(i) = prng.getBit();
                    //c(i) = 1;

                if (logn==logfn)
                {
                    if (level)
                        continue;

                    tvs.resize(n, m, type);
                    tvs.setLeafVals(s, c, 0, 0);

                    expS = s;
                    expPreC = c;
                    expPreC.resize(n, 1);
                    expSufC = c;
                    for (u64 i = 1; i < expSufC.size(); ++i)
                        expSufC(i - 1) = expSufC(i);
                    expSufC(expSufC.size() - 1) = 0;
                }
                else
                {
                    if (level == 0)
                    {
                        //std::cout << "exp clast " << (int)c(n0) << " @ " << n0 << std::endl;
                        tvs.resize(n0, m, type);
                        tvs.setLeafVals(s, c, 0, 0);

                        expS = s; expS.resize(n0, m);
                        expPreC = c; expPreC.resize(n0, 1);
                        expSufC.resize(n0, 1);
                        for (u64 i = 0; i < expSufC.size(); ++i)
                            expSufC(i) = c(i + 1);
                    }
                    else
                    {
                        auto nn = 1ull << logfn;
                        tvs.resize(nn, m, type);
                        tvs.setLeafVals(s, c, n0, r);

                        expS.resize(nn, m);
                        expPreC.resize(nn, 1);

                        memcpy<u8, u8>(expS.subMatrix(r, n - n0), s.subMatrix(n0));
                        memcpy<u8, u8>(expPreC.subMatrix(r, n - n0), c.subMatrix(n0));

                        expSufC = expPreC; expSufC.resize(nn, 1);
                        for (u64 i = r+1; i < expSufC.size(); ++i)
                            expSufC(i - 1) = expSufC(i);
                        expSufC(expSufC.size() - 1) = 0;
                    }
                }

                auto even = tvs[0];
                auto odd = tvs[1];

                auto preBit = perfectShuffle(even.mPreBit.transpose(), odd.mPreBit.transpose());
                auto sufBit = perfectShuffle(even.mSufBit.transpose(), odd.mSufBit.transpose());
                auto preVal = perfectShuffle(even.mPreVal.transpose(), odd.mPreVal.transpose());
                auto sufVal = perfectShuffle(even.mSufVal.transpose(), odd.mSufVal.transpose());

                bool failed = false;
                for (u64 i = 0; i < expS.numEntries(); ++i)
                {
                    if ((type & AggTree::Type::Prefix) &&
                        preBit(i) != expPreC(i))
                    {
                        std::cout << (int)preBit(i) << " != " << (int)expPreC(i) << std::endl;
                        throw RTE_LOC;
                    }

                    if ((type & AggTree::Type::Suffix))
                    {

                        //std::cout << "suf " << i << " " << (int)sufBit(i) << " != " << (int)expSufC(i) << std::endl;
                        if (sufBit(i) != expSufC(i))
                        {
                            failed = true;
                            throw RTE_LOC;
                        }
                    }

                    for (u64 j = 0; j < s.bytesPerEnrty(); ++j)
                    {

                        if ((type & AggTree::Type::Prefix) &&
                            preVal(i, j) != expS(i, j))
                            throw RTE_LOC;
                        if ((type & AggTree::Type::Suffix) &&
                            sufVal(i, j) != expS(i, j))
                            throw RTE_LOC;
                    }
                }

                if (failed)
                    throw RTE_LOC;
            }
        }
    }
}

void AggTree_dup_pre_setLeaves_Test()
{

    PRNG prng(ZeroBlock);

    auto op = [](
        const oc::BitVector& left,
        const oc::BitVector& right)
    {
        return left ^ right;
    };


    //u64 n = oc::roundUpTo(361, 16);
    for (u64 n : { 8ull, 256ull, 361ull, 24223ull })
    {
        u64 m = 11;

        PTree tree;


        tree.init(n, m, prng, op);
        auto s = tree.shareVals(prng);
        auto c = tree.shareBits(prng);

        //for (u64 i = 0; i < n; ++i)
        //    std::cout << "v " << i << " " << tree.mInput[i] << " " << (int)s[0](i,0) << " " << (int)s[1](i,0) << std::endl;

        for (auto type : { AggTree::Type::Prefix, AggTree::Type::Suffix,AggTree::Type::Full })
        {
            std::array<SplitLevel, 2> tvs[2];

            for (u64 p = 0; p < 2; ++p)
            {
                if (tree.logfn == tree.logn)
                {
                    tvs[p][0].resize(tree.n16, m, type);
                    tvs[p][0].setLeafVals(s[p], c[p], 0, 0);
                }
                else
                {
                    tvs[p][0].resize(tree.n0, m, type);
                    tvs[p][1].resize(1ull << tree.logfn, m, type);

                    tvs[p][0].setLeafVals(s[p], c[p], 0, 0);
                    tvs[p][1].setLeafVals(s[p], c[p], tree.n0, tree.r);
                }
            }

            PLevel leaves[2];

            if (tree.logfn == tree.logn)
            {
                leaves[0].reveal(tvs[0][0], tvs[1][0]);
            }
            else
            {

                leaves[0].reveal(tvs[0][0], tvs[1][0]);
                leaves[1].reveal(tvs[0][1], tvs[1][1]);
            }

            for (u64 i = 0; i < tree.n16; ++i)
            {
                auto q = i < tree.n0 ? 0 : 1;
                auto w = i < tree.n0 ? i : i - tree.r;

                if (type & AggTree::Type::Prefix)
                {

                    auto v0 = leaves[q].mPreVal[w];
                    auto b0 = leaves[q].mPreBit[w];

                    auto expV = tree.mLevels[q].mUp.mPreVal[w];
                    auto expB = tree.mLevels[q].mUp.mPreBit[w];
                    if (expV != v0)
                    {
                        std::cout << "\nexp " << (expV) << std::endl;
                        std::cout << "act " << (v0) << std::endl;
                        throw RTE_LOC;
                    }

                    if (expB != (b0))
                    {
                        std::cout << "\nexp " << expB << std::endl;
                        std::cout << "act " << b0 << std::endl;
                        throw RTE_LOC;
                    }
                }

                if (type & AggTree::Type::Suffix)
                {
                    auto v0 = leaves[q].mSufVal[w];
                    auto b0 = leaves[q].mSufBit[w];

                    auto expV = tree.mLevels[q].mUp.mSufVal[w];
                    auto expB = tree.mLevels[q].mUp.mSufBit[w];
                    if (expV != v0)
                    {
                        std::cout << "\nexp " << (expV) << std::endl;
                        std::cout << "act " << (v0) << std::endl;
                        throw RTE_LOC;
                    }

                    if (expB != (b0))
                    {
                        std::cout << "\nexp " << expB << std::endl;
                        std::cout << "act " << b0 << std::endl;
                        throw RTE_LOC;
                    }
                }
            }
        }
    }
}
//
//
//void AggTree_dup_pre_upstream_cir_Test()
//{
//	u64 bitCount = 1;
//
//	AggTree t0;
//	t0.mDebug = true;
//	auto op = [](
//		oc::BetaCircuit& cir,
//		const oc::BetaBundle& left,
//		const oc::BetaBundle& right,
//		oc::BetaBundle& out)
//	{
//		cir.addCopy(left, out);
//	};
//	auto cir = t0.upstreamCir(bitCount, AggTree::Prefix, op);
//
//	cir.levelByAndDepth(BetaCircuit::LevelizeType::Reorder);
//
//	eval(cir, 10, 10, true, ~0ull);
//
//}
//
//namespace
//{
//	struct TreeRecord
//	{
//		oc::BitVector prefix, suffix;
//		u8 pProd, sProd;
//
//		TreeRecord(i64* v, u64 bitCount, AggTree::Type type)
//		{
//			throw RTE_LOC;
//			//u8* iter = (u8*)v;
//			//auto bitCount8 = oc::roundUpTo(bitCount, 8);
//
//
//			//if (type & AggTree::Type::Prefix)
//			//{
//			//	prefix.append(iter, bitCount);
//			//	iter += bitCount8 / 8;
//			//}
//
//			//if (type & AggTree::Type::Suffix)
//			//{
//			//	suffix.append(iter, bitCount);
//			//	iter += bitCount8 / 8;
//			//}
//
//			//pProd = iter[0] & 1;
//			//sProd = (iter[0] / 2) & 1;
//		}
//	};
//}
//
//void AggTree_dup_pre_upstream_Test()
//{
//
//	auto opp = [](
//		const oc::BitVector& left,
//		const oc::BitVector& right)
//	{
//		return left;
//	};
//	auto op = [](
//		oc::BetaCircuit& cir,
//		const oc::BetaBundle& left,
//		const oc::BetaBundle& right,
//		oc::BetaBundle& out)
//	{
//		cir.addCopy(left, out);
//	};
//
//	TestComm comm;
//	CommPkg& com0 = comm[0];
//	CommPkg& com1 = comm[1];
//	CommPkg& com2 = comm[2];
//
//	u64 n = 311;
//	u64 m = 11;
//	auto type = AggTree::Type::Prefix;
//
//	Sh3Encryptor e0, e1, e2;
//	e0.init(0, block(0, 0), block(1, 1));
//	e1.init(1, block(1, 1), block(2, 2));
//	e2.init(2, block(2, 2), block(0, 0));
//	auto& g0 = e0.mShareGen;
//	auto& g1 = e1.mShareGen;
//	auto& g2 = e2.mShareGen;
//
//	PRNG prng(oc::ZeroBlock);
//	AggTree t0, t1, t2;
//	PTreeNew tree;
//	tree.init(n, m, prng, opp);
//
//	Level root[3];
//
//	auto n16 = tree.n16;
//	auto logn = tree.logn;
//	auto logfn = tree.logfn;
//	auto s = tree.shareVals(prng);
//	auto c = tree.shareBits(prng);
//
//	std::array<std::vector<SplitLevel>, 3> tvs;
//	tvs[0].resize(logn);
//	tvs[1].resize(logn);
//	tvs[2].resize(logn);
//
//
//	auto f0 = std::async([&]() {
//		t0.upstream(s[0], c[0], op, 0, type, com0, g0, root[0], tvs[0]);
//		});
//	auto f1 = std::async([&]() {
//		t1.upstream(s[1], c[1], op, 1, type, com1, g1, root[1], tvs[1]);
//		});
//	auto f2 = std::async([&]() {
//		t2.upstream(s[2], c[2], op, 2, type, com2, g2, root[2], tvs[2]);
//		});
//
//	f0.get();
//	f1.get();
//	f2.get();
//
//	if (tvs[0].size() != logn)
//		throw RTE_LOC;
//
//	std::vector<PLevel> levels(logn);
//	for (u64 i = 0; i < levels.size(); ++i)
//	{
//		levels[i].load(tvs[0][i], tvs[1][i], tvs[2][i]);
//	}
//	levels.emplace_back();
//	levels.back().load(root[0], root[1], root[2]);
//
//	for (u64 j = 0; j < tree.mLevels.size(); ++j)
//	{
//		auto& exp = tree.mLevels[j].mUp;
//		for (u64 i = 0; i < exp.size(); ++i)
//		{
//
//			if (levels[j].mPreVal[i] != exp.mPreVal[i])
//			{
//				std::cout << "\n i" << i << std::endl;
//				std::cout << "exp " << exp.mPreVal[i] << std::endl;
//				std::cout << "act " << levels[j].mPreVal[i] << std::endl;
//				throw RTE_LOC;
//			}
//			if (levels[j].mPreBit[i] != exp.mPreBit[i])
//				throw RTE_LOC;
//		}
//	}
//}
//
//namespace {
//
//	void compare(oc::BetaCircuit& c0, oc::BetaCircuit& c1)
//	{
//		u64 numTrials = 10;
//		using namespace oc;
//
//		u64 numInputs = c0.mInputs.size();
//		u64 numOutputs = c0.mOutputs.size();
//
//		if (numInputs != c1.mInputs.size())
//			throw std::runtime_error(LOCATION);
//		if (numOutputs != c1.mOutputs.size())
//			throw std::runtime_error(LOCATION);
//
//		std::vector<BitVector> inputs(numInputs);
//		std::vector<BitVector> output0(numOutputs), output1(numOutputs);
//		PRNG prng(ZeroBlock);
//
//		for (u64 t = 0; t < numTrials; ++t)
//		{
//			for (u64 i = 0; i < numInputs; ++i)
//			{
//				if (c0.mInputs[i].size() != c1.mInputs[i].size())
//					throw RTE_LOC;
//
//				inputs[i].resize(c0.mInputs[i].size());
//				inputs[i].randomize(prng);
//			}
//			for (u64 i = 0; i < numOutputs; ++i)
//			{
//				if (c0.mOutputs[i].size() != c1.mOutputs[i].size())
//					throw RTE_LOC;
//				output0[i].resize(c0.mOutputs[i].size());
//				output1[i].resize(c0.mOutputs[i].size());
//			}
//
//			c0.evaluate(inputs, output0, false);
//			//std::cout << "\n";
//			c1.evaluate(inputs, output1, false);
//
//			for (u64 i = 0; i < numOutputs; ++i)
//			{
//				if (output0[i] != output1[i])
//				{
//					for (u64 j = 0; j < output0[i].size(); ++j)
//						std::cout << (j / 10);
//					std::cout << std::endl;
//					for (u64 j = 0; j < output0[i].size(); ++j)
//						std::cout << (j % 10);
//					std::cout << std::endl;
//					std::cout << output0[i] << std::endl;
//					std::cout << output1[i] << std::endl;
//					std::cout << (output0[i] ^ output1[i]) << std::endl;
//
//					throw RTE_LOC;
//				}
//				//for (u64 j = 0; j < numShares; ++j)
//				//{
//				//	BitVector oj((u8*)out[j].data(), cir.mOutputs[i].size());
//				//	if (oj != outputs[j][i])
//				//	{
//				//		std::cout << "exp " << outputs[j][i] << std::endl;
//				//		std::cout << "act " << oj << std::endl;
//				//		throw RTE_LOC;
//				//	}
//				//}
//			}
//		}
//	}
//
//}
//void AggTree_dup_pre_downstream_cir_Test()
//{
//	u64 bitCount = 1;
//
//	AggTree t0;
//	t0.mDebug = true;
//	auto op = [](
//		oc::BetaCircuit& cir,
//		const oc::BetaBundle& left,
//		const oc::BetaBundle& right,
//		oc::BetaBundle& out)
//	{
//		cir.addCopy(left, out);
//	};
//	auto cir = t0.downstreamCir(bitCount, op, AggTree::Prefix);
//
//	auto c1 = cir;
//	cir.levelByAndDepth();
//	compare(c1, cir);
//	eval(cir, 10, 10, false, ~0ull);
//}
//
//template<typename Op, typename OpCir>
//void AggTree_pre_downstream_Test(Op op, OpCir opCir)
//{
//
//	TestComm com;
//
//	u64 n = 311;
//	u64 m = 64;
//	auto type = AggTree::Prefix;
//
//	std::array<Sh3ShareGen, 3> g;
//	g[0].init(block(0, 0), block(1, 1));
//	g[1].init(block(1, 1), block(2, 2));
//	g[2].init(block(2, 2), block(0, 0));
//
//	AggTree t[3];
//	t[0].mDebug = true;
//	t[1].mDebug = true;
//	t[2].mDebug = true;
//
//	PRNG prng(ZeroBlock);
//	PTreeNew tree;
//	tree.init(n, m, prng, op);
//
//	auto s = tree.shareVals(prng);
//	auto c = tree.shareBits(prng);
//
//	std::array<Level, 3> root, root2;
//	std::array<SplitLevel, 3> preSuf, vals;
//	std::array<std::vector<SplitLevel>, 3> tvs;
//	auto logn = tree.logn;
//	tvs[0].resize(logn);
//	tvs[1].resize(logn);
//	tvs[2].resize(logn);
//
//	std::array<std::future<void>, 3>ff;
//
//	for (u64 i = 0; i < 3; ++i)
//		ff[i] = std::async([&, i]()
//			{
//				t[i].upstream(s[i], c[i], opCir, i, type, com[i], g[i], root[i], tvs[i]);
//				root2[i] = root[i];
//				t[i].downstream(s[i], c[i], opCir, root[i], tvs[i], preSuf[i], vals[i], i, type, com[i], g[i]);
//			});
//
//	ff[0].get();
//	ff[1].get();
//	ff[2].get();
//
//	std::vector<PLevel> levels(logn);
//	for (u64 i = 0; i < levels.size(); ++i)
//	{
//		levels[i].load(tvs[0][i], tvs[1][i], tvs[2][i]);
//	}
//	levels.emplace_back();
//	levels.back().load(root2[0], root2[1], root2[2]);
//
//	for (u64 j = levels.size() - 2; j < levels.size(); --j)
//	{
//		auto& lvl = tree.mLevels[j];
//
//		for (u64 i = 0; i < lvl.mDown.size(); ++i)
//		{
//			auto act = levels[j].mPreVal[i];
//			auto exp = tree.mLevels[j].mDown.mPreVal[i];
//			if (exp != act)
//			{
//				std::cout << "\ni " << i << std::endl;
//				std::cout << "act " << act << std::endl;
//				std::cout << "exp " << exp << std::endl << std::endl;
//
//				auto p = i / 2;
//				auto l = i & 0;
//				auto r = i | 1;
//				std::cout << "pnt exp " << tree.mLevels[j + 1].mUp.mPreVal[p] << " " << tree.mLevels[j + 1].mUp.mPreBit[p] << "  " << p << std::endl;
//				std::cout << "    act " << levels[j + 1].mPreVal[p] << " " << levels[j + 1].mPreBit[p] << std::endl;
//				std::cout << "ch0 exp " << tree.mLevels[j].mUp.mPreVal[l] << " " << tree.mLevels[j].mUp.mPreBit[l] << "  " << l << (l == i ? " <- " : "") << std::endl;
//				std::cout << "    act " << levels[j].mPreVal[l] << " " << levels[j].mPreBit[l] << std::endl;
//				std::cout << "ch1 exp " << tree.mLevels[j].mUp.mPreVal[r] << " " << tree.mLevels[j].mUp.mPreBit[r] << "  " << r << (r == i ? " <- " : "") << std::endl;
//				std::cout << "    act " << levels[j].mPreVal[r] << " " << levels[j].mPreBit[r] << std::endl;
//
//
//				throw RTE_LOC;
//			}
//		}
//	}
//
//	PLevel pre; pre.load(preSuf[0], preSuf[1], preSuf[2]);
//	PLevel val; val.load(vals[0], vals[1], vals[2]);
//
//	for (u64 i = 0; i < n; ++i)
//	{
//		auto q = i < tree.n0 ? 0 : 1;
//		auto w = i < tree.n0 ? i : i - tree.r;
//
//		{
//			auto exp = tree.mLevels[q].mDown.mPreVal[w];
//			auto act = pre.mPreVal[i];
//			if (act != exp)
//			{
//				std::cout << "i   " << i << std::endl;
//				std::cout << "exp " << exp << std::endl;
//				std::cout << "act " << act << std::endl;
//				std::cout << "    " << (act ^ exp) << std::endl;
//
//				throw RTE_LOC;
//			}
//		}
//
//		{
//			auto exp = tree.mLevels[q].mUp.mPreVal[w];
//			auto act = val.mPreVal[i];
//			if (act != exp)
//			{
//				std::cout << "i   " << i << std::endl;
//				std::cout << "exp " << exp << std::endl;
//				std::cout << "act " << act << std::endl;
//				std::cout << "    " << (act ^ exp) << std::endl;
//
//				throw RTE_LOC;
//			}
//		}
//
//		{
//			auto exp = tree.mLevels[q].mUp.mPreBit[w];
//			auto act = val.mPreBit[i];
//			if (act != exp)
//			{
//				std::cout << "i   " << i << std::endl;
//				std::cout << "exp " << exp << std::endl;
//				std::cout << "act " << act << std::endl;
//				std::cout << "    " << (act ^ exp) << std::endl;
//
//				throw RTE_LOC;
//			}
//		}
//	}
//}
//
//void AggTree_dup_pre_downstream_Test()
//{
//	auto opCir = [](
//		oc::BetaCircuit& cir,
//		const oc::BetaBundle& left,
//		const oc::BetaBundle& right,
//		oc::BetaBundle& out)
//	{
//		cir.addCopy(left, out);
//	};
//
//	auto op = [](
//		const oc::BitVector& left,
//		const oc::BitVector& right)
//	{
//		return left;
//	};
//	AggTree_pre_downstream_Test(op, opCir);
//}
//
//
//void AggTree_xor_pre_downstream_Test()
//{
//	auto opCir = [](
//		oc::BetaCircuit& cir,
//		const oc::BetaBundle& left,
//		const oc::BetaBundle& right,
//		oc::BetaBundle& out)
//	{
//		for (u64 i = 0; i < left.size(); ++i)
//			cir.addGate(left[i], right[i], oc::GateType::Xor, out[i]);
//	};
//
//	auto op = [](
//		const oc::BitVector& left,
//		const oc::BitVector& right)
//	{
//		return left ^ right;
//	};
//	AggTree_pre_downstream_Test(op, opCir);
//}
//
//
//template<typename Op, typename OpCir>
//void AggTree_pre_full_Test(Op op, OpCir opCir)
//{
//	IOService ios;
//	auto sl01 = Session(ios, "127.0.0.1:1212", SessionMode::Server, "12");
//	auto sl10 = Session(ios, "127.0.0.1:1212", SessionMode::Client, "12");
//	auto sl02 = Session(ios, "127.0.0.1:1212", SessionMode::Server, "13");
//	auto sl20 = Session(ios, "127.0.0.1:1212", SessionMode::Client, "13");
//	auto sl12 = Session(ios, "127.0.0.1:1212", SessionMode::Server, "23");
//	auto sl21 = Session(ios, "127.0.0.1:1212", SessionMode::Client, "23");
//
//	Channel chl01 = sl01.addChannel();
//	Channel chl10 = sl10.addChannel();
//	Channel chl02 = sl02.addChannel();
//	Channel chl20 = sl20.addChannel();
//	Channel chl12 = sl12.addChannel();
//	Channel chl21 = sl21.addChannel();
//
//	CommPkg com0{ chl02, chl01 };
//	CommPkg com1{ chl10, chl12 };
//	CommPkg com2{ chl21, chl20 };
//
//	u64 n = 311;
//	u64 m = 100;
//	auto type = AggTree::Prefix;
//
//	Sh3Encryptor e0, e1, e2;
//	e0.init(0, block(0, 0), block(1, 1));
//	e1.init(1, block(1, 1), block(2, 2));
//	e2.init(2, block(2, 2), block(0, 0));
//	auto& g0 = e0.mShareGen;
//	auto& g1 = e1.mShareGen;
//	auto& g2 = e2.mShareGen;
//	PRNG prng(oc::ZeroBlock);
//
//	AggTree t0, t1, t2;
//	PTreeNew tree;
//	tree.init(n, m, prng, op);
//
//
//	auto s = tree.shareVals(prng);
//	auto c = tree.shareBits(prng);
//	BinMatrix d0(n, m), d1(n, m), d2(n, m);
//
//	auto f0 = std::async([&]() {
//		t0.apply(s[0], c[0], opCir, 0, type, com0, g0, d0);
//		});
//	auto f1 = std::async([&]() {
//		t1.apply(s[1], c[1], opCir, 1, type, com1, g1, d1);
//		});
//	auto f2 = std::async([&]() {
//		t2.apply(s[2], c[2], opCir, 2, type, com2, g2, d2);
//		});
//
//	f0.get();
//	f1.get();
//	f2.get();
//
//	auto dd = reveal(d0, d1, d2);
//	for (u64 i = 0; i < n; ++i)
//	{
//		auto act = BitVector((u8*)&dd(i, 0), m);
//		if (act != tree.mPre[i])
//		{
//			std::cout << "\n" << i << std::endl;
//			std::cout << "act " << act << std::endl;
//			std::cout << "exp " << tree.mPre[i] << std::endl;
//
//			std::cout << "\n";
//			std::cout << "val " << tree.mInput[i] << " " << tree.mLevels[0].mDown.mPreVal[i] << " " << tree.mCtrl[i] << std::endl;
//			//std::cout << "act " << tree.mInput[i] << " " << tree.mLevels[o].mDown.mPreVal[i] << " " << tree.mCtrl[i] << std::endl;
//			throw RTE_LOC;
//		}
//	}
//}
//
//
//void AggTree_dup_pre_full_Test()
//{
//	auto opCir = [](
//		oc::BetaCircuit& cir,
//		const oc::BetaBundle& left,
//		const oc::BetaBundle& right,
//		oc::BetaBundle& out)
//	{
//		cir.addCopy(left, out);
//	};
//
//	auto op = [](
//		const oc::BitVector& left,
//		const oc::BitVector& right)
//	{
//		return left;
//	};
//
//	AggTree_pre_full_Test(op, opCir);
//}
//
//
//void AggTree_xor_pre_full_Test()
//{
//	auto opCir = [](
//		oc::BetaCircuit& cir,
//		const oc::BetaBundle& left,
//		const oc::BetaBundle& right,
//		oc::BetaBundle& out)
//	{
//		for (u64 i = 0; i < left.size(); ++i)
//			cir.addGate(left[i], right[i], oc::GateType::Xor, out[i]);
//	};
//
//	auto op = [](
//		const oc::BitVector& left,
//		const oc::BitVector& right)
//	{
//		return left ^ right;
//	};
//
//	AggTree_pre_full_Test(op, opCir);
//}
//
//void AggTree_dup_suf_upstream_Test()
//{
//	auto cop = [](
//		oc::BetaCircuit& cir,
//		const oc::BetaBundle& left,
//		const oc::BetaBundle& right,
//		oc::BetaBundle& out)
//	{
//		cir.addCopy(right, out);
//	};
//	auto op = [](
//		const oc::BitVector& left,
//		const oc::BitVector& right)
//	{
//		return right;
//	};
//
//	auto type = AggTree::Type::Suffix;
//	TestComm com;
//
//	u64 n = 16;
//	u64 m = 64;
//
//
//	std::array<Sh3ShareGen, 3> g;
//	g[0].init(block(0, 0), block(1, 1));
//	g[1].init(block(1, 1), block(2, 2));
//	g[2].init(block(2, 2), block(0, 0));
//
//	AggTree t[3];
//	t[0].mDebug = true;
//	t[1].mDebug = true;
//	t[2].mDebug = true;
//
//	PTreeNew tree;
//	PRNG prng(ZeroBlock);
//	tree.init(n, m, prng, op);
//
//	auto s = tree.shareVals(prng);
//	auto c = tree.shareBits(prng);
//
//	auto logn = tree.logn;
//	std::array<Level, 3> root;
//	std::array<SplitLevel, 3> preSuf, vals;
//	std::array<std::vector<SplitLevel>, 3> tvs;
//	tvs[0].resize(logn);
//	tvs[1].resize(logn);
//	tvs[2].resize(logn);
//
//	std::array<std::future<void>, 3>ff;
//
//	for (u64 i = 0; i < 3; ++i)
//		ff[i] = std::async([&, i]()
//			{
//				t[i].upstream(s[i], c[i], cop, i, type, com[i], g[i], root[i], tvs[i]);
//			});
//
//	ff[0].get();
//	ff[1].get();
//	ff[2].get();
//
//
//	if (tvs[0].size() != logn)
//		throw RTE_LOC;
//
//	std::vector<PLevel> levels(logn);
//	for (u64 i = 0; i < levels.size(); ++i)
//	{
//		levels[i].load(tvs[0][i], tvs[1][i], tvs[2][i]);
//	}
//	levels.emplace_back();
//	levels.back().load(root[0], root[1], root[2]);
//
//	for (u64 j = 0; j < tree.mLevels.size(); ++j)
//	{
//		auto& exp = tree.mLevels[j].mUp;
//		for (u64 i = 0; i < exp.size(); ++i)
//		{
//			if (levels[j].mSufVal[i] != exp.mSufVal[i])
//			{
//				std::cout << "\n i" << i << std::endl;
//				std::cout << "exp " << exp.mSufVal[i] << std::endl;
//				std::cout << "act " << levels[j].mSufVal[i] << std::endl;
//				throw RTE_LOC;
//			}
//			if (levels[j].mSufBit[i] != exp.mSufBit[i])
//				throw RTE_LOC;
//		}
//	}
//}
//
//
//
//void AggTree_dup_suf_downstream_Test()
//{
//
//	auto op = [](
//		const oc::BitVector& left,
//		const oc::BitVector& right)
//	{
//		return left;
//	};
//	auto opCir = [](
//		oc::BetaCircuit& cir,
//		const oc::BetaBundle& left,
//		const oc::BetaBundle& right,
//		oc::BetaBundle& out)
//	{
//		cir.addCopy(left, out);
//	};
//
//	TestComm com;
//
//	for (u64 n : {16, 25, 311, 3423, 43423})
//	{
//
//		u64 m = 64;
//		auto type = AggTree::Suffix;
//
//		std::array<Sh3ShareGen, 3> g;
//		g[0].init(block(0, 0), block(1, 1));
//		g[1].init(block(1, 1), block(2, 2));
//		g[2].init(block(2, 2), block(0, 0));
//
//		AggTree t[3];
//		t[0].mDebug = true;
//		t[1].mDebug = true;
//		t[2].mDebug = true;
//
//		PRNG prng(ZeroBlock);
//		PTreeNew tree;
//		tree.init(n, m, prng, op);
//
//		auto s = tree.shareVals(prng);
//		auto c = tree.shareBits(prng);
//
//		std::array<Level, 3> root, root2;
//		std::array<SplitLevel, 3> preSuf, vals;
//		std::array<std::vector<SplitLevel>, 3> tvs;
//		auto logn = tree.logn;
//		tvs[0].resize(logn);
//		tvs[1].resize(logn);
//		tvs[2].resize(logn);
//
//		std::array<std::future<void>, 3>ff;
//
//		for (u64 i = 0; i < 3; ++i)
//			ff[i] = std::async([&, i]()
//				{
//					t[i].upstream(s[i], c[i], opCir, i, type, com[i], g[i], root[i], tvs[i]);
//					root2[i] = root[i];
//					t[i].downstream(s[i], c[i], opCir, root[i], tvs[i], preSuf[i], vals[i], i, type, com[i], g[i]);
//				});
//
//		ff[0].get();
//		ff[1].get();
//		ff[2].get();
//
//		std::vector<PLevel> levels(logn);
//		for (u64 i = 0; i < levels.size(); ++i)
//		{
//			levels[i].load(tvs[0][i], tvs[1][i], tvs[2][i]);
//		}
//		levels.emplace_back();
//		levels.back().load(root2[0], root2[1], root2[2]);
//
//		for (u64 j = levels.size() - 2; j < levels.size(); --j)
//		{
//			auto& lvl = tree.mLevels[j];
//
//			for (u64 i = 0; i < lvl.mDown.size(); ++i)
//			{
//				auto act = levels[j].mSufVal[i];
//				auto exp = tree.mLevels[j].mDown.mSufVal[i];
//				if (exp != act)
//				{
//					std::cout << "\ni " << i << std::endl;
//					std::cout << "act " << act << std::endl;
//					std::cout << "exp " << exp << std::endl << std::endl;
//
//					auto p = i / 2;
//					auto l = i & 0;
//					auto r = i | 1;
//					std::cout << "pnt exp " << tree.mLevels[j + 1].mUp.mSufVal[p] << " " << tree.mLevels[j + 1].mUp.mSufBit[p] << "  " << p << std::endl;
//					std::cout << "    act " << levels[j + 1].mSufVal[p] << " " << levels[j + 1].mSufBit[p] << std::endl;
//					std::cout << "ch0 exp " << tree.mLevels[j].mUp.mSufVal[l] << " " << tree.mLevels[j].mUp.mSufBit[l] << "  " << l << (l == i ? " <- " : "") << std::endl;
//					std::cout << "    act " << levels[j].mSufVal[l] << " " << levels[j].mSufBit[l] << std::endl;
//					std::cout << "ch1 exp " << tree.mLevels[j].mUp.mSufVal[r] << " " << tree.mLevels[j].mUp.mSufBit[r] << "  " << r << (r == i ? " <- " : "") << std::endl;
//					std::cout << "    act " << levels[j].mSufVal[r] << " " << levels[j].mSufBit[r] << std::endl;
//
//
//					throw RTE_LOC;
//				}
//			}
//		}
//
//		PLevel pre; pre.load(preSuf[0], preSuf[1], preSuf[2]);
//		PLevel val; val.load(vals[0], vals[1], vals[2]);
//
//		for (u64 i = 0; i < n; ++i)
//		{
//			auto q = i < tree.n0 ? 0 : 1;
//			auto w = i < tree.n0 ? i : i - tree.r;
//
//			{
//				auto exp = tree.mLevels[q].mDown.mSufVal[w];
//				auto act = pre.mSufVal[i];
//				if (act != exp)
//				{
//					std::cout << "i   " << i << std::endl;
//					std::cout << "exp " << exp << std::endl;
//					std::cout << "act " << act << std::endl;
//					std::cout << "    " << (act ^ exp) << std::endl;
//
//					throw RTE_LOC;
//				}
//			}
//
//			{
//				auto exp = tree.mLevels[q].mUp.mSufVal[w];
//				auto act = val.mSufVal[i];
//				if (act != exp)
//				{
//					std::cout << "i   " << i << std::endl;
//					std::cout << "exp " << exp << std::endl;
//					std::cout << "act " << act << std::endl;
//					std::cout << "    " << (act ^ exp) << std::endl;
//
//					throw RTE_LOC;
//				}
//			}
//
//			{
//				//auto exp = tree.mLevels[q].mUp.mSufBit[w];
//				//auto act = val.mSufBit[i];
//				//auto exp2 = (i + 1 < tree.mCtrl.size()) ? (u8)tree.mCtrl[i+1] : 0;
//				//if (act != exp)
//				//{
//				//	std::cout << "i   " << i << std::endl;
//				//	std::cout << "exp " << exp << std::endl;
//				//	std::cout << "eee " << exp2 << std::endl;
//				//	std::cout << "act " << act << std::endl;
//				//	std::cout << "    " << (act ^ exp) << std::endl;
//
//				//	throw RTE_LOC;
//				//}
//			}
//		}
//
//	}
//}
//
//
//template<typename Op, typename OpCir>
//void AggTree_suf_full_Test(Op op, OpCir opCir)
//{
//
//	TestComm com;
//	for (u64 n : {16, 23, 256, 24223})
//	{
//
//		u64 m = 111;
//
//		Sh3Encryptor e0, e1, e2;
//		e0.init(0, block(0, 0), block(1, 1));
//		e1.init(1, block(1, 1), block(2, 2));
//		e2.init(2, block(2, 2), block(0, 0));
//		auto& g0 = e0.mShareGen;
//		auto& g1 = e1.mShareGen;
//		auto& g2 = e2.mShareGen;
//
//		AggTree t0, t1, t2;
//
//		BinMatrix s0(n, m), s1(n, m), s2(n, m);
//		BinMatrix d0(n, m), d1(n, m), d2(n, m);
//		BinMatrix c0(n, m), c1(n, m), c2(n, m);
//
//		Matrix<i64> ss(n, oc::divCeil(m, 64));
//		std::vector<oc::BitVector> s(n), d(n);
//		Matrix<i64> c(n, 1);
//
//		PRNG prng(ZeroBlock);
//		for (u64 i = 0; i < n; ++i)
//		{
//			s[i].resize(m);
//			memset(s[i].data(), i + 1, s[i].sizeBytes());
//			memcpy(ss[i].data(), s[i].data(), s[i].sizeBytes());
//		}
//
//		d[n - 1] = s[n - 1];
//		c(n - 1) = prng.getBit();
//		for (u64 i = n - 2; i < n; --i)
//		{
//			c(i) = i ? prng.getBit() : 0;
//
//			if (c(i + 1))
//				d[i] = op(s[i], d[i + 1]);
//			else
//				d[i] = s[i];
//		}
//
//		share(ss, m, s0, s1, s2, prng);
//		share(c, 1, c0, c1, c2, prng);
//
//		auto f0 = std::async([&]() {
//			t0.apply(s0, c0, opCir, 0, AggTree::Suffix, com[0], g0, d0);
//			});
//		auto f1 = std::async([&]() {
//			t1.apply(s1, c1, opCir, 1, AggTree::Suffix, com[1], g1, d1);
//			});
//		auto f2 = std::async([&]() {
//			t2.apply(s2, c2, opCir, 2, AggTree::Suffix, com[2], g2, d2);
//			});
//
//		f0.get();
//		f1.get();
//		f2.get();
//
//		bool failed = false;
//		auto dd = reveal(d0, d1, d2);
//		for (u64 i = 0; i < n; ++i)
//		{
//			//auto ddi = dd(i);
//			//auto di = d[i];
//			auto act = BitVector((u8*)&dd(i, 0), m);
//
//			//std::cout << ddi << "  " << di << " " << c(i) << std::endl;
//			if (act != d[i])
//			{
//				failed = true;
//				//throw RTE_LOC;
//			}
//		}
//
//		if (failed)
//			throw RTE_LOC;
//
//	}
//}
//
//
//void AggTree_dup_suf_full_Test()
//{
//	auto opCir = [](
//		oc::BetaCircuit& cir,
//		const oc::BetaBundle& left,
//		const oc::BetaBundle& right,
//		oc::BetaBundle& out)
//	{
//		cir.addCopy(right, out);
//	};
//
//	auto op = [](
//		const oc::BitVector& left,
//		const oc::BitVector& right)
//	{
//		return right;
//	};
//
//	AggTree_suf_full_Test(op, opCir);
//}
//void AggTree_xor_suf_full_Test()
//{
//	auto opCir = [](
//		oc::BetaCircuit& cir,
//		const oc::BetaBundle& left,
//		const oc::BetaBundle& right,
//		oc::BetaBundle& out)
//	{
//		for (u64 i = 0; i < left.size(); ++i)
//			cir.addGate(left[i], right[i], oc::GateType::Xor, out[i]);
//	};
//
//	auto op = [](
//		const oc::BitVector& left,
//		const oc::BitVector& right)
//	{
//		return left ^ right;
//	};
//
//	AggTree_suf_full_Test(op, opCir);
//}
//
//
//void AggTree_xor_full_check_Test()
//{
//	auto opCir = [](
//		oc::BetaCircuit& cir,
//		const oc::BetaBundle& left,
//		const oc::BetaBundle& right,
//		oc::BetaBundle& out)
//	{
//		for (u64 i = 0; i < left.size(); ++i)
//			cir.addGate(left[i], right[i], oc::GateType::Xor, out[i]);
//	};
//
//	auto op = [](
//		const oc::BitVector& left,
//		const oc::BitVector& right)
//	{
//		return left ^ right;
//	};
//
//	TestComm com;
//	for (u64 n : {16, 23, 256, 24223})
//	{
//
//		u64 m = 101;
//
//		auto type = AggTree::Full;
//		std::array<Sh3ShareGen, 3> g;
//		g[0].init(block(0, 0), block(1, 1));
//		g[1].init(block(1, 1), block(2, 2));
//		g[2].init(block(2, 2), block(0, 0));
//
//		PTreeNew tree;
//		PRNG prng(ZeroBlock);
//		tree.init(n, m, prng, op);
//		AggTree t[3];
//		t[0].mDebug = true;
//		t[1].mDebug = true;
//		t[2].mDebug = true;
//
//		auto s = tree.shareVals(prng);
//		auto c = tree.shareBits(prng);
//		std::array<BinMatrix, 3> d;
//
//
//		std::array<std::future<void>, 3> f;
//		SplitLevel preSuf[3], vals[3];
//		std::array<Level, 3> roots;
//		std::array<std::vector<SplitLevel>, 3> upLevels, dnLevels;
//		for (u64 i = 0; i < 3; ++i)
//			f[i] = std::async([&, i]()
//				{
//					u64 bitCount = s[i].bitCount();
//					Level root;
//					std::vector<SplitLevel> levels(oc::log2ceil(n));
//
//					t[i].upstream(s[i], c[i], opCir, i, type, com[i], g[i], root, levels);
//					upLevels[i] = levels;
//					roots[i] = root;
//					t[i].downstream(s[i], c[i], opCir, root, levels, preSuf[i], vals[i], i, type, com[i], g[i]);
//					dnLevels[i] = levels;
//
//					d[i].resize(n, bitCount);
//
//					t[i].computeLeaf(vals[i], preSuf[i], opCir, d[i], i, type, com[i], g[i]);
//				});
//
//		f[0].get();
//		f[1].get();
//		f[2].get();
//
//
//		if (upLevels[0].size() != tree.logn)
//			throw RTE_LOC;
//
//		std::vector<PLevel> up(tree.logn);
//		for (u64 i = 0; i < up.size(); ++i)
//		{
//			up[i].load(upLevels[0][i], upLevels[1][i], upLevels[2][i]);
//		}
//		up.emplace_back();
//		up.back().load(roots[0], roots[1], roots[2]);
//
//		for (u64 j = 0; j < tree.mLevels.size(); ++j)
//		{
//			auto& exp = tree.mLevels[j].mUp;
//			for (u64 i = 0; i < exp.size(); ++i)
//			{
//				if (up[j].mSufVal[i] != exp.mSufVal[i])
//				{
//					std::cout << "\n i" << i << std::endl;
//					std::cout << "exp " << exp.mSufVal[i] << std::endl;
//					std::cout << "act " << up[j].mSufVal[i] << std::endl;
//					throw RTE_LOC;
//				}
//				if (up[j].mSufBit[i] != exp.mSufBit[i])
//					throw RTE_LOC;
//			}
//		}
//
//
//		std::vector<PLevel> dn(tree.logn);
//		for (u64 i = 0; i < dn.size(); ++i)
//		{
//			dn[i].load(dnLevels[0][i], dnLevels[1][i], dnLevels[2][i]);
//		}
//		dn.emplace_back();
//		dn.back().load(roots[0], roots[1], roots[2]);
//
//		for (u64 j = dn.size() - 2; j < dn.size(); --j)
//		{
//			auto& lvl = tree.mLevels[j];
//
//			for (u64 i = 0; i < lvl.mDown.size(); ++i)
//			{
//				auto act = dn[j].mSufVal[i];
//				auto exp = tree.mLevels[j].mDown.mSufVal[i];
//				if (exp != act)
//				{
//					std::cout << "\ni " << i << std::endl;
//					std::cout << "act " << act << std::endl;
//					std::cout << "exp " << exp << std::endl << std::endl;
//
//					auto p = i / 2;
//					auto l = i & 0;
//					auto r = i | 1;
//					std::cout << "pnt exp " << tree.mLevels[j + 1].mDown.mSufVal[p] << " " << tree.mLevels[j + 1].mDown.mSufBit[p] << "  " << p << std::endl;
//					std::cout << "    act " << dn[j + 1].mSufVal[p] << " " << dn[j + 1].mSufBit[p] << std::endl;
//					std::cout << "ch0 exp " << tree.mLevels[j].mDown.mSufVal[l] << " " << tree.mLevels[j].mDown.mSufBit[l] << "  " << l << (l == i ? " <- " : "") << std::endl;
//					std::cout << "    act " << dn[j].mSufVal[l] << " " << dn[j].mSufBit[l] << std::endl;
//					std::cout << "ch1 exp " << tree.mLevels[j].mDown.mSufVal[r] << " " << tree.mLevels[j].mDown.mSufBit[r] << "  " << r << (r == i ? " <- " : "") << std::endl;
//					std::cout << "    act " << dn[j].mSufVal[r] << " " << dn[j].mSufBit[r] << std::endl;
//
//
//					throw RTE_LOC;
//				}
//			}
//		}
//
//		PLevel pre; pre.load(preSuf[0], preSuf[1], preSuf[2]);
//		PLevel val; val.load(vals[0], vals[1], vals[2]);
//
//		for (u64 i = 0; i < n; ++i)
//		{
//			auto q = i < tree.n0 ? 0 : 1;
//			auto w = i < tree.n0 ? i : i - tree.r;
//
//			{
//				auto exp = tree.mLevels[q].mDown.mSufVal[w];
//				auto act = pre.mSufVal[i];
//				if (act != exp)
//				{
//					std::cout << "i   " << i << std::endl;
//					std::cout << "exp " << exp << std::endl;
//					std::cout << "act " << act << std::endl;
//					std::cout << "    " << (act ^ exp) << std::endl;
//
//					throw RTE_LOC;
//				}
//			}
//
//			{
//				auto exp = tree.mLevels[q].mUp.mSufVal[w];
//				auto act = val.mSufVal[i];
//				if (act != exp)
//				{
//					std::cout << "i   " << i << std::endl;
//					std::cout << "exp " << exp << std::endl;
//					std::cout << "act " << act << std::endl;
//					std::cout << "    " << (act ^ exp) << std::endl;
//
//					throw RTE_LOC;
//				}
//			}
//
//			{
//				//auto exp = tree.mLevels[q].mUp.mSufBit[w];
//				//auto act = val.mSufBit[i];
//				//auto exp2 = (i + 1 < tree.mCtrl.size()) ? (u8)tree.mCtrl[i+1] : 0;
//				//if (act != exp)
//				//{
//				//	std::cout << "i   " << i << std::endl;
//				//	std::cout << "exp " << exp << std::endl;
//				//	std::cout << "eee " << exp2 << std::endl;
//				//	std::cout << "act " << act << std::endl;
//				//	std::cout << "    " << (act ^ exp) << std::endl;
//
//				//	throw RTE_LOC;
//				//}
//			}
//		}
//
//
//		bool failed = false;
//		auto dd = reveal(d[0], d[1], d[2]);
//		for (u64 i = 0; i < n; ++i)
//		{
//			//auto ddi = dd(i);
//			//auto di = d[i];
//			auto act = BitVector((u8*)&dd(i, 0), m);
//
//			//std::cout << ddi << "  " << di << " " << c(i) << std::endl;
//			if (act != tree.mFull[i])
//			{
//				std::cout << i << " " << tree.r << " " << tree.n0 << "\n";
//				std::cout << "exp " << tree.mFull[i] << std::endl;
//				std::cout << "act " << act << std::endl;
//				failed = true;
//				//throw RTE_LOC;
//			}
//		}
//
//		if (failed)
//			throw RTE_LOC;
//	}
//}
//
//void AggTree_xor_full_full_Test()
//{
//	auto opCir = [](
//		oc::BetaCircuit& cir,
//		const oc::BetaBundle& left,
//		const oc::BetaBundle& right,
//		oc::BetaBundle& out)
//	{
//		for (u64 i = 0; i < left.size(); ++i)
//			cir.addGate(left[i], right[i], oc::GateType::Xor, out[i]);
//	};
//
//	auto op = [](
//		const oc::BitVector& left,
//		const oc::BitVector& right)
//	{
//		return left ^ right;
//	};
//
//	TestComm com;
//	for (u64 n : {16, 23, 256, 24223})
//	{
//
//		u64 m = 101;
//
//		Sh3Encryptor e0, e1, e2;
//		e0.init(0, block(0, 0), block(1, 1));
//		e1.init(1, block(1, 1), block(2, 2));
//		e2.init(2, block(2, 2), block(0, 0));
//		auto& g0 = e0.mShareGen;
//		auto& g1 = e1.mShareGen;
//		auto& g2 = e2.mShareGen;
//
//		PTreeNew tree;
//		PRNG prng(ZeroBlock);
//		tree.init(n, m, prng, op);
//		AggTree t0, t1, t2;
//
//		auto s = tree.shareVals(prng);
//		auto c = tree.shareBits(prng);
//		std::array<BinMatrix, 3> d;
//
//		auto f0 = std::async([&]() {
//
//			t0.apply(s[0], c[0], opCir, 0, AggTree::Full, com[0], g0, d[0]);
//			});
//		auto f1 = std::async([&]() {
//			t1.apply(s[1], c[1], opCir, 1, AggTree::Full, com[1], g1, d[1]);
//			});
//		auto f2 = std::async([&]() {
//			t2.apply(s[2], c[2], opCir, 2, AggTree::Full, com[2], g2, d[2]);
//			});
//
//		f0.get();
//		f1.get();
//		f2.get();
//
//		bool failed = false;
//		auto dd = reveal(d[0], d[1], d[2]);
//		for (u64 i = 0; i < n; ++i)
//		{
//			//auto ddi = dd(i);
//			//auto di = d[i];
//			auto act = BitVector((u8*)&dd(i, 0), m);
//
//			//std::cout << ddi << "  " << di << " " << c(i) << std::endl;
//			if (act != tree.mFull[i])
//			{
//				std::cout << i << " " << tree.r << " " << tree.n0 << "\n";
//				std::cout << "exp " << tree.mFull[i] << std::endl;
//				std::cout << "act " << act << std::endl;
//				failed = true;
//				//throw RTE_LOC;
//			}
//		}
//
//		if (failed)
//			throw RTE_LOC;
//	}
//
//}
