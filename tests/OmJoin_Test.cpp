

#include "OmJoin_Test.h"
#include "secure-join/Join/OmJoin.h"

using namespace secJoin;

void OmJoin_loadKeys_Test()
{

    u64 n0 = 321;
    u64 n1 = 423;
    u64 m = 17;
    Table leftTable, rightTable;
    leftTable.mColumns.emplace_back("name", TypeID::IntID, m);
    rightTable.mColumns.emplace_back("name", TypeID::IntID, m);

    leftTable.mColumns[0].mData.resize(n0, m);
    rightTable.mColumns[0].mData.resize(n1, m);

    auto& ld = leftTable.mColumns[0].mData;
    auto& rd = rightTable.mColumns[0].mData;

    PRNG prng(oc::ZeroBlock);
    prng.get(ld.data(), ld.size());
    prng.get(rd.data(), rd.size());
    ld.trim();
    rd.trim();

    ColRef left(leftTable, leftTable.mColumns[0]);
    ColRef right(rightTable, rightTable.mColumns[0]);

    auto res = OmJoin::loadKeys(left, right);

    for (u64 i = 0; i < n0; ++i)
    {
        if (memcmp(res[i].data(), ld[i].data(), ld.bytesPerEntry()))
            throw RTE_LOC;
    }
    for (u64 i = 0; i < n1; ++i)
    {
        if (memcmp(res[i + n0].data(), rd[i].data(), rd.bytesPerEntry()))
            throw RTE_LOC;
    }
}

void OmJoin_getControlBits_Test()
{
    u64 n = 342;
    u64 m = 31;
    u64 offset = 32;

    auto sock = coproto::LocalAsyncSocket::makePair();

    BinMatrix k(n, m + offset), kk[2], cc[2];
    PRNG prng(oc::ZeroBlock);
    prng.get(k.data(), k.size());
    k.trim();

    share(k, kk[0], kk[1], prng);

    OleGenerator ole0, ole1;
    ole0.fakeInit(OleGenerator::Role::Sender);
    ole1.fakeInit(OleGenerator::Role::Receiver);

    auto r = macoro::sync_wait(macoro::when_all_ready(
        OmJoin::getControlBits(kk[0], offset, sock[0], cc[0], ole0),
        OmJoin::getControlBits(kk[1], offset, sock[1], cc[1], ole1)));

    std::get<0>(r).result();
    std::get<1>(r).result();

    auto c = reveal(cc[0], cc[1]);

    if (c.mData(0))
        throw RTE_LOC;
    for (u64 i = 1; i < n; ++i)
    {
        auto exp = memcmp(k[i - 1].data() + offset / 8, k[i].data() + offset / 8, k.bytesPerEntry() - offset / 8) == 0;
        auto act = c(i);

        if (exp != act)
            throw RTE_LOC;
    }
}

void OmJoin_concatColumns_Test()
{
    u64 n0 = 234;
    u64 n1 = 333;
    Table t0, t1;
    u64 m = 13;
    BinMatrix keys(n0 + n1, m);
    t0.mColumns.emplace_back("c0", TypeID::IntID, 11);
    t0.mColumns.emplace_back("c1", TypeID::IntID, 31);
    t0.mColumns.emplace_back("c2", TypeID::IntID, 1);
    t1.mColumns.emplace_back("r0", TypeID::IntID, 11);
    t1.mColumns.emplace_back("r1", TypeID::IntID, 31);
    t1.mColumns.emplace_back("r2", TypeID::IntID, 1);

    t0.resize(n0);
    t1.resize(n1);

    PRNG prng(oc::ZeroBlock);
    for (u64 i = 0; i < t0.mColumns.size(); ++i)
    {
        prng.get(t0[i].mCol.mData.data(), t0[i].mCol.mData.size());
        t0[i].mCol.mData.trim();
    }
    prng.get(keys.data(), keys.size());
    keys.trim();

    std::vector<ColRef> select;
    select.emplace_back(t0[0]);
    select.emplace_back(t0[1]);
    select.emplace_back(t0[2]);
    select.emplace_back(t1[0]);
    select.emplace_back(t1[1]);
    select.emplace_back(t1[2]);

    BinMatrix y;
    u64 offset;
    OmJoin::concatColumns(t0[0], select, n1, keys, offset, y);

    for (u64 i = 0; i < n0; ++i)
    {
        // std::cout << "y" << i << " " << hex(y[i]) << " ~ " << std::flush;
        auto iter = oc::BitIterator(y.mData[i].data());
        for (u64 j = 0; j < t0.mColumns.size(); ++j)
        {
            // std::cout << hex(t0[j].mCol.mData[i]) << " " << std::flush;
            auto expIter = oc::BitIterator(t0[j].mCol.mData[i].data());
            for (u64 k = 0; k < t0[j].mCol.getBitCount(); ++k)
            {
                u8 exp = *expIter++;
                u8 act = *iter++;
                if (exp != act)
                    throw RTE_LOC;
            }

            auto rem = t0[j].mCol.getBitCount() % 8;
            if (rem)
            {
                iter = iter + (8 - rem);
            }
        }
        auto expIter = oc::BitIterator(keys.mData[i].data());
        for (u64 k = 0; k < keys.bitsPerEntry(); ++k)
        {
            u8 exp = *expIter++;
            u8 act = *iter++;
            if (exp != act)
                throw RTE_LOC;
        }

        auto rem = keys.bitsPerEntry() % 8;
        if (rem)
        {
            iter = iter + (8 - rem);
        }
        // std::cout << std::endl;
    }
}

void OmJoin_getOutput_Test()
{

    u64 nL = 234;
    u64 nR = 125;
    u64 mL = 3, mR = 1;


    Table L, R;
    L.init(nL + nR, { {
        ColumnInfo{"l1", TypeID::IntID, 33},
        ColumnInfo{"l2", TypeID::IntID, 1},
        ColumnInfo{"l3", TypeID::IntID, 5}
        } });
    R.init(nR, { {
            ColumnInfo{"r1", TypeID::IntID, 8},
        } }
    );

    PRNG prng(oc::ZeroBlock);
    for (u64 i = 0; i < mL; ++i)
        prng.get(L.mColumns[i].data(), L.mColumns[i].size());

    for (u64 i = 0; i < mR; ++i)
        prng.get(R.mColumns[i].data(), R.mColumns[i].size());

    u64 bitCount =
        oc::roundUpTo(L[0].mCol.getBitCount(), 8) +
        oc::roundUpTo(L[1].mCol.getBitCount(), 8) +
        oc::roundUpTo(L[2].mCol.getBitCount(), 8) + 8;
    BinMatrix data(nL + nR, bitCount);

    BinMatrix isActive(nL + nR, 1);
    prng.get(isActive.data(), isActive.size());
    isActive.trim();

    std::vector<BinMatrix*> cat{ &L.mColumns[0].mData,&L.mColumns[1].mData,&L.mColumns[2].mData, &isActive };
    OmJoin::concatColumns(data, cat);

    Table LL = L;
    for (u64 i = 0; i < LL.mColumns.size(); ++i)
        LL.mColumns[i].mData.resize(nL, LL.mColumns[i].mBitCount);

    std::vector<ColRef> select{ LL[0], LL[1], LL[2], R[0] };

    Table out;
    OmJoin::getOutput(data, select, select[0], out);


    for (u64 i = 0; i < mR; ++i)
    {
        for (u64 j = 0; j < select.size(); ++j)
        {
            auto exp = &select[j].mTable == &LL ?
                L.mColumns[j].mData.mData[i + nL] :
                R.mColumns[0].mData[i];

            auto act = out.mColumns[j].mData.mData[i];
            if (exp.size() != act.size())
                throw RTE_LOC;
            if (memcmp(exp.data(), act.data(), act.size()))
            {
                std::cout << "exp " << hex(exp) << std::endl;
                std::cout << "act " << hex(act) << std::endl;
                throw RTE_LOC;
            }
        }

        if (out.mIsActive[i] != isActive(nL + i))
            throw RTE_LOC;
    }
}