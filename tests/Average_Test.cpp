#include "Average_Test.h"


using namespace secJoin;

void Average_concatColumns_Test()
{
    u64 n0 = 234;
    Table t0;
    t0.mColumns.emplace_back("c0", TypeID::IntID, 11);
    t0.mColumns.emplace_back("c1", TypeID::IntID, 31);
    t0.mColumns.emplace_back("c2", TypeID::IntID, 5);
    t0.resize(n0);

    // Average avg;

    PRNG prng(oc::ZeroBlock);
    for (u64 i = 0; i < t0.mColumns.size(); ++i)
    {
        prng.get(t0[i].mCol.mData.data(), t0[i].mCol.mData.size());
        t0[i].mCol.mData.trim();
    }
    BinMatrix y;
    std::vector<OmJoin::Offset> offsets;

    std::vector<ColRef> averageCols;
    averageCols.emplace_back(t0[0]);
    averageCols.emplace_back(t0[1]);
    averageCols.emplace_back(t0[2]);


    OleGenerator ole;
    ole.fakeInit(OleGenerator::Role::Receiver);
     
    Average::concatColumns( t0[0], averageCols, y, offsets, ole);
    BinMatrix ones(n0, sizeof(oc::u64) * 8);
    for(oc::u64 i = 0; i < n0; i++)
            ones(i,0) = 1;


    for (u64 i = 0; i < n0; ++i)
    {
        auto iter = oc::BitIterator(y.mData[i].data());
        
        for (u64 j = 0; j < t0.mColumns.size(); ++j)
        {
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


        auto expIter = oc::BitIterator(ones.mData[i].data());

        for (u64 k = 0; k < ones.mBitCount; ++k)
        {
            u8 exp = *expIter++;
            u8 act = *iter++;
            if (exp != act)
                throw RTE_LOC;
        }
    }

    
}



void Average_getControlBits_Test()
{
    u64 n = 342;
    u64 keyBitCount = 21;

    auto sock = coproto::LocalAsyncSocket::makePair();

    BinMatrix keys(n, keyBitCount), kk[2], cc[2];
    PRNG prng(oc::ZeroBlock);
    prng.get(keys.data(), keys.size());

    std::vector<u8> exp(n);
    for (u64 i = 1; i < n; ++i)
    {
        exp[i] = prng.getBit();
        if (exp[i])
        {
            memcpy(keys.data(i), keys.data(i - 1), keys.cols());
        }
    }

    share(keys, kk[0], kk[1], prng);

    OleGenerator ole0, ole1;
    ole0.fakeInit(OleGenerator::Role::Sender);
    ole1.fakeInit(OleGenerator::Role::Receiver);

    auto r = macoro::sync_wait(macoro::when_all_ready(
        Average::getControlBits( kk[0], sock[0] ,cc[0], ole0),
        Average::getControlBits( kk[1], sock[1] ,cc[1], ole1)));

    std::get<0>(r).result();
    std::get<1>(r).result();

    auto c = reveal(cc[0], cc[1]);

    if (c.mData(0))
        throw RTE_LOC;
    for (u64 i = 1; i < n; ++i)
    {
        auto act = c(i);
        if (exp[i] != act)
            throw RTE_LOC;
    }
}

void Average_avg_Test(const oc::CLP& cmd)
{
    u64 nTb = 333;
    Table tb, tbShare;

    bool printSteps = cmd.isSet("print");
    // bool mock = !cmd.isSet("noMock");
    bool mock = true;

    tb.init(nTb, { {
        {"L1", TypeID::IntID, 12},
        {"L2", TypeID::IntID, 16},
        {"L3", TypeID::IntID, 16}
    } });

    tbShare.init(nTb, { {
        {"L1", TypeID::IntID, 12},
        {"L2", TypeID::IntID, 16},
        {"L3", TypeID::IntID, 16}
    } });

    for (u64 i = 0; i < nTb; ++i)
    {
        tb.mColumns[0].mData.mData(i, 0) = i % 5 ;
        tb.mColumns[1].mData.mData(i, 0) = i % 4;
        tb.mColumns[1].mData.mData(i, 1) = i % 4;
        tb.mColumns[2].mData.mData(i, 0) = i % 4;
        tb.mColumns[2].mData.mData(i, 1) = i % 4;
    }

    Average avg1, avg2;

    avg1.mInsecurePrint = printSteps;
    avg2.mInsecurePrint = printSteps;

    avg1.mInsecureMockSubroutines = mock;
    avg2.mInsecureMockSubroutines = mock;

    OleGenerator ole0, ole1;
    ole0.fakeInit(OleGenerator::Role::Sender);
    ole1.fakeInit(OleGenerator::Role::Receiver);

    PRNG prng0(oc::ZeroBlock);
    PRNG prng1(oc::OneBlock);
    auto sock = coproto::LocalAsyncSocket::makePair();

    Table out[2];

    auto r = macoro::sync_wait(macoro::when_all_ready(
        avg1.avg(tb[0], { tb[1], tb[2] }, out[0], prng0, ole0, sock[0]),
        avg2.avg(tbShare[0], { tbShare[1], tbShare[2] }, out[1], prng1, ole1, sock[1])
    ));
    std::get<1>(r).result();
    std::get<0>(r).result();

    auto res = reveal(out[0], out[1]);
    
    auto exp = average(tb[0], { tb[1], tb[2] });

    if (res != exp)
    {
        std::cout << "exp \n" << exp << std::endl;
        std::cout << "act \n" << res << std::endl;
        std::cout << "ful \n" << reveal(out[0], out[1], false) << std::endl;
        throw RTE_LOC;
    }
}