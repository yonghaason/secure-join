#include "OleGenerator_Test.h"
#include "secure-join/OleGenerator.h"

void OleGenerator_Basic_Test()
{
    using namespace secJoin;

    OleGenerator g0, g1;
    macoro::thread_pool tp;
    auto chl = coproto::LocalAsyncSocket::makePair();

    u64 totalSize = 1ull << 26;
    u64 reservoirSize = 1ull << 22;
    u64 numConcurrent = 4;
    u64 chunkSize = 1ull << 18;

    oc::PRNG prng(oc::CCBlock);
    auto work = tp.make_work();
    tp.create_threads(6);

    g0.init(OleGenerator::Role::Sender, tp, chl[0], prng, totalSize, reservoirSize, numConcurrent, chunkSize);
    g1.init(OleGenerator::Role::Receiver, tp, chl[1], prng, totalSize, reservoirSize, numConcurrent, chunkSize);

    u64 s = 0;
    while (s < totalSize)
    {

        SharedTriple t0, t1;
        auto n = prng.get<u64>() % chunkSize;

        auto r = macoro::sync_wait(macoro::when_all_ready(
            g0.get(t0, n),
            g1.get(t1, n)
        ));

        for (u64 i = 0; i < t0.mAdd.size(); ++i)
        {
            if ((t0.mAdd[i] ^ t1.mAdd[i]) != (t0.mMult[i] & t1.mMult[i]))
                throw RTE_LOC;
        }

        s += t0.size();
    }

    macoro::sync_wait(macoro::when_all_ready(
        g0.stop(),
        g1.stop()
    ));
}
