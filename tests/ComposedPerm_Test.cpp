#include "ComposedPerm_Test.h"
using namespace secJoin;
#include "util.h"

void ComposedPerm_replicated_perm_test()
{


    u64 n = 5;    // total number of rows
    u64 rowSize = 1;

    oc::Matrix<u8> x(n, rowSize);
    
    oc::PRNG prng(oc::block(0,0));


    auto chls = coproto::LocalAsyncSocket::makePair();
    OleGenerator ole0, ole1;
    ole0.fakeInit(OleGenerator::Role::Sender);
    ole1.fakeInit(OleGenerator::Role::Receiver);
    // std::vector<u64> pi0(n), pi1(n);
    prng.get(x.data(), x.size());


    std::array<oc::Matrix<u8>, 2> sout;
    std::array<oc::Matrix<u8>, 2> xShares = share(x,prng);

    Perm p0(n, prng);
    Perm p1(n, prng);
    Perm pi = p0.compose(p1);
    oc::Matrix<u8> t(n, rowSize),yExp(n, rowSize), yAct(n, rowSize);

    ComposedPerm perm1(p0, 0); 
    ComposedPerm perm2(p1, 1);

    for(auto invPerm :  {false, true})
    {
    
        if(invPerm)
        {
            p1.apply<u8>(x, t, invPerm);
            p0.apply<u8>(t, yAct, invPerm);
        }
        else
        {
            p0.apply<u8>(x, t, invPerm);
            p1.apply<u8>(t, yAct, invPerm);
        }

        pi.apply<u8>(x, yExp, invPerm);
        if(eq(yAct,yExp) == false)
            throw RTE_LOC;

        sout[0].resize(n, rowSize);
        sout[1].resize(n, rowSize);

        auto proto0 = perm1.apply<u8>(xShares[0], sout[0], chls[0], ole0, invPerm);
        auto proto1 = perm2.apply<u8>(xShares[1], sout[1], chls[1], ole1, invPerm);

        auto res = macoro::sync_wait(macoro::when_all_ready(std::move(proto0), std::move(proto1)));
        std::get<0>(res).result();
        std::get<1>(res).result();

        yAct = reveal(sout[0], sout[1]);
        if(eq(yAct,yExp) == false)
            throw RTE_LOC;
    }

}

