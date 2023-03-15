#include "SharePerm_Test.h"
using namespace secJoin;
#include "util.h"

void SharePerm_replicated_perm_test()
{


    u64 n = 5;    // total number of rows
    u64 rowSize = 1;

    oc::Matrix<u8> x(n, rowSize);
    
    oc::PRNG prng(oc::block(0,0));

    auto chls = coproto::LocalAsyncSocket::makePair();

    // Initializing the vector x & permutation pi
    for(u64 i =0; i < n; ++i)
    { 
        prng.get((u8*) &x[i][0], x[i].size());
    }


    std::array<oc::Matrix<u8>, 2> sout;
    std::array<oc::Matrix<u8>, 2> xShares = share(x,prng);

    Perm p0(n, prng);
    Perm p1(n, prng);
    Perm pi = p0.compose(p1);
    oc::Matrix<u8> t(n, rowSize),yExp(n, rowSize), yAct(n, rowSize);

    SharePerm perm1(p0, 0); 
    SharePerm perm2(p1, 1);

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

        auto proto0 = perm1.apply(xShares[0], sout[0], invPerm, chls[0]);
        auto proto1 = perm2.apply(xShares[1], sout[1], invPerm, chls[1]);

        auto res = macoro::sync_wait(macoro::when_all_ready(std::move(proto0), std::move(proto1)));
        std::get<0>(res).result();
        std::get<1>(res).result();

        yAct = reconstruct_from_shares(sout[0], sout[1]);
        if(eq(yAct,yExp) == false)
            throw RTE_LOC;
    }

}

