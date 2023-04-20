#include "ComposedPerm_Test.h"
using namespace secJoin;
#include "util.h"

void ComposedPerm_replicated_perm_test()
{


    u64 n = 10;    // total number of rows
    u64 rowSize = 5;

    oc::Matrix<u8> x(n, rowSize);
    
    oc::PRNG prng(oc::block(0,0));


    auto chls = coproto::LocalAsyncSocket::makePair();
    OleGenerator ole0, ole1;
    ole0.fakeInit(OleGenerator::Role::Sender);
    ole1.fakeInit(OleGenerator::Role::Receiver);
    // std::vector<u64> pi0(n), pi1(n);
    std::array<Perm, 2> pi;
    
    
    pi[0].mPerm.resize(n);
    pi[1].mPerm.resize(n);

    // Initializing the vector x & permutation pi
    for(u64 i =0; i < n; ++i)
    { 
        prng.get((u8*) &x[i][0], x[i].size());

        pi[0].mPerm[i] = (i+2) % n;
        pi[1].mPerm[i] = (i+1) % n;
    }


    std::array<oc::Matrix<u8>, 2> sout;
    std::array<oc::Matrix<u8>, 2> xShares = share(x,prng);

    Perm p0(pi[0]);
    Perm p1(pi[1]);

    ComposedPerm perm1(p0, 0); 
    ComposedPerm perm2(p1, 1);

    auto proto0 = perm1.apply(xShares[0], sout[0], chls[0], ole0);
    auto proto1 = perm2.apply(xShares[1], sout[1], chls[1], ole1);

    auto res = macoro::sync_wait(macoro::when_all_ready(std::move(proto0), std::move(proto1)));
    std::get<0>(res).result();
    std::get<1>(res).result();

    check_results(x,sout,pi[0], pi[1]);

}

