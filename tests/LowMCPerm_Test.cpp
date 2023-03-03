#include "LowMCPerm_Test.h"
#include "util.h"
using namespace secJoin;

void LowMCPerm_perm_test(const oc::CLP& cmd)
{
    // User input
    u64 n = 10;    // total number of rows
    u64 rowSize = cmd.getOr("m",63);      

    oc::Matrix<u8> x(n, rowSize), x2Perm(n,rowSize);
    bool invPerm = false;

    LowMCPerm m1, m2;
    oc::PRNG prng0(oc::block(0, 0));
    oc::PRNG prng1(oc::block(0, 1));

    auto chls = coproto::LocalAsyncSocket::makePair();

    std::vector<u64> pi(n);

    // Initializing the vector x & permutation pi
    for(u64 i =0; i < n; ++i)
    { 
        // std::cout << "The size of x[i] is " << x[i].size() << std::endl;
        // std::cout << "The size of offset * sizeof(LowMC2<>::block) is " << offset * sizeof(LowMC2<>::block) << std::endl;
        oc::PRNG prng(oc::block(0, i));
        prng.get((u8*) &x[i][0], x[i].size());
        /*std::fi*/
        pi[i] = (i+5) % n;
    }


    Gmw gmw0, gmw1;
    std::array<oc::Matrix<u8>, 2> sout;

    auto proto0 = m1.applyVec(x, prng0, gmw0, chls[0], sout[0]);
    auto proto1 = m2.applyPerm(pi, prng1, n, rowSize, gmw1, chls[1], sout[1], invPerm);

    auto res = macoro::sync_wait(macoro::when_all_ready(std::move(proto0), std::move(proto1)));

    std::get<0>(res).result();
    std::get<1>(res).result();

    check_results(x, sout, pi, invPerm);

}

void LowMCPerm_inv_perm_test()
{

    // User input
    u64 n = 10;    // total number of rows
    u64 rowSize = 40;    

    oc::Matrix<u8> x(n, rowSize), x2Perm(n,rowSize);
    bool invPerm = false;

    LowMCPerm m1, m2;
    oc::PRNG prng(oc::block(0,0));

    auto chls = coproto::LocalAsyncSocket::makePair();

    std::vector<u64> pi(n);

    // Initializing the vector x & permutation pi
    for(u64 i =0; i < n; ++i)
    { 
        prng.get((u8*) &x[i][0], x[i].size());
        pi[i] = (i+1) % n;
    }


    Gmw gmw0, gmw1;
    std::array<oc::Matrix<u8>, 2> soutPerm, soutInv;

    auto proto0 = m1.applyVec(x, prng, gmw0, chls[0], soutPerm[0]);
    auto proto1 = m2.applyPerm(pi, prng, n, rowSize, gmw1, chls[1], soutPerm[1], invPerm);

    auto res = macoro::sync_wait(macoro::when_all_ready(std::move(proto0), std::move(proto1)));

    std::get<0>(res).result();
    std::get<1>(res).result();

    oc::Matrix<u8> recon_sout = reconstruct_from_shares( soutPerm[0], soutPerm[1]);

    proto0 = m1.applyVec(recon_sout, prng, gmw0, chls[0], soutInv[0]);
    proto1 = m2.applyPerm(pi, prng, n, rowSize, gmw1, chls[1], soutInv[1], !invPerm);

    auto res1 = macoro::sync_wait(macoro::when_all_ready(std::move(proto0), std::move(proto1)));

    std::get<0>(res1).result();
    std::get<1>(res1).result();

    check_inv_results(x, soutInv);
}


void LowMCPerm_secret_shared_input_inv_perm_test()
{

    // User input
    u64 n = 453;    // total number of rows
    u64 rowSize = 54;    

    oc::Matrix<u8> x(n, rowSize), x2Perm(n,rowSize);
    bool invPerm = false;

    LowMCPerm m1, m2;
    oc::PRNG prng(oc::block(0,0));

    auto chls = coproto::LocalAsyncSocket::makePair();

    std::vector<u64> pi(n);

    // Initializing the vector x & permutation pi
    for(u64 i =0; i < n; ++i)
    { 
        prng.get((u8*) &x[i][0], x[i].size());
        pi[i] = (i+1) % n;
    }

    std::array<oc::Matrix<u8>, 2> xShares = share(x,prng);

    Gmw gmw0, gmw1;
    std::array<oc::Matrix<u8>, 2> soutPerm, soutInv;

    auto proto0 = m1.applyVec(xShares[0], prng, gmw0, chls[0], soutPerm[0]);
    auto proto1 = m2.applyVecPerm(xShares[1],pi, prng, gmw1, chls[1], soutPerm[1], invPerm);

    auto res = macoro::sync_wait(macoro::when_all_ready(std::move(proto0), std::move(proto1)));

    std::get<0>(res).result();
    std::get<1>(res).result();

    

    proto0 = m1.applyVec(soutPerm[0], prng, gmw0, chls[0], soutInv[0]);
    proto1 = m2.applyVecPerm(soutPerm[1], pi, prng, gmw1, chls[1], soutInv[1], !invPerm);

    auto res1 = macoro::sync_wait(macoro::when_all_ready(std::move(proto0), std::move(proto1)));

    std::get<0>(res1).result();
    std::get<1>(res1).result();

    check_inv_results(x, soutInv);
}

void LowMCPerm_secret_shared_input_perm_test()
{
    // User input
    u64 n = 1454;    // total number of rows
    u64 rowSize = 66;
    

    oc::Matrix<u8> x(n, rowSize), x2Perm(n,rowSize);
    bool invPerm = false;

    LowMCPerm m1, m2;
    oc::PRNG prng(oc::block(0,0));

    auto chls = coproto::LocalAsyncSocket::makePair();

    std::vector<u64> pi(n);

    // Initializing the vector x & permutation pi
    for(u64 i =0; i < n; ++i)
    { 
        // std::cout << "The size of x[i] is " << x[i].size() << std::endl;
        // std::cout << "The size of offset * sizeof(LowMC2<>::block) is " << offset * sizeof(LowMC2<>::block) << std::endl;
        prng.get((u8*) &x[i][0], x[i].size());

        pi[i] = (i+1) % n;
    }


    std::array<oc::Matrix<u8>, 2> xShares = share(x,prng);

    Gmw gmw0, gmw1;
    std::array<oc::Matrix<u8>, 2> sout;

    auto proto0 = m1.applyVec(xShares[0], prng, gmw0, chls[0], sout[0]);
    auto proto1 = m2.applyVecPerm(xShares[1], pi, prng, gmw1, chls[1], sout[1], invPerm);

    auto res = macoro::sync_wait(macoro::when_all_ready(std::move(proto0), std::move(proto1)));

    std::get<0>(res).result();
    std::get<1>(res).result();
    

    check_results(x, sout, pi, invPerm);

}
