#include "LowMCPerm_Test.h"

using namespace secJoin;

void LowMCPerm_perm_test()
{
    // User input
    u64 n = 10;    // total number of rows
    u64 rowSize = 5;    

    Matrix<u8> x(n, rowSize), x2Perm(n,rowSize);
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


    Gmw gmw0, gmw1;
    std::array<Matrix<u8>, 2> sout;

    auto proto0 = m1.applyVec(x, prng, gmw0, chls[0], sout[0]);
    auto proto1 = m2.applyPerm(pi, prng, n, rowSize, gmw1, chls[1], sout[1], invPerm);

    auto res = macoro::sync_wait(macoro::when_all_ready(std::move(proto0), std::move(proto1)));

    std::get<0>(res).result();
    std::get<1>(res).result();

    check_results(x, sout, pi, invPerm);

}

void LowMCPerm_inv_perm_test()
{

    // User input
    u64 n = 10;    // total number of rows
    u64 rowSize = 5;    

    Matrix<u8> x(n, rowSize), x2Perm(n,rowSize);
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
    std::array<Matrix<u8>, 2> soutPerm, soutInv;

    auto proto0 = m1.applyVec(x, prng, gmw0, chls[0], soutPerm[0]);
    auto proto1 = m2.applyPerm(pi, prng, n, rowSize, gmw1, chls[1], soutPerm[1], invPerm);

    auto res = macoro::sync_wait(macoro::when_all_ready(std::move(proto0), std::move(proto1)));

    std::get<0>(res).result();
    std::get<1>(res).result();

    Matrix<u8> recon_sout = reconstruct_from_shares( soutPerm[0], soutPerm[1]);

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
    u64 n = 10;    // total number of rows
    u64 rowSize = 5;    

    Matrix<u8> x(n, rowSize), x2Perm(n,rowSize);
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

    std::array<Matrix<u8>, 2> xShares = share(x,prng);

    Gmw gmw0, gmw1;
    std::array<Matrix<u8>, 2> soutPerm, soutInv;

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
    u64 n = 10;    // total number of rows
    u64 rowSize = 5;
    

    Matrix<u8> x(n, rowSize), x2Perm(n,rowSize);
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


    std::array<Matrix<u8>, 2> xShares = share(x,prng);

    Gmw gmw0, gmw1;
    std::array<Matrix<u8>, 2> sout;

    auto proto0 = m1.applyVec(xShares[0], prng, gmw0, chls[0], sout[0]);
    auto proto1 = m2.applyVecPerm(xShares[1], pi, prng, gmw1, chls[1], sout[1], invPerm);

    auto res = macoro::sync_wait(macoro::when_all_ready(std::move(proto0), std::move(proto1)));

    std::get<0>(res).result();
    std::get<1>(res).result();
    

    check_results(x, sout, pi, invPerm);

}

void check_inv_results(
    Matrix<u8> &x,
    std::array<Matrix<u8>, 2> &sout)
{
    // Checking the dimensions
    if(sout[0].rows() != x.rows())
        throw RTE_LOC;
    if(sout[1].rows() != x.rows())
        throw RTE_LOC;
    if(sout[0].cols() != x.cols())
        throw RTE_LOC;
    if(sout[1].cols() != x.cols())
        throw RTE_LOC;
 

    // Checking if everything works
    for (u64 i = 0; i < x.rows(); ++i)
    {
        
        for(u64 j=0; j < x.cols(); j++)
        {
            auto act = x(i,j);
            auto cur = sout[0](i,j) ^ sout[1](i,j);
            if ( act != cur)
            {
                std::cout << "Unit Test Failed" << std::endl;
                throw RTE_LOC;
            }

        }
    }

}

void check_results(
    Matrix<u8> &x,
    std::array<Matrix<u8>, 2> &sout, 
    std::vector<u64> &pi,
    bool invPerm)
{
    // Checking the dimensions
    if(sout[0].rows() != x.rows())
        throw RTE_LOC;
    if(sout[1].rows() != x.rows())
        throw RTE_LOC;
    if(sout[0].cols() != x.cols())
        throw RTE_LOC;
    if(sout[1].cols() != x.cols())
        throw RTE_LOC;
 

    // Checking if everything works
    for (u64 i = 0; i < x.rows(); ++i)
    {
        
        for(u64 j=0; j < x.cols(); j++)
        {
            u8 act, cur;
            if(invPerm)
            {
                act = x(pi[i],j);
                cur = sout[0](i,j) ^ sout[1](i,j);
            }
            else
            {
                act = x(i,j);
                cur = sout[0](pi[i],j) ^ sout[1](pi[i],j);
            }


            if ( act != cur)
            {
                std::cout << "Unit Test Failed" << std::endl;
                throw RTE_LOC;
            }

        }
    }


}

std::array<Matrix<u8>, 2> share(
    Matrix<u8> v, 
    PRNG& prng)
{
    auto n = v.rows();
    Matrix<u8>
        s0(n, v.cols()),
        s1(n, v.cols());

    prng.get(s0.data(), s0.size());

    for (u64 i = 0; i < v.size(); ++i)
        s1(i) = v(i) ^ s0(i);

    return { s0, s1 };
}

Matrix<u8> reconstruct_from_shares(
    Matrix<u8> v1, 
    Matrix<u8> v2)
{

    // Checking the dimensions
    if(v1.rows() != v2.rows())
        throw RTE_LOC;
    if(v1.cols() != v2.cols())
        throw RTE_LOC;

    Matrix<u8> s(v1.rows(), v1.cols());


    for (u64 i = 0; i < v1.size(); ++i)
        s(i) = v1(i) ^ v2(i);

    return s;
}