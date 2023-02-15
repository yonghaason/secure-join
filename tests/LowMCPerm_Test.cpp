#include "LowMCPerm_Test.h"

using namespace secJoin;

void LowMCPerm_basic_test()
{
    // User input
    u64 n = 10;    // total number of rows
    u64 rowSize = 5;    

    Matrix<u8> x(n, rowSize), x2Perm(n,rowSize);
    

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

    auto proto0 = m1.applyVec(x, prng, n, rowSize, gmw0, chls[0], sout[0]);
    auto proto1 = m2.applyPerm(pi, prng, n, rowSize, gmw1, chls[1], sout[1]);

    auto res = macoro::sync_wait(macoro::when_all_ready(std::move(proto0), std::move(proto1)));

    std::get<0>(res).result();
    std::get<1>(res).result();

    checkResults(x,sout,pi);

}

void LowMCPerm_secret_shared_input_test()
{
    // User input
    u64 n = 10;    // total number of rows
    u64 rowSize = 5;
    

    Matrix<u8> x(n, rowSize), x2Perm(n,rowSize);
    

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

    auto proto0 = m1.applyVec(xShares[0], prng, n, rowSize, gmw0, chls[0], sout[0]);
    auto proto1 = m2.applyVecPerm(xShares[1], pi, prng, n, rowSize, gmw1, chls[1], sout[1]);

    auto res = macoro::sync_wait(macoro::when_all_ready(std::move(proto0), std::move(proto1)));

    std::get<0>(res).result();
    std::get<1>(res).result();
    

    checkResults(x,sout,pi);

}



void LowMCPerm_replicated_perm_test()
{
        // User input
    u64 n = 10;    // total number of rows
    u64 rowSize = 5;
    

    Matrix<u8> x(n, rowSize), x2Perm(n,rowSize);
    

    LowMCPerm m0, m1;
    oc::PRNG prng(oc::block(0,0));

    auto chls = coproto::LocalAsyncSocket::makePair();

    std::vector<u64> pi0(n), pi1(n);

    // Initializing the vector x & permutation pi
    for(u64 i =0; i < n; ++i)
    { 
        // std::cout << "The size of x[i] is " << x[i].size() << std::endl;
        // std::cout << "The size of offset * sizeof(LowMC2<>::block) is " << offset * sizeof(LowMC2<>::block) << std::endl;
        prng.get((u8*) &x[i][0], x[i].size());

        pi0[i] = (i+2) % n;
        pi1[i] = (i+1) % n;
    }


    std::array<Matrix<u8>, 2> xShares = share(x,prng);

    Gmw gmw00, gmw01, gmw10, gmw11;
    std::array<Matrix<u8>, 2> soutperm0, soutperm1;

    auto proto0 = m0.applyVec(xShares[0], prng, n, rowSize, gmw00, chls[0], soutperm0[0]);
    auto proto1 = m1.applyVecPerm(xShares[1], pi1, prng, n, rowSize, gmw01, chls[1], soutperm0[1]);

    auto res0 = macoro::sync_wait(macoro::when_all_ready(std::move(proto0), std::move(proto1)));

    std::get<0>(res0).result();
    std::get<1>(res0).result();

    
    proto0 = m0.applyVecPerm(soutperm0[0], pi0, prng, n, rowSize, gmw10, chls[0], soutperm1[0]);
    proto1 = m1.applyVec(soutperm0[1], prng, n, rowSize, gmw11, chls[1], soutperm1[1]);

    auto res1 = macoro::sync_wait(macoro::when_all_ready(std::move(proto1), std::move(proto0)));

    std::get<0>(res1).result();
    std::get<1>(res1).result();

    
    checkResults(x,soutperm1,pi0, pi1);
}

void checkResults(
    Matrix<u8> &x,
    std::array<Matrix<u8>, 2> &sout, 
    std::vector<u64> &pi0,
    std::vector<u64> &pi1
    )
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
            auto act = sout[0](i,j) ^ sout[1](i,j);
            if ( act != x( pi0[ pi1[i] ],j))
            {
                std::cout << "Unit Test Failed" << std::endl;
                throw RTE_LOC;
            }

        }
    }


}


void checkResults(
    Matrix<u8> &x,
    std::array<Matrix<u8>, 2> &sout, 
    std::vector<u64> &pi)
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
            auto act = sout[0](i,j) ^ sout[1](i,j);
            if ( act != x(pi[i],j))
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