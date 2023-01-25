#include "secure-join/LowMCPerm.h"
// #include "LowMCPerm_Test.h"

using namespace secJoin;

void LowMCPerm_basic_test()
{
    // User input
    u64 rowSize = 5;
    u64 n = 100;    // total number of rows

    Matrix<u8> x(n, rowSize);
    

    LowMCPerm m1, m2;
    oc::PRNG prng(oc::block(0,0));

    auto chls = coproto::LocalAsyncSocket::makePair();

    std::vector<u64> pi(n);


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

    if(sout[0].rows() != n)
    throw RTE_LOC;
    if(sout[1].rows() != n)
    throw RTE_LOC;
    if(sout[0].cols() != rowSize)
    throw RTE_LOC;
    if(sout[1].cols() != rowSize)
    throw RTE_LOC;

    // Checking if everything works
    for (u64 i = 0; i < n; ++i)
    {
        
        for(u64 j=0; j < x.cols(); j++)
        {
            auto act = sout[0](i,j) ^ sout[1](i,j);
            if ( act != x(pi[i],j))
            {
                throw RTE_LOC;
            }

        }
    }


}