#include "VectorPerm_Test.h"


using namespace secJoin;

void VectorPerm_basic_test()
{
    // User input
    u64 n = 5;    // total number of rows
    u64 rowSize = 1;

    std::vector<u64> s(n);

    // ---- s should be vector<u64>
    std::array<oc::Matrix<u8>,2> xPerm;
    
    oc::Matrix<u8> stemp(n, rowSize), x(n,rowSize);
    oc::PRNG prng(oc::block(0,0));
    auto chls = coproto::LocalAsyncSocket::makePair();


    // Creating permutation s
    for(u8 i =0; i < n; ++i)
    { 
        prng.get((u8*) &x[i][0], x[i].size());
        // x[i][0] = (u8)10+i;

        // std::cout<<"/////  " << *(u8*)&x[i][0] << std::endl;

        s[i] = (i) % n;
        // s[i] = (i+1) % n;
    }


    // Secret Sharing s
    std::array<std::vector<u64>, 2> sShares = share(s,prng);

    Perm mPerm(n, prng);
    

    VectorPerm vecPerm1(sShares[0], prng, 0),
        vecPerm2(sShares[1], prng, 1);

    auto proto0 = vecPerm1.setup(chls[0]);
    auto proto1 = vecPerm2.setup(chls[1]);

    auto res = macoro::sync_wait(macoro::when_all_ready(std::move(proto0), std::move(proto1)));

    try{
        std::get<0>(res).result();
    }
    catch(std::exception &ex)
    {
        std::cout << ex.what() << std::endl;
        std::get<1>(res).result();

        throw ex;
    }
    std::get<1>(res).result();


    // Secret Sharing x
    std::array<oc::Matrix<u8>, 2> xShares = share(x,prng);



    proto0 = vecPerm1.main( xShares[0], xPerm[0], prng, chls[0]);
    proto1 = vecPerm2.main( xShares[1], xPerm[1], prng, chls[1]);

    auto res1 = macoro::sync_wait(macoro::when_all_ready(std::move(proto0), std::move(proto1)));

    std::get<0>(res1).result();
    std::get<1>(res1).result();


    bool invPerm = false;
    
    // oc::Matrix<oc::u8> xPermCom = reconstruct_from_shares(xPerm[0], xPerm[1]);

    check_results(x, xPerm, s, invPerm);
}
