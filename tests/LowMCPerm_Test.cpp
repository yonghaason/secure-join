#include "secure-join/LowMCPerm.h"
// #include "LowMCPerm_Test.h"

using namespace secJoin;

template <typename T>
std::vector<T> reconstruct(std::array<Matrix<u8>, 2> shares)
{
    // std::cout << "The size of T is " << sizeof(T) << std::endl;
    if (shares[0].cols() != sizeof(T))
        throw RTE_LOC;
    if (shares[1].cols() != sizeof(T))
        throw RTE_LOC;
    if (shares[0].rows() != shares[1].rows())
        throw RTE_LOC;

    std::vector<T> ret(shares[0].rows());
    oc::MatrixView<u8> v((u8*)ret.data(), ret.size(), sizeof(T));

    for (u64 i = 0; i < v.size(); ++i)
        v(i) = shares[0](i) ^ shares[1](i);

    return ret;
}

void LowMCPerm_basic_test()
{
    // User input
    u64 bitPerRow = 500;
    u64 n = 2;    // total number of rows

    Matrix<u8> x(n, oc::divCeil(bitPerRow,8.0));
    

    u64 offset = oc::divCeil (  bitPerRow , (sizeof(LowMC2<>::block) * 8.0)); 
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

    auto proto0 = m1.applyVec(x, prng, n, offset, gmw0, chls[0], sout[0]);
    auto proto1 = m2.applyPerm(pi, prng, n, offset, gmw1, chls[1], sout[1]);

    auto res = macoro::sync_wait(macoro::when_all_ready(std::move(proto0), std::move(proto1)));

    // Getting the actual values from the secret shared data

    sout[0].resize((n * offset * sizeof(LowMC2<>::block))/ sizeof(u8), sizeof(u8)); 
    sout[1].resize((n * offset * sizeof(LowMC2<>::block))/ sizeof(u8), sizeof(u8)); 
    auto out = reconstruct<u8>(sout);

    
    // Checking if everything works
    for (u64 i = 0; i < n; ++i)
    {
        
        for(u64 j=0; j < offset; j++)
        {
            if ( out[i] != (*(u8*) &x(pi[i],j)) )
            {
                throw RTE_LOC;
            }

        }
    }


}