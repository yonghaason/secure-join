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
    u64 n = 1000;
    LowMCPerm m1, m2;
    oc::PRNG prng(oc::block(0,0));

    auto chls = coproto::LocalAsyncSocket::makePair();

    std::vector<u64> pi(n);
    std::vector<LowMC2<>::block> x(n);

    for(u64 i =0; i < n; ++i)
    {
        // x[i] = prng0.get<u64>() % n;
        x[i] = i;
        pi[i] = (i+1) % n;
    }

    Gmw gmw0,gmw1;

    auto proto0 = m1.applyVec(x, prng,n,gmw0,chls[0]);
    auto proto1 = m2.applyPerm(pi, prng,n, gmw1,chls[1]);

    auto res = macoro::sync_wait(macoro::when_all_ready(std::move(proto0), std::move(proto1)));

    auto p0 = gmw0.run(chls[0]);
    auto p1 = gmw1.run(chls[1]);
    eval(p0, p1);

    std::array<Matrix<u8>, 2> sout;
    sout[0].resize(n, sizeof(LowMC2<>::block));
    sout[1].resize(n, sizeof(LowMC2<>::block));

    // Both party receives the secret shared values
    gmw0.getOutput(0, sout[0]);
    gmw1.getOutput(0, sout[1]);

    // Getting the actual values from the secret shared data
    auto out = reconstruct<LowMC2<>::block>(sout);

    
    // Checking if the everything works
    for (u64 i = 0; i < n; ++i)
    {
        if (out[i] != x[pi[i]] )
        {
            throw RTE_LOC;
        }
    }

}