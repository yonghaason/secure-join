#pragma once
#include "cryptoTools/Common/Matrix.h"
#include "cryptoTools/Crypto/PRNG.h"
#include "Defines.h"
#include <vector>
#include "Perm/AdditivePerm.h"

using namespace secJoin;
using oc::Matrix;
using oc::PRNG;

inline void share(const Matrix<u32>& x, Matrix<u32>& x0, Matrix<u32>& x1, PRNG& prng)
{
    x0.resize(x.rows(), x.cols());
    x1.resize(x.rows(), x.cols());
    prng.get(x0.data(), x0.size());

    for (u64 i = 0; i < x.size(); ++i)
        x1(i) = x(i) - x0(i);
}

inline void share(const span<u32> x, std::vector<u32>& x0, std::vector<u32>& x1, PRNG& prng)
{
    x0.resize(x.size());
    x1.resize(x.size());
    prng.get(x0.data(), x0.size());
    for (u64 i = 0; i < x.size(); ++i)
        x1[i] = x[i] - x0[i];
}


inline void share(const Matrix<u8>& x, u64 bitCount, Matrix<u8>& x0, Matrix<u8>& x1, PRNG& prng)
{
    if (x.cols() != oc::divCeil(bitCount, 8))
        throw RTE_LOC;

    x0.resize(x.rows(), x.cols());
    x1.resize(x.rows(), x.cols());
    prng.get(x0.data(), x0.size());
    for (u64 i = 0; i < x.size(); ++i)
        x1(i) = x(i) ^ x0(i);

    if (bitCount % 8)
    {
        auto mask = (1 << (bitCount % 8)) - 1;
        for (u64 i = 0; i < x.rows(); ++i)
        {
            x0[i].back() &= mask;
            x1[i].back() &= mask;
        }
    }
}

inline void share(const Matrix<u8>& x, Matrix<u8>& x0, Matrix<u8>& x1, PRNG& prng)
{
    share(x, x.cols() * 8, x0, x1, prng);
}
inline Perm reveal(const AdditivePerm& x0, const AdditivePerm& x1)
{
    if (x0.mRho != x1.mRho)
        throw RTE_LOC;
    Perm p(x0.size());

    {
        for (u64 i = 0; i < p.size(); ++i)
            p.mPerm[i] = x0.mShare[i] ^ x1.mShare[i];
    }
    //else
    //{
    //    for (u64 i = 0; i < p.size(); ++i)
    //        p.mPerm[i] = x0.mShare[i] + x1.mShare[i];
    //}

    //p.validate();
    return p;
}

inline Matrix<u32> reveal(const Matrix<u32>& x0, const Matrix<u32>& x1)
{
    Matrix<u32> r(x0.rows(), x0.cols());
    for (u64 i = 0; i < r.size(); ++i)
        r(i) = x0(i) + x1(i);
    return r;
}


inline std::array<oc::Matrix<oc::u8>, 2> share(
    oc::Matrix<oc::u8> v,
    oc::PRNG& prng)
{
    auto n = v.rows();
    oc::Matrix<oc::u8>
        s0(n, v.cols()),
        s1(n, v.cols());

    prng.get(s0.data(), s0.size());

    for (oc::u64 i = 0; i < v.size(); ++i)
        s1(i) = v(i) ^ s0(i);

    return { s0, s1 };
}



inline std::array<oc::Matrix<oc::u32>, 2> share(
    oc::Matrix<oc::u32> v,
    oc::PRNG& prng)
{
    auto n = v.rows();
    oc::Matrix<oc::u32>
        s0(n, v.cols()),
        s1(n, v.cols());

    prng.get(s0.data(), s0.size());

    for (oc::u64 i = 0; i < v.size(); ++i)
        s1(i) = v(i) - s0(i);

    return { s0, s1 };
}

inline std::array<std::vector<u32>, 2> xorShare(
    span<const u32> v,
    oc::PRNG& prng)
{
    auto n = v.size();
    std::vector<u32>
        s0(n),
        s1(n);

    prng.get(s0.data(), s0.size());
    prng.get((u8*) s0.data(), n * sizeof(u32));

    for (oc::u64 i = 0; i < v.size(); ++i)
        s1[i] = v[i] ^ s0[i];

    return { s0, s1 };
}

inline oc::Matrix<oc::u8> reveal(
    const oc::Matrix<oc::u8>& v1,
    const oc::Matrix<oc::u8>& v2)
{

    // Checking the dimensions
    if (v1.rows() != v2.rows())
        throw RTE_LOC;
    if (v1.cols() != v2.cols())
        throw RTE_LOC;

    oc::Matrix<oc::u8> s(v1.rows(), v1.cols());


    for (oc::u64 i = 0; i < v1.size(); ++i)
        s(i) = v1(i) ^ v2(i);

    return s;
}


inline bool eq(
    const oc::Matrix<oc::u8>& v1,
    const oc::Matrix<oc::u8>& v2)
{
    // Checking the dimensions
    if (v1.rows() != v2.rows())
        throw RTE_LOC;
    if (v1.cols() != v2.cols())
        throw RTE_LOC;

    return std::equal(v1.begin(), v1.end(), v2.begin());
}
inline bool eq(
    const oc::Matrix<oc::u32>& v1,
    const oc::Matrix<oc::u32>& v2)
{
    // Checking the dimensions
    if (v1.rows() != v2.rows())
        throw RTE_LOC;
    if (v1.cols() != v2.cols())
        throw RTE_LOC;

    return std::equal(v1.begin(), v1.end(), v2.begin());
}

inline void printMatrix(const oc::Matrix<oc::u8>& v1)
{
    for(int i = 0; i < v1.rows(); i++)
    {
        std::cout << hex(v1[i]) << " ";
        std::cout << std::endl;
    }
}