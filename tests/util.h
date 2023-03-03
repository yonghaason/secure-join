#pragma once
#include "cryptoTools/Common/Matrix.h"
#include "cryptoTools/Crypto/PRNG.h"
#include "secure-join/Defines.h"
#include <vector>

inline void check_inv_results(
    oc::Matrix<oc::u8>& x,
    std::array<oc::Matrix<oc::u8>, 2>& sout)
{
    // Checking the dimensions
    if (sout[0].rows() != x.rows())
        throw RTE_LOC;
    if (sout[1].rows() != x.rows())
        throw RTE_LOC;
    if (sout[0].cols() != x.cols())
        throw RTE_LOC;
    if (sout[1].cols() != x.cols())
        throw RTE_LOC;


    // Checking if everything works
    for (oc::u64 i = 0; i < x.rows(); ++i)
    {

        for (oc::u64 j = 0; j < x.cols(); j++)
        {
            auto act = x(i, j);
            auto cur = sout[0](i, j) ^ sout[1](i, j);
            if (act != cur)
            {
                std::cout << "Unit Test Failed" << std::endl;
                throw RTE_LOC;
            }

        }
    }

}

inline void check_results(
    oc::Matrix<oc::u8>& x,
    std::array<oc::Matrix<oc::u8>, 2>& sout,
    std::vector<oc::u64>& pi,
    bool invPerm)
{
    // Checking the dimensions
    if (sout[0].rows() != x.rows())
        throw RTE_LOC;
    if (sout[1].rows() != x.rows())
        throw RTE_LOC;
    if (sout[0].cols() != x.cols())
        throw RTE_LOC;
    if (sout[1].cols() != x.cols())
        throw RTE_LOC;


    // Checking if everything works
    for (oc::u64 i = 0; i < x.rows(); ++i)
    {

        for (oc::u64 j = 0; j < x.cols(); j++)
        {
            oc::u8 act, cur, cur0, cur1;
            if (invPerm)
            {
                act = x(pi[i], j);
                cur0 = sout[0](i, j);
                cur1 = sout[1](i, j);
            }
            else
            {
                act = x(i, j);
                cur0 = sout[0](pi[i], j);
                cur1 = sout[1](pi[i], j);
            }

            cur = cur0 ^ cur1;

            if (act != cur)
            {
                //std::cout << "Unit Test Failed " << std::endl;

                //std::cout << std::hex << std::setw(2) << std::setfill('0') << int(act) << std::endl;
                //std::cout << std::hex << std::setw(2) << std::setfill('0') << int(cur) << std::endl;
                //std::cout << std::hex << std::setw(2) << std::setfill('0') << int(cur0) << std::endl;
                //std::cout << std::hex << std::setw(2) << std::setfill('0') << int(cur1) << std::endl;
                throw RTE_LOC;
            }

        }

    }
}


inline void check_results(
    oc::Matrix<oc::u8>& x,
    std::array<oc::Matrix<oc::u8>, 2>& sout,
    std::vector<oc::u64>& pi0,
    std::vector<oc::u64>& pi1
)
{
    // Checking the dimensions
    if (sout[0].rows() != x.rows())
        throw RTE_LOC;
    if (sout[1].rows() != x.rows())
        throw RTE_LOC;
    if (sout[0].cols() != x.cols())
        throw RTE_LOC;
    if (sout[1].cols() != x.cols())
        throw RTE_LOC;


    // Checking if everything works
    for (oc::u64 i = 0; i < x.rows(); ++i)
    {

        for (oc::u64 j = 0; j < x.cols(); j++)
        {
            auto act = sout[0](pi0[pi1[i]], j) ^ sout[1](pi0[pi1[i]], j);
            if (act != x(i, j))
            {
                std::cout << "Unit Test Failed" << std::endl;
                throw RTE_LOC;
            }

        }
    }
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

inline oc::Matrix<oc::u8> reconstruct_from_shares(
    oc::Matrix<oc::u8> v1,
    oc::Matrix<oc::u8> v2)
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