#pragma once
#include "secure-join/Defines.h"
#include <vector>
#include "ComposedPerm.h"
#include "Permutation.h"
#include "cryptoTools/Common/Timer.h"

namespace secJoin
{

    class AdditivePerm : public oc::TimerAdapter
    {
    public:
        std::vector<u32> mShare;
        ComposedPerm mPi;
        Perm mRho;
        bool mIsSetup = false;

        bool isSetup() const { return mIsSetup; }

        AdditivePerm() = default;

        AdditivePerm(span<u32> shares, PRNG& prng, u8 partyIdx) :
            mPi(shares.size(), partyIdx, prng)
        {
            mShare.resize(shares.size());
            std::copy(shares.begin(), shares.end(), (u32*)mShare.data());
        }

        void init(u64 size)
        {
            mShare.resize(size);
            mPi.mPerm.mPerm.resize(size);
            mRho.mPerm.resize(size);
            mIsSetup = false;
        }

        void setupDlpnSender(oc::block& key, std::vector<oc::block>& rk)
        {
            mPi.setupDlpnSender(key, rk);
        }

        void setupDlpnReceiver(std::vector<std::array<oc::block, 2>>& sk)
        {
            mPi.setupDlpnReceiver(sk);
        }

        macoro::task<> setupDlpnSender(OleGenerator& ole)
        {
            MC_BEGIN(macoro::task<>, this, &ole);
            MC_AWAIT(mPi.setupDlpnSender(ole));
            MC_END();
        }

        macoro::task<> setupDlpnReceiver(OleGenerator& ole)
        {
            MC_BEGIN(macoro::task<>, this, &ole);
            MC_AWAIT(mPi.setupDlpnReceiver(ole));
            MC_END();
        }


        // generate the masking (replicated) permutation mPi
        // and then reveal mRhoPP = mPi(mShares).
        //
        // We can then apply our main permutation (mShares)
        // or an input vector x by computing
        //
        // t = mRho(x)
        // y = mPi^-1(t)
        //
        // mRho is public and mPi is replicated so we
        // have protocols for both.
        //
        macoro::task<> setup(
            coproto::Socket& chl,
            OleGenerator& ole,
            PRNG& prng
        )
        {
            MC_BEGIN(macoro::task<>, this, &chl, &ole, &prng,
                rho1 = oc::Matrix<u32>{},
                rho2 = oc::Matrix<u32>{},
                ss = std::vector<u32>{},
                i = u64{}
            );

            mPi.init(mShare.size(), (int)ole.mRole, prng);

            // rho1 will resized() and initialed in the apply function
            rho1.resize(mShare.size(), 1);
            MC_AWAIT(mPi.apply<u32>(
                oc::MatrixView<u32>(mShare.data(), mShare.size(), 1),
                rho1, chl, ole, false));

            // Exchanging the [Rho]
            if (mPi.mPartyIdx == 0)
            {
                // First party first sends the [rho] and then receives it
                MC_AWAIT(chl.send(rho1));

                rho2.resize(rho1.rows(), rho1.cols());
                MC_AWAIT(chl.recv(rho2));
            }
            else
            {
                // Second party first receives the [rho] and then sends it
                rho2.resize(rho1.rows(), rho1.cols());
                MC_AWAIT(chl.recv(rho2));

                MC_AWAIT(chl.send(rho1));
            }

            // Constructing Rho
            if (mShare.size() != rho2.rows())
                throw RTE_LOC;

            if (mShare.size() != rho1.rows())
                throw RTE_LOC;

            mRho.mPerm.resize(rho1.rows());

            // std::cout << "Rho1 Rows " << rho1.rows() << std::endl;
            // std::cout << "Rho1 Cols " << rho1.cols() << std::endl;

            // std::cout << "Size of one row is " << sizeof(*(u32*)rho1(0)) << std::endl;
            // std::cout << "Value of zero row is " << *(u32*)rho1.data(0) << std::endl;

            {
                for (i = 0; i < rho1.rows(); ++i)
                {
                    mRho.mPerm[i] = *(u32*)rho1.data(i) ^ *(u32*)rho2.data(i);
//#ifndef NDEBUG
//                    if (mRho[i] >= size())
//                    {
//                        ss.resize(mShare.size());
//                        MC_AWAIT(chl.send(coproto::copy(mShare)));
//                        MC_AWAIT(chl.recv(ss));
//
//
//                        for (u64 j = 0; j < size(); ++j)
//                        {
//                            if ((ss[j] ^ mShare[j]) > size())
//                                throw RTE_LOC;
//                        }
//                    }
//#endif

                    assert(mRho[i] < size());
                }
            }

            mIsSetup = true;

            MC_END();
        }

        u64 size() const { return mShare.size(); }


        template<typename T>
        macoro::task<> apply(
            oc::span<const T> in,
            oc::span<T> out,
            oc::PRNG& prng,
            coproto::Socket& chl,
            OleGenerator& ole,
            bool inv = false)
        {
            return apply<T>(
                oc::MatrixView<const T>(in.data(), in.size(), 1),
                oc::MatrixView<T>(out.data(), out.size(), 1),
                prng, chl, ole, inv
                );
        }

        template<typename T>
        macoro::task<> apply(
            oc::MatrixView<const T> in,
            oc::MatrixView<T> out,
            oc::PRNG& prng,
            coproto::Socket& chl,
            OleGenerator& ole,
            bool inv = false)
        {
            if (out.rows() != in.rows())
                throw RTE_LOC;
            if (out.cols() != in.cols())
                throw RTE_LOC;
            if (out.rows() != size())
                throw RTE_LOC;

            MC_BEGIN(macoro::task<>, this, in, out, &prng, &chl, &ole, inv,
                temp = oc::Matrix<T>{},
                soutInv = oc::Matrix<T>{}
            );

            if (isSetup() == false)
                MC_AWAIT(setup(chl, ole, prng));

            if (inv)
            {
                temp.resize(in.rows(), in.cols());
                MC_AWAIT(mPi.apply<T>(in, temp, chl, ole, false));
                mRho.apply<T>(temp, out, true);
            }
            else
            {
                // Local Permutation of [x]
                temp.resize(in.rows(), in.cols());
                mRho.apply<T>(in, temp);
                MC_AWAIT(mPi.apply<T>(temp, out, chl, ole, true));
            }

            MC_END();
        }


        macoro::task<> compose(
            AdditivePerm& pi,
            AdditivePerm& dst,
            oc::PRNG& prng,
            coproto::Socket& chl,
            OleGenerator& gen)
        {
            if (pi.size() != size())
                throw RTE_LOC;
            //dst.init(p2.size(), p2.mPi.mPartyIdx, gen);
            dst.init(size());
            return pi.apply<u32>(mShare, dst.mShare, prng, chl, gen);
        }

    };
}