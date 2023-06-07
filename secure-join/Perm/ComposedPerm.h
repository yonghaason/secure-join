#pragma once
#include "secure-join/Perm/LowMCPerm.h"
#include "secure-join/Perm/InsecurePerm.h"
#include "secure-join/GMW/Gmw.h"
#include "secure-join/Perm/DLpnPerm.h"

namespace secJoin
{
    // A shared permutation where P0 holds pi_0 and P1 holds pi_1
    // such that the combined permutation is pi = pi_1 o pi_0.
    class ComposedPerm
    {
    public:
        u64 mPartyIdx=-1;
        Perm mPerm;
        DLpnPerm dlpnPerm;
        bool isSecure = true;

        ComposedPerm() = default;

        //initializing the permutation
        ComposedPerm(Perm perm, u8 partyIdx)
            : mPartyIdx(partyIdx)
            , mPerm(std::move(perm))
        {}
        ComposedPerm(u64 n, u8 partyIdx, PRNG& prng)
            : mPartyIdx(partyIdx)
            , mPerm(n, prng)
        {}

        // ComposedPerm(u64 n, u8 partyIdx, PRNG& prng, DLpnPrfSender& sender, DLpnPrfReceiver& recver, DLpnPrf& dm)
        //     : mPartyIdx(partyIdx)
        //     , mPerm(n, prng)
        // {
        //     this->sender = sender;
        //     this.recver = recver;
        //     this.dm = dm;
        // }

        void setupDlpnSender(oc::block& key, std::vector<oc::block>& rk)
        {
            dlpnPerm.setupDlpnSender(key, rk);
        }

        void setupDlpnReceiver(std::vector<std::array<oc::block, 2>>& sk)
        {
            dlpnPerm.setupDlpnReceiver(sk);
        }

        inline macoro::task<> setupDlpnSender(OleGenerator& ole)
        {

            MC_BEGIN(macoro::task<>, this, &ole);
            MC_AWAIT(dlpnPerm.setupDlpnSender(ole));
            MC_END();
        }

        inline macoro::task<> setupDlpnReceiver(OleGenerator& ole)
        {

            MC_BEGIN(macoro::task<>, this, &ole);
            MC_AWAIT(dlpnPerm.setupDlpnReceiver(ole));
            MC_END();
        }

        u64 size() const
        {
            return mPerm.size();
        }

        void init(u64 n, u8 partyIdx, PRNG& prng)
        {
            mPartyIdx = partyIdx;
            mPerm.randomize(n, prng);
        }

        template<typename T>
        macoro::task<> apply(
            oc::MatrixView<const T> in,
            oc::MatrixView<T> out,
            coproto::Socket& chl,
            OleGenerator& ole,
            bool inv = false)
        {
            if (out.rows() != in.rows() ||
                out.cols() != in.cols())
                throw RTE_LOC;

            if (out.rows() != mPerm.size())
                throw RTE_LOC;

            if (mPartyIdx > 1)
                throw RTE_LOC;

            MC_BEGIN(macoro::task<>, in, out, &chl, &ole, inv,
                prng = oc::PRNG(ole.mPrng.get()),
                this,
                soutperm = oc::Matrix<T>{}
            );

            soutperm.resize(in.rows(), in.cols());
            if ((inv ^ bool(mPartyIdx)) == true)
            {
                MC_AWAIT(InsecurePerm::apply<T>(in, soutperm, prng, chl, ole));
                MC_AWAIT(InsecurePerm::apply<T>(mPerm, soutperm, out, prng, chl, inv, ole));
                //MC_AWAIT(LowMCPerm::apply<T>(in, soutperm, prng, chl, ole));
                //MC_AWAIT(LowMCPerm::apply<T>(mPerm, soutperm, out, prng, chl, inv, ole));
            }
            else
            {
                MC_AWAIT(InsecurePerm::apply<T>(mPerm, in, soutperm, prng, chl, inv, ole));
                MC_AWAIT(InsecurePerm::apply<T>(soutperm, out, prng, chl, ole));

                //MC_AWAIT(LowMCPerm::apply<T>(mPerm, in, soutperm, prng, chl, inv, ole));
                //MC_AWAIT(LowMCPerm::apply<T>(soutperm, out, prng, chl, ole));
            }

            MC_END();
        }

        template<typename T>
        macoro::task<> apply(
            oc::MatrixView<T> in,
            oc::MatrixView<T> out,
            coproto::Socket& chl,
            OleGenerator& ole,
            int something,
            bool inv = false)
        {
            if (out.rows() != in.rows() ||
                out.cols() != in.cols())
                throw RTE_LOC;

            if (out.rows() != mPerm.size())
                throw RTE_LOC;

            if (mPartyIdx > 1)
                throw RTE_LOC;

            MC_BEGIN(macoro::task<>, &in, &out, &chl, &ole, inv,
                prng = oc::PRNG(ole.mPrng.get()),
                this,
                soutperm = oc::Matrix<u8>{}
            );

            soutperm.resize(in.rows(), in.cols());
            if ((inv ^ bool(mPartyIdx)) == true)
            {
                //MC_AWAIT(LowMCPerm::apply<T>(in, soutperm, prng, chl, ole));
                //MC_AWAIT(LowMCPerm::apply<T>(mPerm, soutperm, out, prng, chl, inv, ole));

                if(isSecure)
                {
                    MC_AWAIT(dlpnPerm.apply(prng, chl, ole, in.rows(), in.cols(), in, soutperm));
                    MC_AWAIT(dlpnPerm.apply(mPerm, in.cols(), prng, chl, ole, soutperm, out, inv));
                }
                else
                {
                    // MC_AWAIT(InsecurePerm::apply<T>(in, soutperm, prng, chl, ole));
                    // MC_AWAIT(InsecurePerm::apply<T>(mPerm, soutperm, out, prng, chl, inv, ole));
                }

            }
            else
            {
                //MC_AWAIT(LowMCPerm::apply<T>(mPerm, in, soutperm, prng, chl, inv, ole));
                //MC_AWAIT(LowMCPerm::apply<T>(soutperm, out, prng, chl, ole));

                if(isSecure)
                {
                    MC_AWAIT(dlpnPerm.apply(mPerm, in.cols(), prng, chl, ole, in, soutperm, inv));
                    MC_AWAIT(dlpnPerm.apply(prng, chl, ole, in.rows(), in.cols(), soutperm, out));
                }
                else
                {
                    // MC_AWAIT(InsecurePerm::apply<T>(mPerm, in, soutperm, prng, chl, inv, ole));
                    // MC_AWAIT(InsecurePerm::apply<T>(soutperm, out, prng, chl, ole));
                }


            }

            MC_END();
        }


        void printMatrix(oc::Matrix<u8>& matrix)
        {

            for(int i = 0; i < matrix.rows() ; i++)
            {
                std::cout << hex(matrix[i]) << std::endl;   
            }
        }


        macoro::task<> compose(
            const ComposedPerm& in,
            ComposedPerm& out,
            coproto::Socket& chl,
            OleGenerator& ole)
        {
            throw RTE_LOC;
        }
    };

}