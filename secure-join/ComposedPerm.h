#pragma once
#include "secure-join/LowMCPerm.h"
#include "GMW/Gmw.h"

namespace secJoin
{
    // A shared permutation where P0 holds pi_0 and P1 holds pi_1
    // such that the combined permutation is pi = pi_1 o pi_0.
    class ComposedPerm
    {
    public:
        u64 mPartyIdx;
        Perm mPerm;

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


        u64 size() const
        {
            return mPerm.size();
        }

        void init(u64 n, u8 partyIdx, PRNG& prng)
        {
            mPartyIdx = partyIdx;
            mPerm.randomize(n, prng);
        }

        macoro::task<> apply(
            oc::Matrix<u8>& in,
            oc::Matrix<u8>& out,
            coproto::Socket& chl,
            OleGenerator& ole,
            bool inv = false
        )
        {

            MC_BEGIN(macoro::task<>, &in, &out, &chl, &ole, inv,
                gmw0 = std::move(Gmw()),
                gmw1 = std::move(Gmw()),
                prng = oc::PRNG(ole.mPrng.get()),
                this,
                soutperm = oc::Matrix<u8>{}
            );

            if (mPartyIdx == 0)
            {
                MC_AWAIT(LowMCPerm::applyVec(in, prng, gmw0, chl, soutperm, ole));
                MC_AWAIT(LowMCPerm::applyVecPerm(soutperm, mPerm, prng, gmw1, chl, out, inv, ole));
            }
            else
            {

                MC_AWAIT(LowMCPerm::applyVecPerm(in, mPerm, prng, gmw0, chl, soutperm, inv, ole));
                MC_AWAIT(LowMCPerm::applyVec(soutperm, prng, gmw1, chl, out, ole));
            }

            MC_END();
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