#pragma once
#include "secure-join/LowMCPerm.h"
#include "GMW/Gmw.h"

namespace secJoin
{

    class SharePerm
    {

        private:
            u64 mPartyIdx;
            Perm mPerm;
            // std::vector<u64> mPerm;

        public:

		SharePerm() = default;

		//initializing the permutation
		// SharePerm(Perm perm) : mPerm(std::move(perm)) {}
		SharePerm(Perm perm, u8 partyIdx) : mPartyIdx(partyIdx), mPerm(std::move(perm)) {}


        macoro::task<> apply(
            oc::Matrix<u8>& in,
            oc::Matrix<u8>& out,
            coproto::Socket& chl,
            OleGenerator& ole
            )
        {

            MC_BEGIN(macoro::task<>, &in, &out, &chl,&ole,
                gmw0 = std::move(Gmw()),
                gmw1 = std::move(Gmw()),
                invPerm = bool(false),
                prng = oc::PRNG(oc::block(0,0)),
                this,
                soutperm = oc::Matrix<u8>{}
            );

            if(mPartyIdx == 0)
            {   
                MC_AWAIT(LowMCPerm::applyVec(in, prng, gmw0, chl, soutperm, ole));
                MC_AWAIT(LowMCPerm::applyVecPerm(soutperm, mPerm.mPerm, prng, gmw1, chl, out, invPerm,ole));
            }
            else
            {

                MC_AWAIT(LowMCPerm::applyVecPerm(in, mPerm.mPerm, prng, gmw0, chl, soutperm, invPerm,ole));
                MC_AWAIT(LowMCPerm::applyVec(soutperm, prng, gmw1, chl, out, ole));
            }

            MC_END();
        }
    };

}