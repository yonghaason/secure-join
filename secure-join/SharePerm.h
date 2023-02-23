#pragma once
#include "secure-join/LowMCPerm.h"
#include "GMW/Gmw.h"

namespace secJoin
{

    class SharePerm
    {

        private:
            int mPartyIdx;
            //  Perm mPerm;
            std::vector<u64> mPerm;

        public:

		SharePerm() = default;

		//initializing the permutation
		// SharePerm(Perm perm) : mPerm(std::move(perm)) {}
		SharePerm(std::vector<u64> perm, u8 partyIdx) : mPartyIdx(partyIdx), mPerm(std::move(perm)) {}


        macoro::task<> apply(
            Matrix<u8>& in,
            Matrix<u8>& out,
            coproto::Socket& chl
            )
        {

            MC_BEGIN(macoro::task<>, &in, &out, &chl,
            gmw0 = Gmw(),
            gmw1 = Gmw(),
            invPerm = bool(false),
            prng = oc::PRNG(oc::block(0,0)),
            this,
            soutperm = Matrix<u8>{}
            );

            if(mPartyIdx == 0)
            {   
                MC_AWAIT(LowMCPerm::applyVec(in, prng, in.rows(), in.cols(), gmw0, chl, soutperm));
                MC_AWAIT(LowMCPerm::applyVecPerm(soutperm, mPerm, prng, soutperm.rows(),
                    soutperm.cols(), gmw1, chl, out, invPerm));
            }
            else
            {

                MC_AWAIT(LowMCPerm::applyVecPerm(in, mPerm, prng, in.rows(), in.cols(), gmw0, chl, soutperm, invPerm));
                MC_AWAIT(LowMCPerm::applyVec(soutperm, prng, soutperm.rows(), 
                    soutperm.cols(), gmw1, chl, out));
            }

            MC_END();
        }
    };

}