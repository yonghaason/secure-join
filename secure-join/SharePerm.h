#pragma once
#include "secure-join/LowMCPerm.h"
#include "GMW/Gmw.h"

namespace secJoin
{

    class SharePerm
    {

        public:

        u64 mPartyIdx;
        Perm mPerm;


		SharePerm() = default;

		//initializing the permutation
		// SharePerm(Perm perm) : mPerm(std::move(perm)) {}
		SharePerm(Perm perm, u8 partyIdx) : mPartyIdx(partyIdx), mPerm(std::move(perm)) {}

        // sample a random permutation of the given size. 
        SharePerm(u64 size, PRNG& prng, u8 partyIdx) : mPartyIdx(partyIdx), mPerm(size, prng) {}

        // sample a random permutation of the given size. 
		void init(u64 size, PRNG& prng)
		{
			// assert(partyIdx < 2);
			// mPartyIdx = partyIdx;

			mPerm = Perm(size, prng);
		}


        macoro::task<> apply(
            oc::Matrix<u8>& in,
            oc::Matrix<u8>& out,
            bool invPerm,
            coproto::Socket& chl
            )
        {

            MC_BEGIN(macoro::task<>, &in, &out, &chl, invPerm,
                gmw0 = std::move(Gmw()),
                gmw1 = std::move(Gmw()),
                prng = oc::PRNG(oc::block(0,0)),
                this,
                soutperm = oc::Matrix<u8>{}
            );

            if(invPerm ^ bool(mPartyIdx))
            {   
                MC_AWAIT(LowMCPerm::applyVec(in, prng, gmw0, chl, soutperm));
                MC_AWAIT(LowMCPerm::applyVecPerm(soutperm, mPerm.mPerm, prng, gmw1, chl, out, invPerm));
            }
            else
            {

                MC_AWAIT(LowMCPerm::applyVecPerm(in, mPerm.mPerm, prng, gmw0, chl, soutperm, invPerm));
                MC_AWAIT(LowMCPerm::applyVec(soutperm, prng, gmw1, chl, out));
            }

            MC_END();
        }
    };

}