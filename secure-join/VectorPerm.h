#include "Defines.h"
#include <vector>
#include "SharePerm.h"
#include "Permutation.h"

namespace secJoin
{

	class VectorPerm
	{
	public:
		// Need to eventually change this to si64Matrix
		oc::Matrix<u8> mShare;
		SharePerm mPi;
		Perm mRho;

		bool isSetup() const { return mRho.size(); }

		// VectorPerm() = default;

		// SharePerm(u64 size, PRNG& prng, u8 partyIdx)


		VectorPerm(span<u64> data, PRNG& prng, u8 partyIdx):
			mPi(data.size(), prng, partyIdx)
		{
			mShare.resize(data.size(), sizeof(u64));
			std::copy(data.begin(), data.end(), (u64*)mShare.data());
		}

		VectorPerm(span<u64> data, Perm mPerm, u8 partyIdx):
			mPi(mPerm, partyIdx)
		{
			mShare.resize(data.size(), sizeof(u64));
			std::copy(data.begin(), data.end(), (u64*)mShare.data());
		}

		// void init(u64 n, u64 partyIdx)
		// {
		// 	// mShare.resize(n);
		// 	// mShare.reshape(n, 1);
		// 	mPi.mPartyIdx = partyIdx;
		// 	// mPi.mPerm.clear();
		// 	// mRhoPP.mPerm.clear();
		// }

		// void setShares(std::vector<i64> share)
		// {
		//     if (share.size() != mShare.size())
		//         throw RTE_LOC;

		//     memcpy(&mShare[0], &share[0], sizeof(i64) * mShare.size());
		// }

		// void setShare(std::vector<u64> share)
		// {
		// 	if (share.size() != mShare.size())
		// 		throw RTE_LOC;

		// 	// Need to replace this with the copy function
		// 	memcpy(mShare[0].data(), &share[0], sizeof(u64) * mShare.size());
		// }

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
			coproto::Socket &chl
		)
		{
			MC_BEGIN(macoro::task<>, this, &chl,
					 rho1 = oc::Matrix<u8>{},
					 rho2 = oc::Matrix<u8>{}
					 );

			std::cout << "mPi.mPerm for party = " << mPi.mPartyIdx << " is ";
			std::cout << mPi.mPerm << " " << std::endl;


			// rho1 will resized() and initialzed in the apply function
			MC_AWAIT(mPi.apply(mShare, rho1, true, chl));

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
			if (mShare.rows() != rho2.rows())
				throw RTE_LOC;

			if (mShare.rows() != rho1.rows())
				throw RTE_LOC;

			mRho.mPerm.resize(rho1.rows());

			// std::cout << "Rho1 Rows " << rho1.rows() << std::endl;
			// std::cout << "Rho1 Cols " << rho1.cols() << std::endl;

			// std::cout << "Size of one row is " << sizeof(*(u64*)rho1(0)) << std::endl;
			// std::cout << "Value of zero row is " << *(u64*)rho1.data(0) << std::endl;

			
			for (oc::u64 i = 0; i < rho1.rows(); ++i)
			{
				// rho(i) = rho1(i) ^ rho2(i);
				mRho.mPerm[i] = *(u64*)rho1.data(i) ^ *(u64*)rho2.data(i);

				// ------ Need to find a safer way to do this
			}
			std::cout << "mRho is ";
			std::cout << mRho.mPerm << " ";
			std::cout << std::endl;
			// oc::Matrix<u8> dst(mRhoPP.mPerm.data(), size(), 1);

			// #ifndef NDEBUG
			// u64 failed = 0;
			// for (u64 i = 0; i < size(); ++i)
			// {
			// 	if ((u64)mRhoPP[i] > size())
			// 	{
			// 		if (failed > 10)
			// 		{
			// 			std::cout << "... " << std::endl;
			// 			break;
			// 		}
			// 		++failed;
			// 		std::cout << "bad VectorPerm index " << mRhoPP[i] << std::endl;
			// 	}
			// }

			// if (failed)
			// 	throw RTE_LOC;

			// #endif //

			MC_END();
		}

		u64 size() const { return mShare.size(); }

		macoro::task<> main(
			oc::Matrix<u8> &in,
			oc::Matrix<u8> &out,
			oc::PRNG &prng,
			coproto::Socket &chl)
		{

			MC_BEGIN(macoro::task<>, this, &in, &out, &prng, &chl,
					 permIn = oc::Matrix<u8>{},
					 soutInv = oc::Matrix<u8>{},
					 gmw = Gmw()

			);


			// std::cout << "mRho[" << i << "]="<< mRho.mPerm[i] << std::endl;

			permIn.resize(in.rows(), in.cols());

			// Local Permutation of [x]
			for (u64 i = 0; i < in.rows(); ++i)
			{
				auto dst = permIn[mRho.mPerm[i]].begin();
				// auto src = in[i].data();
				std::copy(in[i].begin(), in[i].end(), dst); // Need to check the second argument
			}

			for (u64 i = 0; i < in.rows(); ++i)
			{

				for (u64 j = 0; j < in.cols(); ++j)
				{
					if(in(i,j) != permIn( mRho.mPerm[i]  , j))
						std::cout<<"Wrong after rho perm" << std::endl;
				}
				
			}

			// Inverse permutation logic
			if (mPi.mPartyIdx == 0)
			{
				//  Second party does the inverse
				MC_AWAIT(LowMCPerm::applyVecPerm(permIn, mPi.mPerm.mPerm, prng, gmw, chl, soutInv, true));
				MC_AWAIT(LowMCPerm::applyVec(soutInv, prng, gmw, chl, out));
			}
			else
			{
				MC_AWAIT(LowMCPerm::applyVec(permIn, prng, gmw, chl, soutInv));
				// Now the first party does the inverse
				MC_AWAIT(LowMCPerm::applyVecPerm(soutInv, mPi.mPerm.mPerm, prng, gmw, chl, out, true));
			}


			MC_END();
		}
	};

}