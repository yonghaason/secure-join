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
			mPi(std::move(mPerm), partyIdx)
		{
			mShare.resize(data.size(), sizeof(u64));
			std::copy(data.begin(), data.end(), (u64*)mShare.data());
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
			coproto::Socket &chl
		)
		{
			MC_BEGIN(macoro::task<>, this, &chl,
					 rho1 = oc::Matrix<u8>{},
					 rho2 = oc::Matrix<u8>{}
					 );

			#ifndef NDEBUG
				std::cout << "mPi.mPerm for party = " << mPi.mPartyIdx << " is ";
				std::cout << mPi.mPerm << " " << std::endl;
			#endif


			// rho1 will resized() and initialzed in the apply function
			MC_AWAIT(mPi.apply(mShare, rho1, false, chl));

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
			#ifndef NDEBUG
				std::cout << "mRho is ";
				std::cout << mRho.mPerm << " ";
				std::cout << std::endl;
			#endif
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

		macoro::task<> apply(
			oc::Matrix<u8> &in,
			oc::Matrix<u8> &out,
			oc::PRNG &prng,
			coproto::Socket &chl)
		{

			MC_BEGIN(macoro::task<>, this, &in, &out, &prng, &chl,
					 temp = oc::Matrix<u8>{},
					 soutInv = oc::Matrix<u8>{},
					 gmw = Gmw()

			);

			out.resize(in.rows(), in.cols());

			// Local Permutation of [x]
			temp.resize(in.rows(), in.cols());
			mRho.apply<u8>(in, temp);

			// Applying pi1 & pi2
			MC_AWAIT(mPi.apply(temp, out, true, chl));


			MC_END();
		}
	};

}