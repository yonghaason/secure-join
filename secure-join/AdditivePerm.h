#pragma once
#include "Defines.h"
#include <vector>
#include "ComposedPerm.h"
#include "Permutation.h"

namespace secJoin
{

	class AdditivePerm
	{
	public:
		// Need to eventually change this to si64Matrix
		enum class Type
		{
			Add,
			Xor
		};

		Type mType = Type::Xor;
		std::vector<u32> mShare;
		ComposedPerm mPi;
		Perm mRho;

		bool isSetup() const { return mRho.size(); }

		AdditivePerm() = default;

		AdditivePerm(span<u32> shares, PRNG& prng, u8 partyIdx, Type type):
			mType(type),
			mPi(shares.size(), partyIdx, prng)
		{
			mShare.resize(shares.size());
			std::copy(shares.begin(), shares.end(), (u32*)mShare.data());
		}

		//AdditivePerm(span<u32> data, Perm mPerm, u8 partyIdx):
		//	mPi(std::move(mPerm), partyIdx)
		//{
		//	mShare.resize(data.size(), sizeof(u32));
		//	std::copy(data.begin(), data.end(), (u32*)mShare.data());
		//}


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
			coproto::Socket &chl,
			OleGenerator& ole
		)
		{
			MC_BEGIN(macoro::task<>, this, &chl, &ole,
					rho1 = oc::Matrix<u32>{},
					rho2 = oc::Matrix<u32>{}
					);

			//std::cout << "mPi.mPerm for party = " << mPi.mPartyIdx << " is ";
			//std::cout << mPi.mPerm << " " << std::endl;

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

			if (mType == Type::Xor)
			{
				for (oc::u32 i = 0; i < rho1.rows(); ++i)
				{
					mRho.mPerm[i] = *(u32*)rho1.data(i) ^ *(u32*)rho2.data(i);
				}
			}
			else
			{
				for (oc::u32 i = 0; i < rho1.rows(); ++i)
				{
					mRho.mPerm[i] = *(u32*)rho1.data(i) + *(u32*)rho2.data(i);
				}
			}
			MC_END();
		}

		u64 size() const { return mShare.size(); }


		macoro::task<> apply(
			oc::Matrix<u8> &in,
			oc::Matrix<u8> &out,
			oc::PRNG &prng,
			coproto::Socket &chl,
			OleGenerator& ole,
			bool inv = false)
		{
			if (inv)
				throw RTE_LOC;

			MC_BEGIN(macoro::task<>, this, &in, &out, &prng, &chl, &ole,
					 temp = oc::Matrix<u8>{},
					 soutInv = oc::Matrix<u8>{}

			);

			out.resize(in.rows(), in.cols());

			// Local Permutation of [x]
			temp.resize(in.rows(), in.cols());
			mRho.apply<u8>(in, temp);


			MC_AWAIT(mPi.apply<u8>(temp, out, chl, ole, true));

			MC_END();
		}


		macoro::task<> compose(
			const AdditivePerm& pi,
			AdditivePerm& out,
			oc::PRNG& prng,
			coproto::Socket& chl,
			OleGenerator& gen
		)
		{
			throw RTE_LOC;
		}

	};

}