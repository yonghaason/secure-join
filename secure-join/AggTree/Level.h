#pragma once
#include "secure-join/Matrix.h"
#include "cryptoTools/Common/BitVector.h"
#include <vector>


namespace secJoin
{

	enum AggTreeType : char
	{
		Prefix = 1,
		Suffix = 2,
		Full = 3
	};


	struct AggTreeLevel
	{
		TBinMatrix mPreVal, mSufVal, mPreBit, mSufBit;

		void resize(u64 n, u64 bitCount, AggTreeType type)
		{
			if (type & AggTreeType::Prefix)
			{
				mPreVal.resize(n, bitCount, sizeof(oc::block));
				mPreBit.resize(n, 1, sizeof(oc::block));
			}
			if (type & AggTreeType::Suffix)
			{
				mSufVal.resize(n, bitCount, sizeof(oc::block));
				mSufBit.resize(n, 1, sizeof(oc::block));
			}
		}
	};

	//struct DLevel
	//{
	//	BinMatrix mPreVal, mSufVal, mPreBit, mSufBit;


	//	void load(std::array<AggTreeLevel, 2>& tvs)
	//	{
	//		//Sh3Converter conv;

	//		throw RTE_LOC;
	//		//auto m = std::max<u64>(tvs[0].mPreVal.bitsPerEntry(), tvs[1].mSufVal.bitsPerEntry());

	//		//BinMatrix preVal[2], sufVal[2], preBit[2], sufBit[2];
	//		//conv.toBinaryMatrix(tvs[0].mPreVal, preVal[0]);
	//		//conv.toBinaryMatrix(tvs[1].mPreVal, preVal[1]);
	//		//conv.toBinaryMatrix(tvs[0].mPreBit, preBit[0]);
	//		//conv.toBinaryMatrix(tvs[1].mPreBit, preBit[1]);
	//		//conv.toBinaryMatrix(tvs[0].mSufVal, sufVal[0]);
	//		//conv.toBinaryMatrix(tvs[1].mSufVal, sufVal[1]);
	//		//conv.toBinaryMatrix(tvs[0].mSufBit, sufBit[0]);
	//		//conv.toBinaryMatrix(tvs[1].mSufBit, sufBit[1]);

	//		//preVal[0].trim();
	//		//preVal[1].trim();
	//		//preBit[0].trim();
	//		//preBit[1].trim();

	//		//sufVal[0].trim();
	//		//sufVal[1].trim();
	//		//sufBit[0].trim();
	//		//sufBit[1].trim();

	//		//mPreVal.resize(preVal[0].rows() + preVal[1].rows(), m);
	//		//mPreBit.resize(preBit[0].rows() + preBit[1].rows(), 1);
	//		//mSufVal.resize(sufVal[0].rows() + sufVal[1].rows(), m);
	//		//mSufBit.resize(sufBit[0].rows() + sufBit[1].rows(), 1);

	//		//for (u64 j = 0; j < mPreVal[0].rows(); ++j)
	//		//{
	//		//	for (u64 l = 0; l < 2; ++l)
	//		//	{
	//		//		for (u64 k = 0; k < mPreVal.i64Cols(); ++k)
	//		//			mPreVal.mShares[l](j, k) = preVal[j & 1].mShares[l](j / 2, k);

	//		//		if (mPreBit.rows())
	//		//			mPreBit.mShares[l](j) = preBit[j & 1].mShares[l](j / 2);
	//		//	}
	//		//}
	//		//for (u64 j = 0; j < mSufVal[0].rows(); ++j)
	//		//{
	//		//	for (u64 l = 0; l < 2; ++l)
	//		//	{
	//		//		for (u64 k = 0; k < mSufVal.i64Cols(); ++k)
	//		//			mSufVal.mShares[l](j, k) = sufVal[j & 1].mShares[l](j / 2, k);

	//		//		if (mSufBit.rows())
	//		//			mSufBit.mShares[l](j) = sufBit[j & 1].mShares[l](j / 2);
	//		//	}
	//		//}
	//	}


	//	void load(AggTreeLevel& tvs)
	//	{
	//		//throw RTE_LOC;
	//		//Sh3Converter conv;
	//		tvs.mPreVal.transpose(mPreVal);
	//		tvs.mPreBit.transpose(mPreBit);
	//		tvs.mSufVal.transpose(mSufVal);
	//		tvs.mSufBit.transpose(mSufBit);
	//	}
	//};



	//struct Level
	//{
	//	TBinMatrix mPreVal, mSufVal, mPreBit, mSufBit;

	//	void resize(u64 n, u64 bitCount, Type type)
	//	{
	//		if (type & Type::Prefix)
	//		{
	//			throw RTE_LOC;
	//			//mPreVal.reset(n, bitCount, 4);
	//			//mPreBit.reset(n, 1, 4);
	//		}
	//		if (type & Type::Suffix)
	//		{
	//			throw RTE_LOC;
	//			//mSufVal.reset(n, bitCount, 4);
	//			//mSufBit.reset(n, 1, 4);
	//		}
	//	}

	//};

	struct PLevelNew
	{
		BinMatrix mPreVal, mSufVal;
		BinMatrix mPreBit, mSufBit;


		u64 numEntries() { return mPreVal.numEntries(); }

		void resize(u64 n, u64 elementBitCount)
		{
			mPreVal.resize(n, elementBitCount);
			mPreVal.resize(n, elementBitCount);
			mSufVal.resize(n, elementBitCount);
			mSufVal.resize(n, elementBitCount);
			mPreBit.resize(n, 1);
			mSufBit.resize(n, 1);
		}

		//void load(DLevel* dl);

		//void validate(TBinMatrix& tvs0, TBinMatrix& tvs1, TBinMatrix& tvs2);

		//void validate(AggTreeLevel& tvs0, AggTreeLevel& tvs1, AggTreeLevel& tvs2);

		void reveal(std::array<AggTreeLevel, 2>& tvs0, std::array<AggTreeLevel, 2>& tvs1);
		void reveal(AggTreeLevel& tvs0, AggTreeLevel& tvs1);

		void perfectUnshuffle(PLevelNew& l0, PLevelNew& l1);
		//void load(AggTreeLevel& tvs0);
	};

	struct PLevel
	{
		std::vector<oc::BitVector> mPreVal, mSufVal;
		oc::BitVector mPreBit, mSufBit;


		u64 numEntries() { return mPreVal.size(); }

		u64 size() { return mPreBit.size(); }

		void resize(u64 n)
		{
			mPreVal.resize(n);
			mPreVal.resize(n);
			mSufVal.resize(n);
			mSufVal.resize(n);
			mPreBit.resize(n);
			mSufBit.resize(n);
		}

		//void load(DLevel* dl);

		//void validate(TBinMatrix& tvs0, TBinMatrix& tvs1, TBinMatrix& tvs2);

		//void validate(AggTreeLevel& tvs0, AggTreeLevel& tvs1, AggTreeLevel& tvs2);

		void reveal(std::array<AggTreeLevel, 2>& tvs0, std::array<AggTreeLevel, 2>& tvs1);
		void reveal(AggTreeLevel& tvs0, AggTreeLevel& tvs1);

		void perfectUnshuffle(PLevel& l0, PLevel& l1);
		//void load(AggTreeLevel& tvs0);
	};
}