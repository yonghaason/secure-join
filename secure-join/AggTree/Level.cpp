
#include "Level.h"

namespace secJoin
{

    void PLevelNew::reveal(std::array<AggTreeLevel, 2>& tvs0, std::array<AggTreeLevel, 2>& tvs1)
    {
        PLevelNew l0, l1;
        l0.reveal(tvs0[0], tvs1[0]);
        l1.reveal(tvs0[1], tvs1[1]);

        perfectUnshuffle(l0, l1);
    }


    void PLevelNew::reveal(AggTreeLevel& tvs0, AggTreeLevel& tvs1)
    {
        AggTreeLevel ll;

        auto revealOne = [](auto& dst, auto& src0, auto& src1)
        {
            dst.resize(src0.numEntries(), src0.bitsPerEntry());
            for (u64 i = 0; i < dst.size(); ++i)
                dst(i) = src0(i) ^ src1(i);
        };

        revealOne(ll.mPreBit, tvs0.mPreBit, tvs1.mPreBit);
        revealOne(ll.mPreVal, tvs0.mPreVal, tvs1.mPreVal);
        revealOne(ll.mSufBit, tvs0.mSufBit, tvs1.mSufBit);
        revealOne(ll.mSufVal, tvs0.mSufVal, tvs1.mSufVal);

        ll.mPreVal.transpose(mPreVal);
        ll.mPreBit.transpose(mPreBit);
        ll.mSufVal.transpose(mSufVal);
        ll.mSufBit.transpose(mSufBit);
    }


    void PLevelNew::perfectUnshuffle(PLevelNew& l0, PLevelNew& l1)
    {
        auto preSize = l0.mPreVal.numEntries() + l1.mPreVal.numEntries();
        mPreVal.resize(preSize, l0.mPreVal.bitsPerEntry());
        mPreBit.resize(preSize, 1);
        auto sufSize = l0.mSufVal.numEntries() + l1.mSufVal.numEntries();
        mSufVal.resize(sufSize, l0.mSufVal.bitsPerEntry());
        mSufBit.resize(sufSize, 1);

        if (preSize & 1)
            throw RTE_LOC;
        if (sufSize & 1)
            throw RTE_LOC;

        for (u64 j = 0; j < preSize; j += 2)
        {
            for (u64 k = 0; k < mPreVal.bytesPerEnrty(); ++k)
            {
                mPreVal(j + 0, k) = l0.mPreBit(j / 2, k);
                mPreVal(j + 1, k) = l1.mPreBit(j / 2, k);
            }

            mPreBit(j + 0) = l0.mPreBit(j / 2);
            mPreBit(j + 1) = l1.mPreBit(j / 2);
        }

        for (u64 j = 0; j < sufSize; j += 2)
        {
            for (u64 k = 0; k < mSufVal.bytesPerEnrty(); ++k)
            {
                mSufVal(j + 0, k) = l0.mSufVal(j / 2, k);
                mSufVal(j + 1, k) = l1.mSufVal(j / 2, k);
            }

            mSufBit(j + 0) = l0.mSufBit(j / 2);
            mSufBit(j + 1) = l1.mSufBit(j / 2);
        }
    }


    void PLevel::reveal(AggTreeSplitLevel& tvs0, AggTreeSplitLevel& tvs1)
    {
        PLevel l0, l1;
        l0.reveal(tvs0[0], tvs1[0]);
        l1.reveal(tvs0[1], tvs1[1]);

        perfectUnshuffle(l0, l1);
    }


    auto revealOne(
        std::vector<oc::BitVector>& dst,
        TBinMatrix& src0,
        TBinMatrix& src1,
        bool print = false)
    {
        //BinMatrix temp(src0.numEntries(), src0.bitsPerEntry());
        //dst.resize(src0.numEntries(), src0.bitsPerEntry());

        auto v0 = src0.transpose();
        auto v1 = src1.transpose();
        //TBinMatrix v(src0.numEntries(), src0.bitsPerEntry());
        //for (i64 i = 0; i < v.size(); ++i)
        //    v(i) = src0(i) ^ src1(i);

        //auto vv = v.transpose();

        dst.resize(src0.numEntries());
        for (u64 i = 0; i < dst.size(); ++i)
        {
            dst[i].resize(src0.bitsPerEntry());
            for (u64 j = 0; j < dst[i].sizeBytes(); ++j)
            {
                dst[i].getSpan<u8>()[j] = v0(i, j) ^ v1(i, j);
            }

            //if (print)
            //    std::cout << "i " << i << " " << (int)dst[i].getSpan<u8>()[0] << " = "
            //    << (int)v0(i, 0) << " + "
            //    << (int)v1(i, 0) << std::endl;
        }

    }

    auto revealOne(
        oc::BitVector& dst,
        TBinMatrix& src0,
        TBinMatrix& src1)
    {
        assert(src0.bitsPerEntry() < 2);
        assert(src1.bitsPerEntry() < 2);
        dst.resize(src0.numEntries());

        //auto n = oc::divCeil(src0.numEntries(), n)
        for (u64 i = 0; i < dst.sizeBytes(); ++i)
        {
            dst.getSpan<u8>()[i] = src0(i) ^ src1(i);
        }
    };


    void PLevel::reveal(AggTreeLevel& tvs0, AggTreeLevel& tvs1)
    {
        revealOne(mPreBit, tvs0.mPreBit, tvs1.mPreBit);
        revealOne(mPreVal, tvs0.mPreVal, tvs1.mPreVal, true);
        revealOne(mSufBit, tvs0.mSufBit, tvs1.mSufBit);
        revealOne(mSufVal, tvs0.mSufVal, tvs1.mSufVal);
    }


    void PLevel::perfectUnshuffle(PLevel& l0, PLevel& l1)
    {

        auto shuffle = [](auto& l0, auto& l1, auto& out)
        {
            auto size = l0.size() + l1.size();
            out.resize(size);

            for (u64 i = 0; i < size; i += 2)
            {
                out[i + 0] = l0[i / 2];

                if (i + 1 < size)
                    out[i + 1] = l1[i / 2];
            }

        };

        shuffle(l0.mPreVal, l1.mPreVal, mPreVal);
        shuffle(l0.mPreBit, l1.mPreBit, mPreBit);
        shuffle(l0.mSufVal, l1.mSufVal, mSufVal);
        shuffle(l0.mSufBit, l1.mSufBit, mSufBit);
    }
}