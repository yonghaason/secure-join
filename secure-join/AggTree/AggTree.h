#pragma once
#include "cryptoTools/Circuit/BetaCircuit.h"
#include "cryptoTools/Circuit/BetaLibrary.h"
#include "cryptoTools/Common/Log.h"
#include "cryptoTools/Crypto/PRNG.h"
#include <iomanip>
#include "PerfectShuffle.h"
#include <functional>
#include "Level.h"
#include "libOTe/Tools/Tools.h"
#include "coproto/Socket/Socket.h"
#include "secure-join/OleGenerator.h"
#include "secure-join/GMW/Gmw.h"
//#include "reveal.h"

namespace secJoin
{
    //void validateShares(BinMatrix& shares, CommPkg& comm, oc::BitVector& mask, bool debug);
    //inline void randomize(TBinMatrix& d)
    //{
    //	static oc::PRNG prng(oc::CCBlock);
    //	for (u64 j = 0; j < 2; ++j)
    //	{
    //		prng.get(
    //			d.mShares[j].data(),
    //			d.mShares[j].size());
    //	}
    //}

    //inline block hash(const TBinMatrix& d)
    //{
    //	oc::RandomOracle ro(sizeof(block));
    //	for (u64 j = 0; j < 2; ++j)
    //	{
    //		ro.Update(
    //			d.mShares[j].data(),
    //			d.mShares[j].size());
    //	}

    //	block r;
    //	ro.Final(r);
    //	return r;
    //}

    //inline std::string hexx(const TBinMatrix& d)
    //{
    //	std::stringstream ss;
    //	for (u64 j = 0; j < d.bitsPerEntry(); ++j)
    //	{
    //		ss << j << ".0." << hex(d.mShares[0][j]) << std::endl;
    //		ss << j << ".1." << hex(d.mShares[1][j]) << std::endl;
    //	}

    //	return ss.str();
    //}
    //inline block hash(const BinMatrix& d)
    //{
    //	oc::RandomOracle ro(sizeof(block));
    //	for (u64 j = 0; j < 2; ++j)
    //	{
    //		ro.Update(
    //			d.mShares[j].data(),
    //			d.mShares[j].size());
    //	}

    //	block r;
    //	ro.Final(r);
    //	return r;
    //}

    inline void perfectUnshuffle(
        TBinMatrix& in,
        TBinMatrix& out0,
        TBinMatrix& out1,
        u64 dstShift,
        u64 numEntries)
    {
        throw RTE_LOC;
        if (dstShift % 8)
            throw RTE_LOC;
        if (numEntries == 0 || in.numEntries() == 0)
            numEntries = in.numEntries();

        if (numEntries == 0)
            return;

        auto dstShift2 = dstShift / 2;
        if (dstShift2 > out0.numEntries())
            throw RTE_LOC;
        if (dstShift2 > out1.numEntries())
            throw RTE_LOC;
        //auto ss = in.() * sizeof(*in.mShares[0].data()) * 8;
        if (numEntries > in.numEntries())
            throw RTE_LOC;
        if (numEntries != out0.numEntries() + out1.numEntries() - dstShift)
            throw RTE_LOC;

        for (u64 i = 0; i < in.bitsPerEntry(); ++i)
        {
            //for (u64 j = 0; j < 2; ++j)
            {
                auto ss = oc::divCeil(out0.numEntries() - dstShift2, 8);
                auto inn = in[i].subspan(0, oc::divCeil(numEntries, 8));
                auto o0 = out0[i].subspan(dstShift2 / 8, ss);
                auto o1 = out1[i].subspan(dstShift2 / 8, ss);
                assert(inn.data() + inn.size() <= (u8*)(in[i].data() + in[i].size()));
                assert(o0.data() + o0.size() <= (u8*)(out0[i].data() + out0[i].size()));
                assert(o1.data() + o1.size() <= (u8*)(out1[i].data() + out1[i].size()));

                if (dstShift2)
                {
                    memset(out0[i].data(), 0, dstShift2 / 8);
                    memset(out1[i].data(), 0, dstShift2 / 8);
                }

                perfectUnshuffle(inn, o0, o1);


                assert(inn.data() + inn.size() <= (u8*)(in[i].data() + in[i].size()));
            }
        }
    }


    inline void perfectUnshuffle(TBinMatrix& in, TBinMatrix& out0, TBinMatrix& out1)
    {
        auto numEntries = in.numEntries();
        if (numEntries == 0)
            return;
        //auto ss = in.simdWidth() * sizeof(*in.mShares[0].data()) * 8;
        //if (numEntries > in.numEntries())
        //	throw RTE_LOC;

        for (u64 i = 0; i < in.bitsPerEntry(); ++i)
        {
            //for (u64 j = 0; j < 2; ++j)
            {
                auto inn = in[i].subspan(0, oc::divCeil(numEntries, 8));
                auto o0 = out0[i].subspan(0, oc::divCeil(numEntries / 2, 8));
                auto o1 = out1[i].subspan(0, oc::divCeil(numEntries / 2, 8));
                assert(inn.data() + inn.size() <= (u8*)(in[i].data() + in[i].size()));
                assert(o0.data() + o0.size() <= (u8*)(out0[i].data() + out0[i].size()));
                assert(o1.data() + o1.size() <= (u8*)(out1[i].data() + out1[i].size()));

                perfectUnshuffle(inn, o0, o1);
                assert(inn.data() + inn.size() <= (u8*)(in[i].data() + in[i].size()));
            }
        }
    }


    inline void perfectShuffle(TBinMatrix& in0, TBinMatrix& in1, TBinMatrix& out)
    {
        auto size = out.numEntries();
        auto inSize = size / 2;
        if (in0.bitsPerEntry() != in1.bitsPerEntry())
            throw RTE_LOC;
        if (out.bitsPerEntry() != in1.bitsPerEntry())
            throw RTE_LOC;
        if (in0.numEntries() != inSize)
            throw RTE_LOC;
        if (in1.numEntries() != inSize)
            throw RTE_LOC;

        for (u64 i = 0; i < in0.bitsPerEntry(); ++i)
        {
            //for (u64 j = 0; j < 2; ++j)
            {
                auto inn0 = span<u8>((u8*)in0[i].data(), oc::divCeil(inSize, 8));
                auto inn1 = span<u8>((u8*)in1[i].data(), oc::divCeil(inSize, 8));
                auto oo = span<u8>((u8*)out[i].data(), oc::divCeil(size, 8));

                assert(oo.data() + oo.size() <= (u8*)(out[i].data() + out[i].size()));
                assert(inn0.data() + inn0.size() <= (u8*)(in0[i].data() + in0[i].size()));
                assert(inn1.data() + inn1.size() <= (u8*)(in1[i].data() + in1[i].size()));
                perfectShuffle(inn0, inn1, oo);
            }
        }
    }

    // This class implements a prefix, suffix or full aggregation tree, 
    // elements an input vector based on a bit vector.
    // Given an input vector x=(x1,x2,...,xn) and bit vector preBit=(0,sufBit,...,bn),
    // 
    // A 'block' is defined as {i,i+1...,j} where 𝑏_𝑖,𝑏_{𝑖+1},…, 𝑏_𝑗=(0,1,1,…,1)
    // and 𝑏_{𝑗+1}=0.
    // 
    // The apply(x,preBit,...) function will output the vector y=(y1,y2,...,yn)
    // 
    // prefix: for each block {i,...,j}
    //		𝑦_𝑖  = 𝑣_𝑖 
    //      𝑦_𝑖′ = 𝑦_𝑖′ ⊕ 𝑣_{𝑖′−1}      :𝑖′∈{𝑖+1,…,𝑗}
    //
    // suffix: for each block {i,...,j}
    //     𝑦_𝑗  = 𝑣_𝑗
    //     𝑦_𝑗′ = 𝑣_𝑗′ ⊕ 𝑦_{𝑗′+1}      :𝑗^′∈{𝑗−1,…,𝑖}
    // 
    // Full: for each block {i,...,j}
    //	   𝑦_𝑖′ = 𝑣_𝑖 ⊕ … ⊕ 𝑣_𝑗      :𝑖^′∈{𝑖,…,𝑗}
    // 
    // 
    class AggTree
    {
    public:
        using Type = AggTreeType;

        // The ⊕ function. Takes as input two values
        // and output the addition of them.
        using Operator = std::function<
            void(
                oc::BetaCircuit& c,
                const oc::BetaBundle& left,
                const oc::BetaBundle& right,
                oc::BetaBundle& out)>;

        // A tree record has the form  (prefix, suffix, prefix-prod, suffix-prod).
        // - prefix is the current prefix value of this node. During upstream
        //   this is the value that is being push up and right. For downstream,
        //   this is the value coming in from the left. Value is padded to be byte aligned.
        // - suffix is the current suffix
        // - prefix-prod is product of the current prefix bits.
        // - suffix-prod is product of the current suffix bits.
        // 
        // Each tree record is padded to be 64 bit aligned.
        // The prefix and suffix will be byte aligned.
        // The product bits will be byte aligned and packed together.
        //
        // eg, given 6 bit values, 
        // 
        //  pppp`pp__`ssss`ss__`bb__`__....__`
        //
        // the prefix will occupy the first 8 bits
        // with the last 2 being padding. Then the suffix. Finally
        // the prefix and suffix bits will be on the next byte followed by
        // however many padding bits are required to make the full records
        // length a multiple of 64.
        //struct TreeRecord
        //{
        //	// the prefix value
        //	oc::BetaBundle mPrefix;

        //	// the suffix value
        //	oc::BetaBundle mSuffix;


        //	// the product of the control bits of the current record.
        //	oc::BetaBundle mPreProd, mSufProd;


        //	//static u64 recordBitCount(u64 valBitCount, Type type)
        //	//{
        //	//	//auto bitsPerEntry8 = oc::roundUpTo(valBitCount, 8);

        //	//	u64 inSize = 2;
        //	//	if (type & Type::Prefix)
        //	//		inSize += bitsPerEntry8;
        //	//	if (type & Type::Suffix)
        //	//		inSize += bitsPerEntry8;

        //	//	// In order to play some tricks to avoid copying values around, we make the 
        //	//	// inputs a multiple of 64 bits. This allows us to call a no-op resize instead
        //	//	// of copying.
        //	//	return oc::roundUpTo(inSize, 64);
        //	//}

        //	TreeRecord(u64 bitsPerEntry, u64 offset, Type type, const oc::BetaBundle& src)
        //	{
        //		init(bitsPerEntry, offset, type, src);
        //	}

        //	void init(u64 bitsPerEntry, u64 offset, Type type, const oc::BetaBundle& src)
        //	{
        //		//u64 inSize = recordBitCount(bitsPerEntry, type);
        //		//auto bitsPerEntry8 = oc::roundUpTo(bitsPerEntry, 8);


        //		auto iter = src.begin() + offset * inSize;
        //		if (type & Type::Prefix)
        //		{
        //			mPrefix.insert(mPrefix.end(), iter, iter + bitsPerEntry);
        //			iter += bitsPerEntry8;
        //		}

        //		if (type & Type::Suffix)
        //		{
        //			mSuffix.insert(mSuffix.end(), iter, iter + bitsPerEntry);
        //			iter += bitsPerEntry8;
        //		}

        //		if (type & Type::Prefix)
        //		{
        //			mPreProd.insert(mPreProd.end(), iter, iter + 1);
        //		}
        //		++iter;
        //		if (type & Type::Suffix)
        //		{
        //			mSufProd.insert(mSufProd.end(), iter, iter + 1);
        //		}
        //		++iter;
        //	}
        //};
        using Level = AggTreeLevel;
        using SplitLevel = AggTreeSplitLevel;

        //	bool mDebug = false;
        //	void apply(
        //		const BinMatrix& src,
        //		const BinMatrix& controlBits,
        //		const Operator& op,
        //		u64 partyIdx,
        //		Type type,
        //		CommPkg& comm,
        //		Sh3ShareGen& gen,
        //		BinMatrix& dst)
        //	{
        //		u64 bitsPerEntry = src.bitsPerEntry();
        //		u64 n = src.rows();
        //		Level root;
        //		std::vector<std::array<Level, 2>> levels(oc::log2ceil(n));
        //		std::array<Level, 2> preSuf, vals;

        //		upstream(src, controlBits, op, partyIdx, type, comm, gen, root, levels);
        //		downstream(src, controlBits, op, root, levels, preSuf, vals, partyIdx, type, comm, gen);

        //		levels.clear();
        //		dst.resize(n, bitsPerEntry);

        //		computeLeaf(vals, preSuf, op, dst, partyIdx, type, comm, gen);
        //	}


            // take the rows
            //  in[srcRowStartIdx]
            //  ...
            //  in[srcRowStartIdx + numRows]
            //
            // and store the bit-transpose in dest. So each 
            // row j of dest will have the form 
            // 
            // dest[j] =  in(srcRowStartIdx,j), in(srcRowStartIdx+1,j),...,in(srcRowStartIdx+numRows,j)
            // 
        void toPackedBin(const BinMatrix& in, TBinMatrix& dest,
            u64 srcRowStartIdx,
            u64 numRows)
        {
            if (numRows > dest.numEntries())
                throw RTE_LOC;
            if (in.bitsPerEntry() != dest.bitsPerEntry())
                throw RTE_LOC;
            if (numRows + srcRowStartIdx > in.numEntries())
                throw RTE_LOC;

            //dest.reset(numRows, in.bitsPerEntry());

            if (in.bitsPerEntry() == 1)
                std::cout << "optimize me" << std::endl;


            auto& s = in;
            auto& d = dest;

            oc::MatrixView<u8> inView(
                (u8*)s.data() + srcRowStartIdx * s.bytesPerEnrty(),
                (u8*)s.data() + (srcRowStartIdx + numRows) * s.bytesPerEnrty(),
                s.bytesPerEnrty());

            assert(inView.data() + inView.size() <= s.data() + s.size());

            oc::MatrixView<u8> memView(
                d.data(),
                d.data() + d.size(),
                d.bytesPerRow());

            assert(memView.data() + memView.size() <= d.data() + d.size());

            oc::transpose(inView, memView);
        }

        void setLeafVals2(
            oc::MatrixView<const u8> src,
            span<const u8> controlBits,
            std::array<Level, 2>& leaves,
            u64 dIdx,
            u64 size,
            Type type)
        {
            auto available = src.rows();
            if (controlBits.size() != available)
                throw RTE_LOC;
            if (size > available)
                throw RTE_LOC;


            if (type & Type::Prefix)
            {
                std::array<BinMatrix, 2> vals;
                vals[0].resize(oc::divCeil(size, 2), src.cols());
                vals[1].resize(size / 2, src.cols());

                leaves[0].mPreBit.resize(vals[0].numEntries(), 1);
                leaves[1].mPreBit.resize(vals[0].numEntries(), 1);
                //std::array<oc::BitIterator, 2> iters;

                for (u64 i = 0; i < size / 2; ++i)
                {
                    memcpy(vals[0].data(i), src.data(2 * i + 0), src.cols());
                    memcpy(vals[1].data(i), src.data(2 * i + 1), src.cols());


                }

                if (size & 1)
                {
                    auto i = size / 2;
                    memcpy(vals[0].data(i), src.data(2 * i + 0), src.cols());
                }

                leaves[0].mPreVal = vals[0].transpose();
                leaves[1].mPreVal = vals[1].transpose();

            }



            //if (type & Type::Suffix)
            //{
            //    std::array<BinMatrix, 2> vals;
            //    vals[0].resize(oc::divCeil(size, 2), src.cols());
            //    vals[1].resize(size / 2, src.cols());

            //    leaves[0].mSufBit.resize(vals[0].numEntries(), 1);
            //    leaves[1].mSufBit.resize(vals[0].numEntries(), 1);


            //    for (u64 i = 0; i < size / 2; ++i)
            //    {
            //        memcpy(vals[0].data(i), src.data(2 * i + 0), src.cols());
            //        memcpy(vals[1].data(i), src.data(2 * i + 1), src.cols());
            //    }

            //    if (size & 1)
            //    {
            //        auto i = size / 2;
            //        memcpy(vals[0].data(i), src.data(2 * i + 0), src.cols());
            //    }


            //    leaves[0].mSufVal = vals[0].transpose();
            //    leaves[1].mSufVal = vals[1].transpose();
            //}


        }


        // load the leaf values and control bits. 
        // src are the values, controlBits are ...
        // leaves are where we will write the results.
        // They are separated into left and right children.
        //
        // sIdx means that we should start copying values from
        // src, controlBits at row sIdx.
        //
        // dIdx means that we should start writing results to
        // leaf index dIdx.
        //
        // We require dIdx to be a multiple of 8 and therefore 
        // we will pad the overall tree to be a multiple of 16.
        // We will assign zero to the padded control bits.
        void setLeafVals2(
            const BinMatrix& src,
            const BinMatrix& controlBits,
            std::array<Level, 2>& leaves,
            u64 sIdx,
            u64 dIdx,
            u64 size,
            Type type)
        {
            auto available = src.numEntries() - sIdx;
            auto size2 = std::min<u64>(size, available);

            setLeafVals2(
                oc::MatrixView<const u8>(src.mData.data(sIdx), src.mData.rows() - sIdx, src.mData.cols()),
                span<u8>(controlBits.mData).subspan(sIdx),
                leaves, dIdx, size2, type);

        }

        // load the leaf values and control bits. 
        // src are the values, controlBits are ...
        // leaves are where we will write the results.
        // They are separated into left and right children.
        //
        // sIdx means that we should start copying values from
        // src, controlBits at row sIdx.
        //
        // dIdx means that we should start writing results to
        // leaf index dIdx.
        //
        // We require dIdx to be a multiple of 8 and therefore 
        // we will pad the overall tree to be a multiple of 16.
        // We will assign zero to the padded control bits.
        void setLeafVals(
            const BinMatrix& src,
            const BinMatrix& controlBits,
            SplitLevel& leaves,
            u64 sIdx,
            u64 dIdx,
            u64 size,
            Type type)
        {
            auto available = src.numEntries() - sIdx;
            auto size2 = std::min<u64>(size, available);
            //assert(size2 == 2);

            TBinMatrix preValues(size2 * bool(type & Type::Prefix), src.bitsPerEntry());
            TBinMatrix sufValues(size2 * bool(type & Type::Suffix), src.bitsPerEntry());
            TBinMatrix preBits(size2 * bool(type & Type::Prefix), 1);
            TBinMatrix sufBits(size2 * bool(type & Type::Suffix), 1);

            //randomize(preValues);
            //randomize(preBits);

            if (type == Type::Full)
            {
                toPackedBin(src, preValues, sIdx, size2);
                sufValues = preValues;

                toPackedBin(controlBits, preBits, sIdx, size2);

                int last = ((sIdx + size2) == controlBits.numEntries()) * 1;
                auto w = sufBits.size() - 1;
                for (u64 i = 0; i < w; ++i)
                {
                    sufBits(i) = (u64(preBits(i)) >> 1) | (u64(preBits(i + 1)) << 7);
                }

                sufBits(w) = u64(preBits(w)) >> 1;
                sufBits(w) = u64(preBits(w)) >> 1;
                if (!last)
                {
                    u64 extra0 = controlBits(sIdx + size2) & 1;

                    *oc::BitIterator((u8*)sufBits.data(), size2 - 1) = extra0;
                }
                else
                {
                    *oc::BitIterator((u8*)sufBits.data(), size2 - 1) = 0;
                }
            }
            else if (type == Type::Prefix)
            {
                //std::cout << hash(src) << " " << hash(controlBits) << " in " << sIdx << std::endl;
                toPackedBin(src, preValues, sIdx, size2);
                toPackedBin(controlBits, preBits, sIdx, size2);
                //std::cout << hexx(preValues) << " " << hexx(preBits) << " out "<< sIdx <<"\n" << std::endl;

            }
            else
            {
                toPackedBin(src, sufValues, sIdx, size2);

                int last = ((sIdx + size2) == controlBits.numEntries()) * 1;

                assert(controlBits.bitsPerEntry() == 1);
                assert(controlBits.bytesPerEnrty() == 1);
                //auto cols = controlBits.bytesPerEnrty();
                auto rows = size2 - last;
                auto d0 = controlBits.data() + (1 + sIdx);

                for (u64 i = 0; i < rows; ++i)
                {
                    assert(d0[i] < 2);
                    *oc::BitIterator(sufBits.data(), i) = d0[i];
                }
                if (last)
                {
                    *oc::BitIterator((u8*)sufBits.data(), size2 - 1) = 0;
                }
                //auto cb0 = oc::MatrixView<u8>((u8*)d0, rows, 1);


                ////auto s0 = oc::MatrixView<u8>(
                //// (u8*)sufBits.mShares[0].data(), 
                //// sufBits.mShares[0].rows(), 
                //// oc::divCeil(sufBits.shareCount() - last, 8));
                ////
                //auto r = sufBits.mData.rows();
                //auto c = oc::divCeil(sufBits.numEntries() - last, 8);
                //auto s0 = oc::MatrixView<u8>((u8*)sufBits.data(), r, c);

                //oc::transpose(cb0, s0);
                ////oc::transpose(cb1, s1);

            }
            if (type & Type::Prefix)
            {

                preValues.trim();
                preBits.trim();
            }

            if (type & Type::Suffix)
            {
                sufValues.trim();
                sufBits.trim();
            }

            perfectUnshuffle(preValues, leaves[0].mPreVal, leaves[1].mPreVal, dIdx, size);
            perfectUnshuffle(sufValues, leaves[0].mSufVal, leaves[1].mSufVal, dIdx, size);
            perfectUnshuffle(preBits, leaves[0].mPreBit, leaves[1].mPreBit, dIdx, size);
            perfectUnshuffle(sufBits, leaves[0].mSufBit, leaves[1].mSufBit, dIdx, size);

            leaves[0].mPreVal.trim();
            leaves[1].mPreVal.trim();
            leaves[0].mSufVal.trim();
            leaves[1].mSufVal.trim();

            leaves[0].mPreBit.trim();
            leaves[1].mPreBit.trim();
            leaves[0].mSufBit.trim();
            leaves[1].mSufBit.trim();

            //if (dIdx == 0 && leaves[0].mSufBit.bitsPerEntry())
            //{
            //	std::lock_guard<std::mutex> ll(oc::gIoStreamMtx);
            //	std::cout << leaves[0].mSufBit.mShares[0](0) << std::endl;
            //}

            // make sure any padding bits are set to zero.
            for (u64 i = dIdx + size2; i < dIdx + size; ++i)
            {
                //for (u64 j = 0; j < 2; ++j)
                {
                    auto q = i & 1;
                    auto w = i / 2;

                    if (type & Type::Prefix)
                    {
                        if (w >= leaves[q].mPreBit.numEntries())
                            throw RTE_LOC;
                        auto d = (u8*)leaves[q].mPreBit.data();
                        *oc::BitIterator(d, w) = 0;

                        for (u64 k = 0; k < leaves[q].mPreVal.bitsPerEntry(); ++k)
                        {
                            auto v = (u8*)leaves[q].mPreVal[k].data();
                            *oc::BitIterator(v, w) = 0;
                        }

                    }

                    if (type & Type::Suffix)
                    {
                        if (w >= leaves[q].mSufBit.numEntries())
                            throw RTE_LOC;
                        auto d = (u8*)leaves[q].mSufBit.data();
                        *oc::BitIterator(d, w) = 0;

                        for (u64 k = 0; k < leaves[q].mSufVal.bitsPerEntry(); ++k)
                        {
                            auto v = (u8*)leaves[q].mSufVal[k].data();
                            *oc::BitIterator(v, w) = 0;
                        }
                    }
                }
            }
        }

        /* This circuit outputs pre,suf,preVal where

                     |  pre  = prep1 ? pre_0 + pre_1 : pre_1,
                     |  suf  = sufp0 ? suf_0 + suf_1 : suf_0
                     *  prep = prep0 * prep1
                     *  sufp = sufp0 * sufp1
                    / \
                   /   \
                  /     \
              pre_0,    pre_1
              suf_0,    suf_1
              prep_0,   prep_1
              sufp_0,   sufp_1
        */
        static oc::BetaCircuit upstreamCir(
            u64 bitsPerEntry,
            Type type,
            const Operator& add)
        {
            oc::BetaCircuit cir;

            //u64 inSize = TreeRecord::recordBitCount(bitsPerEntry, type);

            oc::BetaBundle
                leftPreVal(bitsPerEntry),
                leftSufVal(bitsPerEntry),
                rghtPreVal(bitsPerEntry),
                rghtSufVal(bitsPerEntry),
                leftPreBit(1),
                leftSufBit(1),
                rghtPreBit(1),
                rghtSufBit(1),
                prntPreVal(bitsPerEntry),
                prntSufVal(bitsPerEntry),
                prntPreBit(1),
                prntSufBit(1),
                temp1(bitsPerEntry), temp2(bitsPerEntry);

            if (type & Type::Prefix)
            {
                cir.addInputBundle(leftPreVal);
                cir.addInputBundle(rghtPreVal);
                cir.addInputBundle(leftPreBit);
                cir.addInputBundle(rghtPreBit);
            }
            if (type & Type::Suffix)
            {
                cir.addInputBundle(leftSufVal);
                cir.addInputBundle(rghtSufVal);
                cir.addInputBundle(leftSufBit);
                cir.addInputBundle(rghtSufBit);
            }
            if (type & Type::Prefix)
            {
                cir.addOutputBundle(prntPreVal);
                cir.addOutputBundle(prntPreBit);
            }
            if (type & Type::Suffix)
            {
                cir.addOutputBundle(prntSufVal);
                cir.addOutputBundle(prntSufBit);
            }

            cir.addTempWireBundle(temp1);
            cir.addTempWireBundle(temp2);


            // Apply the computation.
            oc::BetaLibrary lib;

            if (type & Type::Prefix)
            {

                for (int w : leftPreVal)
                {
                    auto flag = cir.mWireFlags[w];
                    if (flag == oc::BetaWireFlag::Uninitialized)
                        throw RTE_LOC;
                }
                for (int w : rghtPreVal)
                {
                    auto flag = cir.mWireFlags[w];
                    if (flag == oc::BetaWireFlag::Uninitialized)
                        throw RTE_LOC;
                }

                add(cir, leftPreVal, rghtPreVal, temp1);

                cir << "B0    " << leftPreVal << "\n";
                cir << "B1    " << rghtPreVal << "\n";
                cir << "B0+B1 " << temp1 << "\n";
                cir << "P1    " << rghtPreBit << "\n";
                //cir << "temp  " << std::to_string(temp1[0]) << " .. " << std::to_string(temp1.back()) << "\n16";

                lib.multiplex_build(cir, temp1, rghtPreVal, rghtPreBit, prntPreVal, temp2);
                cir.addGate(leftPreBit[0], rghtPreBit[0], oc::GateType::And, prntPreBit[0]);

                cir << "B     " << prntPreVal << "\n\n";

            }

            if (type & Type::Suffix)
            {
                add(cir, leftSufVal, rghtSufVal, temp1);

                cir << "UP ****\n";
                cir << "B0    " << leftSufVal << "\n";
                cir << "B1    " << rghtSufVal << "\n";
                cir << "B0+B1 " << temp1 << "\n";
                cir << "P0    " << leftSufBit << "\n";


                lib.multiplex_build(cir, temp1, leftSufVal, leftSufBit, prntSufVal, temp2);
                cir.addGate(leftSufBit[0], rghtSufBit[0], oc::GateType::And, prntSufBit[0]);

                cir << "B     " << prntSufVal << "\n";
            }

            return cir;
        }


        // Perform the upstream computation. Here we want to compute several
        // values for each node of the tree. Each node will hold 
        // 
        //  push up value val, left child value v0, a product preVal
        //
        // The value will be val=v_{1+p1} where v0,v1 are the left and right child
        // values. The product preVal will be preVal=p0*p1 where p0,p1 are the left and 
        // right child product values.  
        //
        // At the leaf level val will be the corresponding input value. preVal will be
        // the control bit to the leaf'sufVal right. I.e., for leaf i, preVal = controlBit[i-1] 
        // and preVal will be zero for the left most leaf (i.e. i=0).
        //
        // For each level of the tree, starting at the preSuf, we compute the 
        // parent values as described.
        void upstream(
            const BinMatrix& src,
            const BinMatrix& controlBits,
            const Operator& op,
            u64 partyIdx,
            Type type,
            coproto::Socket& comm,
            OleGenerator& gen,
            Level& root,
            span<SplitLevel> levels)
        {
            if (src.numEntries() != controlBits.numEntries())
                throw RTE_LOC;

            u64 bitsPerEntry = src.bitsPerEntry();

            u64 n = src.numEntries();
            u64 logfn = oc::log2floor(n);
            u64 logn = oc::log2ceil(n);

            if (logfn != logn)
            {
                // round n16 to a multiple of 16 to make lading values easy.
                n = oc::roundUpTo(n, 16);
                logfn = oc::log2floor(n);
                logn = oc::log2ceil(n);
            }

            // load the values of the leafs. Its possible that we need to split
            // these values across two levels of the tree (non-power of 2 input lengths).
            if (logfn == logn)
            {
                levels[0][0].resize(n / 2, bitsPerEntry, type);
                levels[0][1].resize(n / 2, bitsPerEntry, type);

                setLeafVals(src, controlBits, levels[0],
                    0, 0, n, type);

            }
            else
            {
                // split the leaf values across two levels of the tree.
                auto r = n - (1ull << logfn);
                auto n0 = 2 * r;
                auto n1 = n - n0;

                levels[0][0].resize(n0 / 2, bitsPerEntry, type);
                levels[0][1].resize(n0 / 2, bitsPerEntry, type);
                levels[1][0].resize((1ull << logfn) / 2, bitsPerEntry, type);
                levels[1][1].resize((1ull << logfn) / 2, bitsPerEntry, type);

                setLeafVals(src, controlBits, levels[0], 0, 0, n0, type);
                setLeafVals(src, controlBits, levels[1], n0, r, n1, type);
            }



            Gmw bin;

            auto cir = upstreamCir(bitsPerEntry, type, op);
            // we start at the preSuf and move up.
            for (u64 lvl = 0; lvl < logn; ++lvl)
            {
                auto& children = levels[lvl];
                auto& parent = root;
                u64 size = (type & Type::Prefix) ? levels[lvl][0].mPreBit.numEntries() : levels[lvl][0].mSufBit.numEntries();


                if (type & Type::Prefix)
                {
                    parent.mPreVal.resize(size, bitsPerEntry, 4);
                    parent.mPreBit.resize(size, 1, 4);
                }
                if (type & Type::Suffix)
                {
                    parent.mSufVal.resize(size, bitsPerEntry, 4);
                    parent.mSufBit.resize(size, 1, 4);
                }

                bin.init(size, cir, gen);


                u64 inIdx = 0, outIdx = 0;
                if (type & Type::Prefix)
                {
                    bin.mapInput(inIdx++, children[0].mPreVal);
                    bin.mapInput(inIdx++, children[1].mPreVal);
                    bin.mapInput(inIdx++, children[0].mPreBit);
                    bin.mapInput(inIdx++, children[1].mPreBit);
                    bin.mapOutput(outIdx++, parent.mPreVal);
                    bin.mapOutput(outIdx++, parent.mPreBit);
                }
                if (type & Type::Suffix)
                {
                    bin.mapInput(inIdx++, children[0].mSufVal);
                    bin.mapInput(inIdx++, children[1].mSufVal);
                    bin.mapInput(inIdx++, children[0].mSufBit);
                    bin.mapInput(inIdx++, children[1].mSufBit);
                    bin.mapOutput(outIdx++, parent.mSufVal);
                    bin.mapOutput(outIdx++, parent.mSufBit);
                }

                // eval
                bin.run(comm);


                if (size != 1)
                {
                    auto& splitParent = levels[lvl + 1];
                    auto d = logn - lvl - 2;
                    auto s = 1ull << d;
                    splitParent[0].resize(s, bitsPerEntry, type);
                    splitParent[1].resize(s, bitsPerEntry, type);

                    if (type & Type::Prefix)
                    {
                        perfectUnshuffle(parent.mPreVal, splitParent[0].mPreVal, splitParent[1].mPreVal);
                        perfectUnshuffle(parent.mPreBit, splitParent[0].mPreBit, splitParent[1].mPreBit);
                        assert(splitParent[0].mPreBit.numEntries());
                        assert(splitParent[1].mPreBit.numEntries());
                        assert(splitParent[0].mPreVal.numEntries());
                        assert(splitParent[1].mPreVal.numEntries());

                    }

                    if (type & Type::Suffix)
                    {
                        perfectUnshuffle(parent.mSufVal, splitParent[0].mSufVal, splitParent[1].mSufVal);
                        perfectUnshuffle(parent.mSufBit, splitParent[0].mSufBit, splitParent[1].mSufBit);
                        assert(splitParent[0].mSufBit.numEntries());
                        assert(splitParent[1].mSufBit.numEntries());
                        assert(splitParent[0].mSufVal.numEntries());
                        assert(splitParent[1].mSufVal.numEntries());
                    }

                }
                else
                {
                    assert(lvl == logn - 1);
                }

            }
        }

        /* this circuit pushes values down the tree.

                       |  pre, suf, _
                       |
                       *
                      / \
                     /   \
                    /     \
              pre_0,      pre_1
              suf_0,      suf_1
              p_0,        p_1

           These values are updated as
             pre_1 := p_0 ? pre_0 + pre : pre_0
             pre_0 := pre
             suf_0 := suf_1 + suf : suf_1
             suf_1 := suf
        */
        //	static oc::BetaCircuit downstreamCir(u64 bitsPerEntry, const Operator& op, Type type)
        //	{
        //		oc::BetaCircuit cir;

        //		//auto inSize = TreeRecord::recordBitCount(bitsPerEntry, type);
        //		oc::BetaBundle //in(inSize), inC(2 * inSize), out(2 * inSize),
        //			temp1(bitsPerEntry), temp2(bitsPerEntry);
        //		using namespace oc;

        //		BetaBundle preLeftVal(bitsPerEntry);
        //		BetaBundle sufRghtVal(bitsPerEntry);

        //		BetaBundle preLeftVal_out(bitsPerEntry);
        //		BetaBundle preRghtVal_out(bitsPerEntry);
        //		BetaBundle sufLeftVal_out(bitsPerEntry);
        //		BetaBundle sufRghtVal_out(bitsPerEntry);

        //		BetaBundle preLeftBit(1);
        //		BetaBundle sufRghtBit(1);

        //		BetaBundle prePrntVal(bitsPerEntry);
        //		BetaBundle sufPrntVal(bitsPerEntry);

        //		if (type & Type::Prefix)
        //		{
        //			cir.addInputBundle(preLeftVal);
        //			cir.addInputBundle(preLeftBit);
        //			cir.addInputBundle(prePrntVal);
        //		}

        //		if (type & Type::Suffix)
        //		{
        //			cir.addInputBundle(sufRghtVal);
        //			cir.addInputBundle(sufRghtBit);
        //			cir.addInputBundle(sufPrntVal);
        //		}

        //		if (type & Type::Prefix)
        //		{
        //			cir.addOutputBundle(preLeftVal_out);
        //			cir.addOutputBundle(preRghtVal_out);
        //		}
        //		if (type & Type::Suffix)
        //		{
        //			cir.addOutputBundle(sufLeftVal_out);
        //			cir.addOutputBundle(sufRghtVal_out);
        //		}


        //		// out is both input and output...
        //		//cir.mOutputs.push_back(out);
        //		cir.addTempWireBundle(temp1);
        //		cir.addTempWireBundle(temp2);


        //		oc::BetaLibrary lib;

        //		if (type & Type::Prefix)
        //		{
        //			cir << "down---  \n";
        //			cir << "B0    " << preLeftVal << " " << std::to_string(preLeftVal[0]) << " .. " << std::to_string(preLeftVal.back()) << "\n";
        //			//cir << "B1    " << preRghtVal << "\n16";
        //			cir << "B     " << prePrntVal << "\n";
        //			cir << "P0    " << preLeftBit << "\n";

        //			op(cir, prePrntVal, preLeftVal, temp1);
        //			{
        //				auto& ifFalse = preLeftVal;
        //				auto& ifTrue = temp1;
        //				auto& cd = cir;
        //				auto& choice = preLeftBit; //leftIn.mPreProd;
        //				auto& out = preRghtVal_out; //rightOut.mPrefix;
        //				//lib.multiplex_build(cir, temp1, left.mPrefix, left.mPreProd, right.mPrefix, t2);
        //				for (u64 i = 0; i < out.mWires.size(); ++i)
        //					cd.addGate(ifFalse.mWires[i], ifTrue.mWires[i], oc::GateType::Xor, temp2.mWires[i]);
        //				//cd.addPrint("a^preBit  [" + std::to_string(i) + "] = ");
        //				//cd.addPrint(temp.mWires[0]);
        //				//cd.addPrint("\n16");

        //				for (u64 i = 0; i < out.mWires.size(); ++i)
        //					cd.addGate(temp2.mWires[i], choice.mWires[0], oc::GateType::And, temp1.mWires[i]);

        //				//cd.addPrint("a^preBit&sufVal[" + std::to_string(i) + "] = ");
        //				//cd.addPrint(temp.mWires[0]);
        //				//cd.addPrint("\n16");

        //				for (u64 i = 0; i < out.mWires.size(); ++i)
        //					cd.addGate(ifFalse.mWires[i], temp1.mWires[i], oc::GateType::Xor, out.mWires[i]);
        //			}

        //			cir.addCopy(prePrntVal, preLeftVal_out);

        //			cir << "B0*   " << preLeftVal_out << "\n";
        //			cir << "B1*   " << preRghtVal_out << "\n";

        //		}
        //		if (type & Type::Suffix)
        //		{


        //			cir << "down suf---  \n";
        //			//cir << "B0    " << leftIn.mSuffix << "\n16";
        //			//cir << "temp  " <<  << "\n16";
        //			cir << "B1    " << sufRghtVal << "\n";
        //			cir << "B     " << sufPrntVal << "\n";
        //			cir << "P1    " << sufRghtBit << "\n";
        //			op(cir, sufRghtVal, sufPrntVal, temp1);
        //			//lib.multiplex_build(cir, temp1, right.mSuffix, right.mSufProd, left.mSuffix, temp2);
        //			{
        //				auto& ifFalse = sufRghtVal;
        //				auto& ifTrue = temp1;
        //				auto& cd = cir;
        //				auto& choice = sufRghtBit;
        //				auto& out = sufLeftVal_out;
        //				//lib.multiplex_build(cir, temp1, left.mPrefix, left.mPreProd, right.mPrefix, t2);
        //				for (u64 i = 0; i < out.mWires.size(); ++i)
        //					cd.addGate(ifFalse.mWires[i], ifTrue.mWires[i], oc::GateType::Xor, temp2.mWires[i]);
        //				//cd.addPrint("a^preBit  [" + std::to_string(i) + "] = ");
        //				//cd.addPrint(temp.mWires[0]);
        //				//cd.addPrint("\n16");

        //				for (u64 i = 0; i < out.mWires.size(); ++i)
        //					cd.addGate(temp2.mWires[i], choice.mWires[0], oc::GateType::And, temp1.mWires[i]);

        //				//cd.addPrint("a^preBit&sufVal[" + std::to_string(i) + "] = ");
        //				//cd.addPrint(temp.mWires[0]);
        //				//cd.addPrint("\n16");

        //				for (u64 i = 0; i < out.mWires.size(); ++i)
        //					cd.addGate(ifFalse.mWires[i], temp1.mWires[i], oc::GateType::Xor, out.mWires[i]);
        //			}
        //			cir.addCopy(sufPrntVal, sufRghtVal_out);


        //			cir << "B0*   " << sufLeftVal_out << "\n";
        //			cir << "B1*   " << sufRghtVal_out << "\n";
        //		}

        //		return cir;
        //	}


        //	// apply the downstream circuit to each level of the tree.
        //	void downstream(
        //		const BinMatrix& src,
        //		const BinMatrix& controlBits,
        //		const Operator& op,
        //		Level& root,
        //		span<::std::array<Level, 2>> levels,
        //		::std::array<Level, 2>& preSuf,
        //		std::array<Level, 2>& vals,
        //		u64 partyIdx,
        //		Type type,
        //		CommPkg& comm,
        //		Sh3ShareGen& gen)
        //	{
        //		u64 bitsPerEntry = src.bitsPerEntry();
        //		//u64 inSize = TreeRecord::recordBitCount(bitsPerEntry, type);

        //		std::vector<::std::array<Level, 2>> debugLevels(mDebug * levels.size());


        //		u64 n16 = src.rows();
        //		u64 logfn = oc::log2floor(n16);
        //		u64 logn = oc::log2ceil(n16);

        //		if (logfn != logn)
        //		{
        //			n16 = oc::roundUpTo(n16, 16);
        //			logfn = oc::log2floor(n16);
        //			logn = oc::log2ceil(n16);
        //		}
        //		auto r = n16 - (1ull << logfn);
        //		assert(r % 8 == 0);
        //		auto n0 = 2 * r;
        //		auto n1 = n16 - n0;

        //		auto n1_16 = n1 / 16;
        //		auto n0_16 = n0 / 16;
        //		auto r16 = r / 16;

        //		auto nodeCir = downstreamCir(bitsPerEntry, op, type);

        //		vals[0].resize(n16 / 2, bitsPerEntry, type);
        //		vals[1].resize(n16 / 2, bitsPerEntry, type);
        //		//vals[0].mPreVal.reset(n16 / 2, bitsPerEntry, 4);
        //		//vals[1].mPreVal.reset(n16 / 2, bitsPerEntry, 4);
        //		if (type & Type::Prefix)
        //		{
        //			//vals[0].mPreBit.reset(n16 / 2, 1, 4);
        //			//vals[1].mPreBit.reset(n16 / 2, 1, 4);
        //			preSuf[0].mPreVal.reset(n16 / 2, bitsPerEntry, 4);
        //			preSuf[1].mPreVal.reset(n16 / 2, bitsPerEntry, 4);
        //		}
        //		if (type & Type::Suffix)
        //		{
        //			//vals[0].mSufBit.reset(n16 / 2, 1, 4);
        //			//vals[1].mSufBit.reset(n16 / 2, 1, 4);
        //			preSuf[0].mSufVal.reset(n16 / 2, bitsPerEntry, 4);
        //			preSuf[1].mSufVal.reset(n16 / 2, bitsPerEntry, 4);
        //		}
        //		BinEval bin;

        //		// we start at the root and move down.
        //		for (u64 pLvl = logn; pLvl != 0; --pLvl)
        //		{
        //			auto size = (type & Type::Prefix) ? root.mPreVal.numEntries() : root.mSufVal.numEntries();
        //			auto& parent = root;

        //			auto cLvl = pLvl - 1;
        //			auto& children = levels[cLvl];

        //			bool firstPartial = logn != logfn && cLvl == 1;
        //			bool secondPartial = logn != logfn && cLvl == 0;
        //			bool full = logn == logfn && cLvl == 0;

        //			//bin.enableDebug(partyIdx, -1, comm.mPrev.getSession().addChannel(), comm.mNext.getSession().addChannel());
        //			bin.setCir(nodeCir, size, partyIdx, gen, false, 0);

        //			u64 inIdx = 0, outIdx = 0;
        //			if (type & Type::Prefix)
        //			{
        //				// prefix only takes the left child and parent as input
        //				bin.mapInput(inIdx++, children[0].mPreVal);
        //				bin.mapInput(inIdx++, children[0].mPreBit);
        //				bin.mapInput(inIdx++, parent.mPreVal);

        //				preSuf[0].mPreVal.reshape(size);
        //				preSuf[1].mPreVal.reshape(size);

        //				// left and right child output
        //				bin.mapOutput(outIdx++, preSuf[0].mPreVal);
        //				bin.mapOutput(outIdx++, preSuf[1].mPreVal);
        //			}

        //			if (type & Type::Suffix)
        //			{
        //				// prefix only takes the right child and parent as input
        //				bin.mapInput(inIdx++, children[1].mSufVal);
        //				bin.mapInput(inIdx++, children[1].mSufBit);
        //				bin.mapInput(inIdx++, parent.mSufVal);

        //				preSuf[0].mSufVal.reshape(size);
        //				preSuf[1].mSufVal.reshape(size);

        //				// left and right child output
        //				bin.mapOutput(outIdx++, preSuf[0].mSufVal);
        //				bin.mapOutput(outIdx++, preSuf[1].mSufVal);
        //			}

        //			// eval
        //			bin.evaluate(comm);

        //			if (mDebug)
        //			{
        //				debugLevels[cLvl][0].mPreVal = preSuf[0].mPreVal;
        //				debugLevels[cLvl][1].mPreVal = preSuf[1].mPreVal;
        //				debugLevels[cLvl][0].mSufVal = preSuf[0].mSufVal;
        //				debugLevels[cLvl][1].mSufVal = preSuf[1].mSufVal;
        //			}

        //			if (cLvl)
        //			{
        //				auto& nextChildren = levels[cLvl - 1];
        //				if (type & Type::Prefix)
        //				{
        //					parent.mPreVal.reset(nextChildren[0].mPreVal.numEntries(), bitsPerEntry, 4);

        //					//assert(logn == logfn);
        //					auto old = preSuf[0].mPreVal.numEntries();
        //					preSuf[0].mPreVal.reshape(parent.mPreVal.numEntries() / 2);
        //					preSuf[1].mPreVal.reshape(parent.mPreVal.numEntries() / 2);
        //					perfectShuffle(preSuf[0].mPreVal, preSuf[1].mPreVal, parent.mPreVal);

        //					//assert(logn == logfn);
        //					preSuf[0].mPreVal.reshape(old);
        //					preSuf[1].mPreVal.reshape(old);
        //				}

        //				if (type & Type::Suffix)
        //				{
        //					parent.mSufVal.reset(nextChildren[0].mSufVal.numEntries(), bitsPerEntry, 4);

        //					//assert(logn == logfn);
        //					auto old = preSuf[0].mSufVal.numEntries();
        //					preSuf[0].mSufVal.reshape(parent.mSufVal.numEntries() / 2);
        //					preSuf[1].mSufVal.reshape(parent.mSufVal.numEntries() / 2);
        //					perfectShuffle(preSuf[0].mSufVal, preSuf[1].mSufVal, parent.mSufVal);

        //					//assert(logn == logfn);
        //					preSuf[0].mSufVal.reshape(old);
        //					preSuf[1].mSufVal.reshape(old);
        //				}
        //			}


        //			auto shiftBytes = [](TBinMatrix& src, u64 srcStart, u64 dstStart, u64 size) {

        //				auto bitsPerEntry = src.bitsPerEntry();
        //				for (u64 k = 0; k < bitsPerEntry; ++k)
        //				{
        //					// shift the preSuf values down.
        //					for (u64 j = 0; j < 2; ++j)
        //					{
        //						auto s0 = ((u8*)src.mShares[j][k].data()) + srcStart;
        //						auto d0 = ((u8*)src.mShares[j][k].data()) + dstStart;
        //						auto max = src.mShares[j][k].size() * sizeof(*src.mShares[j][k].data());
        //						auto e = (u8*)(src.mShares[j][k].data() + src.mShares[j][k].size());
        //						auto t = (u8*)(src.mShares[j][k].data()) + max;

        //						assert(dstStart + size < max);
        //						assert(d0 + size <= e);
        //						assert(s0 + size <= e);
        //						assert(e == t);
        //						assert(dstStart > srcStart);
        //						// copy in reverse since the buffers can overlap
        //						for (u64 i = size - 1; i < size; --i)
        //							d0[i] = s0[i];
        //					}
        //				}
        //			};

        //			auto copyBytes = [](TBinMatrix& src, TBinMatrix& dst, u64 srcStart, u64 dstStart, u64 size)
        //			{
        //				auto bitsPerEntry = src.bitsPerEntry();
        //				assert(dst.bitsPerEntry() == bitsPerEntry);
        //				for (u64 k = 0; k < bitsPerEntry; ++k)
        //				{
        //					for (u64 j = 0; j < 2; ++j)
        //					{
        //						auto s0 = ((u8*)src.mShares[j][k].data()) + srcStart;
        //						auto d0 = ((u8*)dst.mShares[j][k].data()) + dstStart;
        //						//auto max = src.mShares[j][k].size() * sizeof(*src.mShares[j][k].data());
        //						auto es = (u8*)(src.mShares[j][k].data() + src.mShares[j][k].size());
        //						auto ed = (u8*)(dst.mShares[j][k].data() + dst.mShares[j][k].size());
        //						//assert(dstStart + size < max);
        //						assert(d0 + size <= ed);
        //						assert(s0 + size <= es);
        //						memcpy(d0, s0, size);
        //					}
        //				}
        //			};

        //			// if we have a partial level, then we need to copy 
        //			// the initial leaf values to vals that are on the 
        //			// second to last level. We will effectively do the
        //			// same for preSuf by shifting the bytes down.
        //			for (u64 j = 0; j < 2 * firstPartial; ++j)
        //			{
        //				if (type & Type::Prefix)
        //				{
        //					assert(cLvl == 1);
        //					// shift the preSuf values down.
        //					shiftBytes(preSuf[j].mPreVal, r16, n0_16, n1_16);

        //					// copy the leaf values
        //					copyBytes(levels[cLvl][j].mPreVal, vals[j].mPreVal, r16, n0_16, n1_16);
        //					copyBytes(levels[cLvl][j].mPreBit, vals[j].mPreBit, r16, n0_16, n1_16);
        //				}

        //				if (type & Type::Suffix)
        //				{
        //					// shift the preSuf values down.
        //					shiftBytes(preSuf[j].mSufVal, r16, n0_16, n1_16);

        //					// copy the leaf values
        //					copyBytes(levels[cLvl][j].mSufVal, vals[j].mSufVal, r16, n0_16, n1_16);
        //					copyBytes(levels[cLvl][j].mSufBit, vals[j].mSufBit, r16, n0_16, n1_16);
        //				}
        //			}

        //			// copy the leaf values that are on the last (partial) level
        //			for (u64 j = 0; j < 2 * secondPartial; ++j)
        //			{
        //				if (type & Type::Prefix)
        //				{
        //					assert(cLvl == 0);
        //					copyBytes(levels[cLvl][j].mPreVal, vals[j].mPreVal, 0, 0, n0_16);
        //					copyBytes(levels[cLvl][j].mPreBit, vals[j].mPreBit, 0, 0, n0_16);

        //					preSuf[j].mPreVal.reshape(n16 / 2);

        //				}

        //				if (type & Type::Suffix)
        //				{
        //					copyBytes(levels[cLvl][j].mSufVal, vals[j].mSufVal, 0, 0, n0_16);
        //					copyBytes(levels[cLvl][j].mSufBit, vals[j].mSufBit, 0, 0, n0_16);
        //					preSuf[j].mSufVal.reshape(n16 / 2);
        //				}
        //			}

        //			// the last level is a full level, we can just move the values.
        //			for (u64 j = 0; j < 2 * full; ++j)
        //			{
        //				if (mDebug)
        //					vals[j] = levels[0][j];
        //				else
        //					vals[j] = std::move(levels[0][j]);
        //			}
        //		}


        //		if (mDebug)
        //		{
        //			for (u64 i = 0; i < levels.size(); ++i)
        //				levels[i] = std::move(debugLevels[i]);
        //		}
        //	}


        //	// apply the downstream circuit to each level of the tree.
        //	void computeLeaf(
        //		std::array<Level, 2>& leaves,
        //		std::array<Level, 2>& preSuf,
        //		const Operator& op,
        //		BinMatrix& dst,
        //		u64 partyIdx,
        //		Type type,
        //		CommPkg& comm,
        //		Sh3ShareGen& gen)
        //	{
        //		u64 n = dst.rows();

        //		oc::BetaLibrary lib;
        //		oc::BetaCircuit cir;
        //		auto bitsPerEntry = (type & Type::Prefix) ? leaves[0].mPreVal.bitsPerEntry() : leaves[0].mSufVal.bitsPerEntry();
        //		auto size = (type & Type::Prefix) ? leaves[0].mPreBit.numEntries() : leaves[0].mSufBit.numEntries();

        //		{
        //			oc::BetaBundle
        //				leftVal(bitsPerEntry),
        //				leftPreVal(bitsPerEntry),
        //				leftSufVal(bitsPerEntry),
        //				leftPreBit(1),
        //				leftSufBit(1),
        //				leftOut(bitsPerEntry),

        //				rghtVal(bitsPerEntry),
        //				rghtPreVal(bitsPerEntry),
        //				rghtSufVal(bitsPerEntry),
        //				rghtPreBit(1),
        //				rghtSufBit(1),
        //				rghtOut(bitsPerEntry),

        //				lt1(bitsPerEntry),
        //				lt2(bitsPerEntry),
        //				lt3(bitsPerEntry),

        //				rt1(bitsPerEntry),
        //				rt2(bitsPerEntry),
        //				rt3(bitsPerEntry);

        //			cir.addInputBundle(leftVal);
        //			cir.addInputBundle(rghtVal);
        //			if (type & Type::Prefix)
        //			{
        //				cir.addInputBundle(leftPreVal);
        //				cir.addInputBundle(rghtPreVal);
        //				cir.addInputBundle(leftPreBit);
        //				cir.addInputBundle(rghtPreBit);
        //			}
        //			if (type & Type::Suffix)
        //			{
        //				cir.addInputBundle(leftSufVal);
        //				cir.addInputBundle(rghtSufVal);
        //				cir.addInputBundle(leftSufBit);
        //				cir.addInputBundle(rghtSufBit);
        //			}

        //			cir.addOutputBundle(leftOut);
        //			cir.addOutputBundle(rghtOut);

        //			cir.addTempWireBundle(lt1);
        //			cir.addTempWireBundle(lt2);
        //			cir.addTempWireBundle(lt3);
        //			cir.addTempWireBundle(rt1);
        //			cir.addTempWireBundle(rt2);
        //			cir.addTempWireBundle(rt3);

        //			switch (type)
        //			{
        //			case aby3::AggTree::Prefix:
        //				op(cir, leftPreVal, leftVal, lt1);
        //				op(cir, rghtPreVal, rghtVal, rt1);
        //				lib.multiplex_build(cir, lt1, leftVal, leftPreBit, leftOut, lt2);
        //				lib.multiplex_build(cir, rt1, rghtVal, rghtPreBit, rghtOut, rt2);

        //				//cir << "\ncir " << leftVal << " " << leftPreVal << " " << leftPreBit << " -> " << leftOut << "\n16";
        //				break;
        //			case aby3::AggTree::Suffix:
        //				op(cir, leftVal, leftSufVal, lt1);
        //				op(cir, rghtVal, rghtSufVal, rt1);
        //				lib.multiplex_build(cir, lt1, leftVal, leftSufBit, leftOut, lt2);
        //				lib.multiplex_build(cir, rt1, rghtVal, rghtSufBit, rghtOut, rt2);
        //				break;
        //			case aby3::AggTree::Full:
        //				// t1 = preVal + val;
        //				op(cir, leftPreVal, leftVal, lt1);
        //				op(cir, rghtPreVal, rghtVal, rt1);

        //				// t3 = preBit ? preVal + val : val;
        //				lib.multiplex_build(cir, lt1, leftVal, leftPreBit, lt3, lt2);
        //				lib.multiplex_build(cir, rt1, rghtVal, rghtPreBit, rt3, rt2);

        //				// t1 = t3 + sufVal;
        //				op(cir, lt3, leftSufVal, lt1);
        //				op(cir, rt3, rghtSufVal, rt1);

        //				// out = sufBit ? t3 + sufVal : t3;
        //				//     = preVal + val + sufVal    ~ preBit=1,sufBit=1
        //				//     = preVal + val             ~ preBit=1,sufBit=0
        //				//     =          val + sufVal    ~ preBit=0,sufBit=1
        //				//     =          val             ~ preBit=0,sufBit=0
        //				lib.multiplex_build(cir, lt1, lt3, leftSufBit, leftOut, lt2);
        //				lib.multiplex_build(cir, rt1, rt3, rghtSufBit, rghtOut, rt2);

        //				break;
        //			default:
        //				throw RTE_LOC;
        //				break;
        //			}
        //		}


        //		BinEval bin;

        //		bin.setCir(cir, size, partyIdx, gen, false, -1);
        //		int inIdx = 0;

        //		// the input values v for each leaf node.
        //		if (type & Type::Prefix)
        //		{
        //			bin.mapInput(inIdx++, leaves[0].mPreVal);
        //			bin.mapInput(inIdx++, leaves[1].mPreVal);
        //		}
        //		else
        //		{
        //			bin.mapInput(inIdx++, leaves[0].mSufVal);
        //			bin.mapInput(inIdx++, leaves[1].mSufVal);
        //		}

        //		if (type & Type::Prefix)
        //		{
        //			// prefix val
        //			bin.mapInput(inIdx++, preSuf[0].mPreVal);
        //			bin.mapInput(inIdx++, preSuf[1].mPreVal);

        //			// prefix bit
        //			bin.mapInput(inIdx++, leaves[0].mPreBit);
        //			bin.mapInput(inIdx++, leaves[1].mPreBit);

        //		}

        //		if (type & Type::Suffix)
        //		{
        //			// prefix val
        //			bin.mapInput(inIdx++, preSuf[0].mSufVal);
        //			bin.mapInput(inIdx++, preSuf[1].mSufVal);

        //			// prefix bit					 
        //			bin.mapInput(inIdx++, leaves[0].mSufBit);
        //			bin.mapInput(inIdx++, leaves[1].mSufBit);
        //		}



        //		bin.evaluate(comm);

        //		BinMatrix leftOut(size, bitsPerEntry), rghtOut(size, bitsPerEntry);
        //		bin.getOutput(0, leftOut);
        //		bin.getOutput(1, rghtOut);

        //		auto d0 = &dst.mShares[0](0);
        //		auto d1 = &dst.mShares[1](0);
        //		auto l0 = &leftOut.mShares[0](0);
        //		auto l1 = &leftOut.mShares[1](0);
        //		auto r0 = &rghtOut.mShares[0](0);
        //		auto r1 = &rghtOut.mShares[1](0);
        //		auto s1 = dst.i64Cols();
        //		auto n2 = n / 2;
        //		for (u64 i = 0; i < n2; ++i)
        //		{
        //			assert(d0 + s1 <= dst.mShares[0].data() + dst.mShares[0].size());
        //			assert(d1 + s1 <= dst.mShares[1].data() + dst.mShares[1].size());
        //			assert(l0 + s1 <= leftOut.mShares[0].data() + leftOut.mShares[0].size());
        //			assert(l1 + s1 <= leftOut.mShares[1].data() + leftOut.mShares[1].size());
        //			assert(r0 + s1 <= rghtOut.mShares[0].data() + rghtOut.mShares[0].size());
        //			assert(r1 + s1 <= rghtOut.mShares[1].data() + rghtOut.mShares[1].size());

        //			memcpy(d0, l0, s1 * sizeof(i64)); d0 += s1; l0 += s1;
        //			memcpy(d1, l1, s1 * sizeof(i64)); d1 += s1; l1 += s1;
        //			memcpy(d0, r0, s1 * sizeof(i64)); d0 += s1; r0 += s1;
        //			memcpy(d1, r1, s1 * sizeof(i64)); d1 += s1; r1 += s1;
        //		}

        //		if (n & 1)
        //		{
        //			auto k = n - 1, i = n / 2;
        //			for (u64 j = 0; j < dst.i64Cols(); ++j)
        //			{
        //				dst.mShares[0](k + 0, j) = leftOut.mShares[0](i, j);
        //				dst.mShares[1](k + 0, j) = leftOut.mShares[1](i, j);
        //			}
        //		}
        //	}

        //};












        //struct DLevel
        //{
        //	BinMatrix mPreVal, mSufVal, mPreBit, mSufBit;


        //	void load(std::array<AggTree::Level, 2>& tvs)
        //	{
        //		Sh3Converter conv;

        //		auto m = std::max<u64>(tvs[0].mPreVal.bitsPerEntry(), tvs[1].mSufVal.bitsPerEntry());

        //		BinMatrix preVal[2], sufVal[2], preBit[2], sufBit[2];
        //		conv.toBinaryMatrix(tvs[0].mPreVal, preVal[0]);
        //		conv.toBinaryMatrix(tvs[1].mPreVal, preVal[1]);
        //		conv.toBinaryMatrix(tvs[0].mPreBit, preBit[0]);
        //		conv.toBinaryMatrix(tvs[1].mPreBit, preBit[1]);
        //		conv.toBinaryMatrix(tvs[0].mSufVal, sufVal[0]);
        //		conv.toBinaryMatrix(tvs[1].mSufVal, sufVal[1]);
        //		conv.toBinaryMatrix(tvs[0].mSufBit, sufBit[0]);
        //		conv.toBinaryMatrix(tvs[1].mSufBit, sufBit[1]);

        //		preVal[0].trim();
        //		preVal[1].trim();
        //		preBit[0].trim();
        //		preBit[1].trim();

        //		sufVal[0].trim();
        //		sufVal[1].trim();
        //		sufBit[0].trim();
        //		sufBit[1].trim();

        //		mPreVal.resize(preVal[0].rows() + preVal[1].rows(), m);
        //		mPreBit.resize(preBit[0].rows() + preBit[1].rows(), 1);
        //		mSufVal.resize(sufVal[0].rows() + sufVal[1].rows(), m);
        //		mSufBit.resize(sufBit[0].rows() + sufBit[1].rows(), 1);

        //		for (u64 j = 0; j < mPreVal[0].rows(); ++j)
        //		{
        //			for (u64 l = 0; l < 2; ++l)
        //			{
        //				for (u64 k = 0; k < mPreVal.i64Cols(); ++k)
        //					mPreVal.mShares[l](j, k) = preVal[j & 1].mShares[l](j / 2, k);

        //				if (mPreBit.rows())
        //					mPreBit.mShares[l](j) = preBit[j & 1].mShares[l](j / 2);
        //			}
        //		}
        //		for (u64 j = 0; j < mSufVal[0].rows(); ++j)
        //		{
        //			for (u64 l = 0; l < 2; ++l)
        //			{
        //				for (u64 k = 0; k < mSufVal.i64Cols(); ++k)
        //					mSufVal.mShares[l](j, k) = sufVal[j & 1].mShares[l](j / 2, k);

        //				if (mSufBit.rows())
        //					mSufBit.mShares[l](j) = sufBit[j & 1].mShares[l](j / 2);
        //			}
        //		}
        //	}


        //	void load(AggTree::Level& tvs)
        //	{
        //		Sh3Converter conv;
        //		conv.toBinaryMatrix(tvs.mPreVal, mPreVal);
        //		conv.toBinaryMatrix(tvs.mPreBit, mPreBit);
        //		conv.toBinaryMatrix(tvs.mSufVal, mSufVal);
        //		conv.toBinaryMatrix(tvs.mSufBit, mSufBit);
        //	}


    };



}