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

        bool mDebug = false;



        // the number of real inputs
        u64 n = 0;

        //the number of inputs rounded upto a power of 2 or multiple of 16
        u64 n16 = 0;

        // log2 floor of n16
        u64 logfn = 0;

        // log2 ceiling of n16
        u64 logn = 0;


        // the number of parents in the second partial level.
        u64 r = 0;

        // the number of leaves in the first partial level.
        u64 n0 = 0;

        // the number of leaves in the second partial level.
        u64 n1 = 0;

        // Here we compute various tree size parameters such as the depth
        // and the number of leaves on the lowest two levels (n0,n1).
        // 
        // for example, if we simply use n16=n=5, we get:
        // 
        //        *
        //    *       *
        //  *   *   *   *
        // * * 
        // 
        // logfn = 2 
        // logn  = 3
        // r     = 1     one parent one the second level (second partial).
        // n0    = 2     two leaves on the first level (first partial).
        // n1    = 3     three leaves on the first level (first partial).
        // 
        void computeTreeSizes(u64 n_)
        {
            n = n_;

            // the number of entries rounded up to a multiple of 16 or power of 2
            n16 = std::min(1ull << oc::log2ceil(n), oc::roundUpTo(n, 16));

            // log 2 floor
            logfn = oc::log2floor(n16);
            // log 2 ceiling 
            logn = oc::log2ceil(n16);

            // the size of the second level 
            auto secondPartial = (1ull << logfn);

            // the number of parents in the second level.
            r = n16 - secondPartial;

            // the size of the first level.
            n0 = 2 * r;

            // the number of leaves on the second level (if any)
            n1 = n16 - n0;

            assert(r % 8 == 0);
        }

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
        static void toPackedBin(const BinMatrix& in, TBinMatrix& dest,
            u64 srcRowStartIdx,
            u64 numRows);

        //static void setLeafVals2(
        //    u64 bitsPerEntry,
        //    oc::MatrixView<const u8> src,
        //    span<const u8> controlBits,
        //    SplitLevel& leaves,
        //    u64 dIdx,
        //    u64 size,
        //    Type type);


        //// load the leaf values and control bits. 
        //// src are the values, controlBits are ...
        //// leaves are where we will write the results.
        //// They are separated into left and right children.
        ////
        //// sIdx means that we should start copying values from
        //// src, controlBits at row sIdx.
        ////
        //// dIdx means that we should start writing results to
        //// leaf index dIdx.
        ////
        //// We require dIdx to be a multiple of 8 and therefore 
        //// we will pad the overall tree to be a multiple of 16.
        //// We will assign zero to the padded control bits.
        //static void setLeafVals2(
        //    const BinMatrix& src,
        //    const BinMatrix& controlBits,
        //    SplitLevel& leaves,
        //    u64 sIdx,
        //    u64 dIdx,
        //    u64 size,
        //    Type type);

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
        //static void setLeafVals(
        //    const BinMatrix& src,
        //    const BinMatrix& controlBits,
        //    SplitLevel& leaves,
        //    u64 sIdx,
        //    u64 dIdx,
        //    u64 size,
        //    Type type);

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
            const Operator& add);

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
        macoro::task<> upstream(
            const BinMatrix& src,
            const BinMatrix& controlBits,
            const Operator& op,
            u64 partyIdx,
            Type type,
            coproto::Socket& comm,
            OleGenerator& gen,
            Level& root,
            span<SplitLevel> levels);

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

           circuit inputs are
           - left Val
           - left bit
           - parent val
          
           outputs are:
           - left val
           - right val
          
           Prefix input outputs go first and then suffix. So the i/o above is repeated twice.
          
        */
        static oc::BetaCircuit downstreamCir(u64 bitsPerEntry, const Operator& op, Type type);


        // apply the downstream circuit to each level of the tree.
        macoro::task<> downstream(
            const BinMatrix& src,
            const BinMatrix& controlBits,
            const Operator& op,
            Level& root,
            span<SplitLevel> levels,
            SplitLevel& preSuf,
            SplitLevel& vals,
            u64 partyIdx,
            Type type,
            coproto::Socket& comm,
            OleGenerator& gen);

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