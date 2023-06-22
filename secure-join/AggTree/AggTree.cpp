#include "AggTree.h"


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

        for (u64 i = 0; i < in.bitsPerEntry(); ++i)
        {
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


    void AggTree::toPackedBin(const BinMatrix& in, TBinMatrix& dest,
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

    oc::BetaCircuit AggTree::upstreamCir(
        u64 bitsPerEntry,
        Type type,
        const Operator& add)
    {
        oc::BetaCircuit cir;

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


    macoro::task<> AggTree::upstream(
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
        MC_BEGIN(macoro::task<>, this, &src, &controlBits, &op, partyIdx, type, comm, &gen, &root, levels,
            bin = Gmw{},
            cir = oc::BetaCircuit{},
            bitsPerEntry = u64{},
            lvl = u64{},
            size = u64{}
        );
        if (src.numEntries() != controlBits.numEntries())
            throw RTE_LOC;

        computeTreeSizes(src.numEntries());

        bitsPerEntry = src.bitsPerEntry();

        // load the values of the leafs. Its possible that we need to split
        // these values across two levels of the tree (non-power of 2 input lengths).
        if (logfn == logn)
        {
            levels[0][0].resize(n / 2, bitsPerEntry, type);
            levels[0][1].resize(n / 2, bitsPerEntry, type);

            levels[0].setLeafVals(src, controlBits, 0, 0);
            //setLeafVals2(src, controlBits, levels[0],
            //    0, 0, n, type);

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

            levels[0].setLeafVals(src, controlBits, 0, 0);
            levels[1].setLeafVals(src, controlBits, n0, r);
            //setLeafVals2(src, controlBits, levels[0], 0, 0, n0, type);
            //setLeafVals2(src, controlBits, levels[1], n0, r, n1, type);
        }




        cir = upstreamCir(bitsPerEntry, type, op);
        // we start at the preSuf and move up.
        for (lvl = 0; lvl < logn; ++lvl)
        {
            size = (type & Type::Prefix) ? levels[lvl][0].mPreBit.numEntries() : levels[lvl][0].mSufBit.numEntries();

            {

                auto& children = levels[lvl];
                auto& parent = root;
                if (type & Type::Prefix)
                {
                    parent.mPreVal.resize(size, bitsPerEntry, 2 * sizeof(block));
                    parent.mPreBit.resize(size, 1, 2 * sizeof(block));
                }
                if (type & Type::Suffix)
                {
                    parent.mSufVal.resize(size, bitsPerEntry, 2 * sizeof(block));
                    parent.mSufBit.resize(size, 1, 2 * sizeof(block));
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
            }

            // eval
            MC_AWAIT(bin.run(comm));


            if (size != 1)
            {
                auto& parent = root;
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

        MC_END();
    }


    oc::BetaCircuit AggTree::downstreamCir(u64 bitsPerEntry, const Operator& op, Type type)
    {
        oc::BetaCircuit cir;

        //auto inSize = TreeRecord::recordBitCount(bitsPerEntry, type);
        oc::BetaBundle //in(inSize), inC(2 * inSize), out(2 * inSize),
            temp1(bitsPerEntry), temp2(bitsPerEntry);
        using namespace oc;

        BetaBundle preLeftVal(bitsPerEntry);
        BetaBundle sufRghtVal(bitsPerEntry);

        BetaBundle preLeftVal_out(bitsPerEntry);
        BetaBundle preRghtVal_out(bitsPerEntry);
        BetaBundle sufLeftVal_out(bitsPerEntry);
        BetaBundle sufRghtVal_out(bitsPerEntry);

        BetaBundle preLeftBit(1);
        BetaBundle sufRghtBit(1);

        BetaBundle prePrntVal(bitsPerEntry);
        BetaBundle sufPrntVal(bitsPerEntry);

        if (type & Type::Prefix)
        {
            cir.addInputBundle(preLeftVal);
            cir.addInputBundle(preLeftBit);
            cir.addInputBundle(prePrntVal);
        }

        if (type & Type::Suffix)
        {
            cir.addInputBundle(sufRghtVal);
            cir.addInputBundle(sufRghtBit);
            cir.addInputBundle(sufPrntVal);
        }

        if (type & Type::Prefix)
        {
            cir.addOutputBundle(preLeftVal_out);
            cir.addOutputBundle(preRghtVal_out);
        }
        if (type & Type::Suffix)
        {
            cir.addOutputBundle(sufLeftVal_out);
            cir.addOutputBundle(sufRghtVal_out);
        }


        // out is both input and output...
        //cir.mOutputs.push_back(out);
        cir.addTempWireBundle(temp1);
        cir.addTempWireBundle(temp2);


        oc::BetaLibrary lib;

        if (type & Type::Prefix)
        {
            cir << "down---  \n";
            cir << "B0    " << preLeftVal << " " << std::to_string(preLeftVal[0]) << " .. " << std::to_string(preLeftVal.back()) << "\n";
            //cir << "B1    " << preRghtVal << "\n16";
            cir << "B     " << prePrntVal << "\n";
            cir << "P0    " << preLeftBit << "\n";

            op(cir, prePrntVal, preLeftVal, temp1);
            {
                auto& ifFalse = preLeftVal;
                auto& ifTrue = temp1;
                auto& cd = cir;
                auto& choice = preLeftBit; //leftIn.mPreProd;
                auto& out = preRghtVal_out; //rightOut.mPrefix;
                //lib.multiplex_build(cir, temp1, left.mPrefix, left.mPreProd, right.mPrefix, t2);
                for (u64 i = 0; i < out.mWires.size(); ++i)
                    cd.addGate(ifFalse.mWires[i], ifTrue.mWires[i], oc::GateType::Xor, temp2.mWires[i]);
                //cd.addPrint("a^preBit  [" + std::to_string(i) + "] = ");
                //cd.addPrint(temp.mWires[0]);
                //cd.addPrint("\n16");

                for (u64 i = 0; i < out.mWires.size(); ++i)
                    cd.addGate(temp2.mWires[i], choice.mWires[0], oc::GateType::And, temp1.mWires[i]);

                //cd.addPrint("a^preBit&sufVal[" + std::to_string(i) + "] = ");
                //cd.addPrint(temp.mWires[0]);
                //cd.addPrint("\n16");

                for (u64 i = 0; i < out.mWires.size(); ++i)
                    cd.addGate(ifFalse.mWires[i], temp1.mWires[i], oc::GateType::Xor, out.mWires[i]);
            }

            cir.addCopy(prePrntVal, preLeftVal_out);

            cir << "B0*   " << preLeftVal_out << "\n";
            cir << "B1*   " << preRghtVal_out << "\n";

        }
        if (type & Type::Suffix)
        {


            cir << "down suf---  \n";
            //cir << "B0    " << leftIn.mSuffix << "\n16";
            //cir << "temp  " <<  << "\n16";
            cir << "B1    " << sufRghtVal << "\n";
            cir << "B     " << sufPrntVal << "\n";
            cir << "P1    " << sufRghtBit << "\n";
            op(cir, sufRghtVal, sufPrntVal, temp1);
            //lib.multiplex_build(cir, temp1, right.mSuffix, right.mSufProd, left.mSuffix, temp2);
            {
                auto& ifFalse = sufRghtVal;
                auto& ifTrue = temp1;
                auto& cd = cir;
                auto& choice = sufRghtBit;
                auto& out = sufLeftVal_out;
                //lib.multiplex_build(cir, temp1, left.mPrefix, left.mPreProd, right.mPrefix, t2);
                for (u64 i = 0; i < out.mWires.size(); ++i)
                    cd.addGate(ifFalse.mWires[i], ifTrue.mWires[i], oc::GateType::Xor, temp2.mWires[i]);
                //cd.addPrint("a^preBit  [" + std::to_string(i) + "] = ");
                //cd.addPrint(temp.mWires[0]);
                //cd.addPrint("\n16");

                for (u64 i = 0; i < out.mWires.size(); ++i)
                    cd.addGate(temp2.mWires[i], choice.mWires[0], oc::GateType::And, temp1.mWires[i]);

                //cd.addPrint("a^preBit&sufVal[" + std::to_string(i) + "] = ");
                //cd.addPrint(temp.mWires[0]);
                //cd.addPrint("\n16");

                for (u64 i = 0; i < out.mWires.size(); ++i)
                    cd.addGate(ifFalse.mWires[i], temp1.mWires[i], oc::GateType::Xor, out.mWires[i]);
            }
            cir.addCopy(sufPrntVal, sufRghtVal_out);


            cir << "B0*   " << sufLeftVal_out << "\n";
            cir << "B1*   " << sufRghtVal_out << "\n";
        }

        return cir;
    }



    // apply the downstream circuit to each level of the tree.
    macoro::task<> AggTree::downstream(
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
        OleGenerator& gen)
    {
        //throw RTE_LOC;
        MC_BEGIN(macoro::task<>, this, &src, &controlBits, &op, &root, levels, &preSuf, &vals, partyIdx, type, &comm, &gen,
            bitsPerEntry = u64{},
            debugLevels = std::vector<SplitLevel>{},
            nodeCir = oc::BetaCircuit{},
            bin = Gmw{},
            pLvl = u64{},
            cLvl = u64{},
            size = u64{}
        );

        bitsPerEntry = src.bitsPerEntry();
        debugLevels.resize(mDebug * levels.size());



        nodeCir = downstreamCir(bitsPerEntry, op, type);

        vals[0].resize(n16 / 2, bitsPerEntry, type);
        vals[1].resize(n16 / 2, bitsPerEntry, type);
        if (type & Type::Prefix)
        {
            preSuf[0].mPreVal.resize(n16 / 2, bitsPerEntry, sizeof(block));
            preSuf[1].mPreVal.resize(n16 / 2, bitsPerEntry, sizeof(block));
        }
        if (type & Type::Suffix)
        {
            preSuf[0].mSufVal.resize(n16 / 2, bitsPerEntry, sizeof(block));
            preSuf[1].mSufVal.resize(n16 / 2, bitsPerEntry, sizeof(block));
        }

        // we start at the root and move down. We store intermidate 
        // levels in `preSuf`. levels is only read from. Once the children 
        // are computed, we combine them and write the result to `root`
        // 
        for (pLvl = logn; pLvl != 0; --pLvl)
        {
            // how many parents are here at this level.
            // For the last level this might not be a power of 2.
            size = (type & Type::Prefix) ? root.mPreVal.numEntries() : root.mSufVal.numEntries();
            cLvl = pLvl - 1;

            {

                auto& parent = root;
                auto& children = levels[cLvl];


                bin.init(size, nodeCir, gen);

                u64 inIdx = 0, outIdx = 0;
                if (type & Type::Prefix)
                {
                    // prefix only takes the left child and parent as input
                    bin.mapInput(inIdx++, children[0].mPreVal);
                    bin.mapInput(inIdx++, children[0].mPreBit);
                    bin.mapInput(inIdx++, parent.mPreVal);

                    // set number of shares we have per wire.
                    preSuf[0].mPreVal.reshape(size); 
                    preSuf[1].mPreVal.reshape(size);

                    // left and right child output
                    bin.mapOutput(outIdx++, preSuf[0].mPreVal);
                    bin.mapOutput(outIdx++, preSuf[1].mPreVal);
                }

                if (type & Type::Suffix)
                {
                    // prefix only takes the right child and parent as input
                    bin.mapInput(inIdx++, children[1].mSufVal);
                    bin.mapInput(inIdx++, children[1].mSufBit);
                    bin.mapInput(inIdx++, parent.mSufVal);

                    // set number of shares we have per wire.
                    preSuf[0].mSufVal.reshape(size);
                    preSuf[1].mSufVal.reshape(size);

                    // left and right child output
                    bin.mapOutput(outIdx++, preSuf[0].mSufVal);
                    bin.mapOutput(outIdx++, preSuf[1].mSufVal);
                }
            }

            // eval
            MC_AWAIT(bin.run(comm));

            // for unit testing, we want to save these intermediate values.
            if (mDebug)
            {
                debugLevels[cLvl][0].mPreVal = preSuf[0].mPreVal;
                debugLevels[cLvl][1].mPreVal = preSuf[1].mPreVal;
                debugLevels[cLvl][0].mSufVal = preSuf[0].mSufVal;
                debugLevels[cLvl][1].mSufVal = preSuf[1].mSufVal;
            }

            // if we arent on the final level, we need to re-order
            // the children. Currently we have all the left children
            // and all the right children in separate lists. We need
            // to merge these two lists together so that the children 
            // are next to each other. This is done using an algorithm
            // called 'perfectShuffle'.
            if (cLvl)
            {
                // where we will store the merged children (ie the next set of parents).
                auto& nextParent = root;
                auto& nextChildren = levels[cLvl - 1];
                if (type & Type::Prefix)
                {
                    nextParent.mPreVal.resize(nextChildren[0].mPreVal.numEntries(), bitsPerEntry, sizeof(block));

                    auto old = preSuf[0].mPreVal.numEntries();

                    // For the second to last level we have a special case
                    // where some of the current level children are not parents
                    // for the next level. We dont want to merge these so we will
                    // skip them by calling reshape.
                    preSuf[0].mPreVal.reshape(nextParent.mPreVal.numEntries() / 2);
                    preSuf[1].mPreVal.reshape(nextParent.mPreVal.numEntries() / 2);

                    // merge the left and right children together.
                    perfectShuffle(preSuf[0].mPreVal, preSuf[1].mPreVal, nextParent.mPreVal);

                    preSuf[0].mPreVal.reshape(old);
                    preSuf[1].mPreVal.reshape(old);
                }

                if (type & Type::Suffix)
                {
                    nextParent.mSufVal.resize(nextChildren[0].mSufVal.numEntries(), bitsPerEntry, sizeof(block));

                    auto old = preSuf[0].mSufVal.numEntries();

                    // For the second to last level we have a special case
                    // where some of the current level children are not parents
                    // for the next level. We dont want to merge these so we will
                    // skip them by calling reshape.
                    preSuf[0].mSufVal.reshape(nextParent.mSufVal.numEntries() / 2);
                    preSuf[1].mSufVal.reshape(nextParent.mSufVal.numEntries() / 2);

                    // merge the left and right children together.
                    perfectShuffle(preSuf[0].mSufVal, preSuf[1].mSufVal, nextParent.mSufVal);

                    preSuf[0].mSufVal.reshape(old);
                    preSuf[1].mSufVal.reshape(old);
                }
            }

            // if we are on a leaf level, then we need to copy the values out.

            auto shiftBytes = [](TBinMatrix& src, u64 srcStart, u64 dstStart, u64 size) {

                auto bitsPerEntry = src.bitsPerEntry();
                for (u64 k = 0; k < bitsPerEntry; ++k)
                {
                    // shift the preSuf values down.
                    auto s0 = ((u8*)src[k].data()) + srcStart;
                    auto d0 = ((u8*)src[k].data()) + dstStart;
                    auto max = src[k].size() * sizeof(*src[k].data());
                    auto e = (u8*)(src[k].data() + src[k].size());
                    auto t = (u8*)(src[k].data()) + max;

                    assert(dstStart + size < max);
                    assert(d0 + size <= e);
                    assert(s0 + size <= e);
                    assert(e == t);
                    assert(dstStart > srcStart);
                    // copy in reverse since the buffers can overlap
                    for (u64 i = size - 1; i < size; --i)
                        d0[i] = s0[i];
                }
            };

            auto copyBytes = [](TBinMatrix& src, TBinMatrix& dst, u64 srcStart, u64 dstStart, u64 size)
            {
                auto bitsPerEntry = src.bitsPerEntry();
                assert(dst.bitsPerEntry() == bitsPerEntry);
                for (u64 k = 0; k < bitsPerEntry; ++k)
                {
                    for (u64 j = 0; j < 2; ++j)
                    {
                        auto s0 = ((u8*)src[k].data()) + srcStart;
                        auto d0 = ((u8*)dst[k].data()) + dstStart;
                        //auto max = src[k].size() * sizeof(*src[k].data());
                        auto es = (u8*)(src[k].data() + src[k].size());
                        auto ed = (u8*)(dst[k].data() + dst[k].size());
                        //assert(dstStart + size < max);
                        assert(d0 + size <= ed);
                        assert(s0 + size <= es);
                        memcpy(d0, s0, size);
                    }
                }
            };

            bool firstPartial = logn != logfn && cLvl == 1;
            bool secondPartial = logn != logfn && cLvl == 0;
            bool full = logn == logfn && cLvl == 0;

            // if we have a partial level, then we need to copy 
            // the initial leaf values to vals that are on the 
            // second to last level. We will effectively do the
            // same for preSuf by shifting the bytes down.
            for (u64 j = 0; j < 2 * firstPartial; ++j)
            {
                if (type & Type::Prefix)
                {
                    assert(cLvl == 1);
                    // shift the preSuf values down.
                    shiftBytes(preSuf[j].mPreVal, r/16, n0/16, n1/16);

                    // copy the leaf values
                    copyBytes(levels[cLvl][j].mPreVal, vals[j].mPreVal, r/16, n0/16, n1/16);
                    copyBytes(levels[cLvl][j].mPreBit, vals[j].mPreBit, r/16, n0/16, n1/16);
                }                                                        
                                                                         
                if (type & Type::Suffix)                                 
                {                                                        
                    // shift the preSuf values down.                     
                    shiftBytes(preSuf[j].mSufVal, r/16, n0/16, n1/16);   
                                                                         
                    // copy the leaf values                              
                    copyBytes(levels[cLvl][j].mSufVal, vals[j].mSufVal, r/16, n0/16, n1/16);
                    copyBytes(levels[cLvl][j].mSufBit, vals[j].mSufBit, r/16, n0/16, n1/16);
                }
            }

            // copy the leaf values that are on the last (partial) level
            for (u64 j = 0; j < 2 * secondPartial; ++j)
            {
                if (type & Type::Prefix)
                {
                    assert(cLvl == 0);
                    copyBytes(levels[cLvl][j].mPreVal, vals[j].mPreVal, 0, 0, n0/16);
                    copyBytes(levels[cLvl][j].mPreBit, vals[j].mPreBit, 0, 0, n0/16);

                    preSuf[j].mPreVal.reshape(n16 / 2);

                }

                if (type & Type::Suffix)
                {
                    copyBytes(levels[cLvl][j].mSufVal, vals[j].mSufVal, 0, 0, n0/16);
                    copyBytes(levels[cLvl][j].mSufBit, vals[j].mSufBit, 0, 0, n0/16);
                    preSuf[j].mSufVal.reshape(n16 / 2);
                }
            }

            // the last level is a full level, we can just move the values.
            for (u64 j = 0; j < 2 * full; ++j)
            {
                if (mDebug)
                    vals[j] = levels[0][j];
                else
                    vals[j] = std::move(levels[0][j]);
            }
        }


        if (mDebug)
        {
            for (u64 i = 0; i < levels.size(); ++i)
                levels[i] = std::move(debugLevels[i]);
        }

        MC_END();
    }



}