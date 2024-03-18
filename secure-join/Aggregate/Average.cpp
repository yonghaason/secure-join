#include "Average.h"

namespace secJoin {

    // Removes the groupBy, activeFlag & compressKeys from the data
    // keys = groupByData + ActiveFlag
    // compressKeys = encode(keys);
    void Average::extractKeyInfo(
        BinMatrix& data,
        BinMatrix& grpByData,
        BinMatrix& compressKeys,
        BinMatrix& actFlag,
        const std::vector<OmJoin::Offset>& offsets)
    {
        u64 n = data.rows();
        u64 groupBySize = offsets[0].mSize;
        u64 compressKeySize = offsets[1].mSize;
        u64 actFlagSize = offsets[2].mSize;
        assert(actFlagSize == 1);
        

        grpByData.resize(n, groupBySize);
        compressKeys.resize(n, compressKeySize);
        actFlag.resize(n, actFlagSize);


        for (u64 i = 0; i < n; ++i)
        {
            memcpy(grpByData.data(i), data.data(i) + (offsets[0].mStart/8), grpByData.bytesPerEntry());
            memcpy(compressKeys.data(i), data.data(i) + (offsets[1].mStart/8), compressKeys.bytesPerEntry());
            memcpy(actFlag.data(i), data.data(i) + (offsets[2].mStart/8), actFlag.bytesPerEntry());
        }

        // Discarding the key information
        data.reshape(offsets[0].mStart);
    }

    // Compute the compressKeys from the keys
    // compressKeys is used to generate the sorting Perm & getting controlBits
    // keys = groupByData + ActiveFlag
    // compressKeys = encode(keys);
    void Average::loadKeys(
        ColRef groupByCol,
        std::vector<u8>& actFlagVec,
        oc::PRNG& prng,
        BinMatrix& compressKeys)
    {
        auto grpByData = groupByCol.mCol.mData;
        auto rows = grpByData.rows();
        auto grpByBits = grpByData.bitsPerEntry();
        auto grpByBytes = grpByData.bytesPerEntry();
        auto compressedSize = mStatSecParam + log2(rows);

        // Appending ActiveFlagBit to the key
        BinMatrix keys(rows, grpByBits + 1);
        assert(rows == actFlagVec.size());
        for (u64 i = 0; i < keys.rows(); ++i)
        {
            memcpy(keys.data(i), grpByData.data(i), grpByBytes);
            *oc::BitIterator((u8*)keys.data(i), grpByBits) = actFlagVec[i];
        }
        
        if (keys.bitsPerEntry() <= compressedSize)
        {
            // Make a copy of keys into compressKeys
            compressKeys.resize(keys.rows(), keys.bitsPerEntry());
            std::swap(keys, compressKeys);
        }
        else
        {
            oc::LinearCode code;
            code.random(prng, keys.bitsPerEntry(), compressedSize);

            compressKeys.resize(rows, compressedSize);

            for (u64 i = 0; i < rows; ++i)
                code.encode(keys.data(i), compressKeys.data(i));

        }
    }


    // concatinate all the columns in `average` that are part of the table.
    // Then append 1's the end for the count
    // Then append the groupByCol 
    // Then concatinate the compressKeys
    // Then append ActFlag to the end
    // keys = groupByData + ActiveFlag
    // compressKeys = encode(keys);
    void Average::concatColumns(
        ColRef groupByCol,
        std::vector<ColRef> avgCol,
        std::vector<u8>& actFlagVec,
        BinMatrix& compressKeys,
        BinMatrix& ret)
    {
        u64 m = avgCol.size();
        u64 n0 = groupByCol.mCol.rows();
        u64 rowByteSize = 0;

        std::vector<BinMatrix*> data;

        for (u64 i = 0; i < m; ++i)
        {
            if (&groupByCol.mTable == &avgCol[i].mTable)
            {
                auto bytes = oc::divCeil(avgCol[i].mCol.getBitCount(), 8);
                assert(avgCol[i].mCol.rows() == n0);
                assert(mOffsets[i].mStart == rowByteSize * 8);
                assert(mOffsets[i].mSize == avgCol[i].mCol.mData.bitsPerEntry());
                assert(mOffsets[i].mName == avgCol[i].mCol.mName);
                
                data.emplace_back(&avgCol[i].mCol.mData);
                rowByteSize += bytes;
            }
            else
            {
                std::string temp("Average table is not same as groupby table\n");
                throw std::runtime_error(temp + LOCATION);
            }
        }

        // Adding a Columns of 1's for calculating average
        BinMatrix ones(n0, sizeof(oc::u64) * 8);

        // Adding 1's in only party column
        if (mPartyIdx)
        {
            for (oc::u64 i = 0; i < n0; i++)
                ones(i, 0) = 1;
        }

        data.emplace_back(&ones);
        rowByteSize += sizeof(oc::u64);

        // Adding the groupBy Cols
        data.emplace_back(&groupByCol.mCol.mData);
        rowByteSize += groupByCol.mCol.mData.bytesPerEntry();

        // Adding the compress Keys
        data.emplace_back(&compressKeys);
        rowByteSize += compressKeys.bytesPerEntry();

        // All columns size + ActFlag Size
        ret.resize(n0, (rowByteSize + 1) * 8);
        OmJoin::concatColumns(ret, data, mOffsets);

        // Adding the ActFlag 
        for(u64 i = 0; i < ret.rows(); i++)
            *oc::BitIterator((u8*)ret.data(i), rowByteSize * 8) = actFlagVec[i];        

    }

    
    // Active Flag = (Controlbits)^-1 & Active Flag
    macoro::task<> Average::updateActiveFlag(
        BinMatrix& actFlag,
        BinMatrix& choice,
        BinMatrix& out,
        coproto::Socket& sock)
    {
        MC_BEGIN(macoro::task<>, &actFlag, &choice, &out, &sock, this);
        
        assert(actFlag.bitsPerEntry() == 1);

        mUpdateActiveFlagGmw.setInput(0, choice);
        mUpdateActiveFlagGmw.setInput(1, actFlag);

        MC_AWAIT(mUpdateActiveFlagGmw.run(sock));

        out.resize(actFlag.rows(), 1);
        mUpdateActiveFlagGmw.getOutput(0, out);
        

        MC_END();
    }


    oc::BetaCircuit updateActiveFlagCir(u64 aSize, u64 bSize, u64 cSize)
    {
        // Current Assumption is Act flag & Control Bit is 1 bit
        assert(aSize == 1);
        assert(aSize == bSize);
        assert(bSize == cSize);

        BetaCircuit cd;

        BetaBundle a(aSize);
        BetaBundle b(bSize);
        BetaBundle c(cSize);
        
        a.mWires.resize(aSize);
        b.mWires.resize(bSize);
        c.mWires.resize(cSize);

        cd.addInputBundle(a);
        cd.addInputBundle(b);
        cd.addOutputBundle(c);

        cd.addGate(a.mWires[0], b.mWires[0], oc::GateType::na_And, c.mWires[0]);

        return cd;
    }

    void Average::init(
        ColRef groupByCol,
        std::vector<ColRef> avgCol,
        CorGenerator& ole,
        bool removeDummies,
        bool printSteps,
        bool mock)
    {
        u64 rows = groupByCol.mCol.rows();
        // u64 rows = groupByCol.mCol.cols();
        // keySize = groupByKeySize + one bit of activeflag
        u64 keySize = groupByCol.mCol.getBitCount() + 1; // Maybe I need to initialize with grpBits + 1

        u64 compressKeySize = std::min<u64>(
            keySize, 
            mStatSecParam + log2(rows));

        mPartyIdx = ole.partyIdx();

        mKeyIndex = -1;
        mDataBitsPerEntry = 0;
        mRemoveDummies = removeDummies;
        mInsecurePrint = printSteps;
        mInsecureMockSubroutines = mock;


        mOffsets.clear();
        mOffsets.reserve(avgCol.size() + 1);
        u64 aggTreeBitCount = 0;


        mSort.mInsecureMock = mInsecureMockSubroutines;
        // sPerm.mInsecureMock = mInsecureMockSubroutines;

        for (u64 i = 0; i < avgCol.size(); ++i)
        {
            auto bytes = avgCol[i].mCol.getByteCount();
            mOffsets.emplace_back(
                OmJoin::Offset{
                    mDataBitsPerEntry,
                    avgCol[i].mCol.getBitCount(),
                    avgCol[i].mCol.mName });

            mDataBitsPerEntry += bytes * 8;
            aggTreeBitCount += avgCol[i].mCol.getBitCount();
        }
        // Columns for ones
        mOffsets.emplace_back(OmJoin::Offset{ mDataBitsPerEntry, sizeof(oc::u64) * 8, "count*" });
        mDataBitsPerEntry += sizeof(oc::u64) * 8;
        aggTreeBitCount += sizeof(oc::u64) * 8;

        // Initialize the AggTree before adding the keys info to the offsets
        auto addCir = getAddCircuit(mOffsets, oc::BetaLibrary::Optimized::Depth);
        mAggTree.init(rows, aggTreeBitCount, AggTreeType::Suffix, addCir, ole);

        mOffsets.emplace_back(OmJoin::Offset{ mDataBitsPerEntry, groupByCol.mCol.getBitCount(), "GroupBy" });
        mDataBitsPerEntry += groupByCol.mCol.getByteCount() * 8;
        
        mOffsets.emplace_back(OmJoin::Offset{ mDataBitsPerEntry, compressKeySize, "CompressKey*" });
        mDataBitsPerEntry += oc::divCeil(compressKeySize, 8) * 8;

        mOffsets.emplace_back(OmJoin::Offset{ mDataBitsPerEntry, 1, "ActFlag" });
        mDataBitsPerEntry += 8;


        
        mSort.init(mPartyIdx, rows, compressKeySize, ole);

        // ////////// Need to edit permForwards & permBackwards
        // in the forward direction we will permute the keys, a flag, 
        // and all of the select columns of the left table. In the 
        // backwards direction, we will unpermute the left table select
        // columns. Therefore, in total we will permute:
        u64 permForward = oc::divCeil(mDataBitsPerEntry, 8) + sizeof(u32);
        // u64 permBackward = (removeDummies == false) * oc::divCeil(mDataBitsPerEntry - 1 - keySize, 8);
        u64 permBackward = 0;

        mPerm.init(mPartyIdx, rows, permForward + permBackward, ole);

        mControlBitGmw.init(rows, OmJoin::getControlBitsCircuit(compressKeySize), ole);

        auto cir = updateActiveFlagCir(1, 1, 1);
        mUpdateActiveFlagGmw.init(rows, cir, ole);
    
    }



    // Assumptions: 
    // 1) Both Average Col & Group by Col are not null
    // 2) Currently one group by column is supported
    macoro::task<> Average::avg(
        ColRef groupByCol,
        std::vector<ColRef> avgCol,
        SharedTable& out,
        oc::PRNG& prng,
        CorGenerator& ole,
        coproto::Socket& sock,
        bool remDummies,
        Perm randPerm)
    {

        MC_BEGIN(macoro::task<>, this, groupByCol, avgCol, &out, &prng, &ole, &sock, remDummies,
            randPerm,
            compressKeys = BinMatrix{},
            sortedgroupByData = BinMatrix{},
            data = BinMatrix{},
            temp = BinMatrix{},
            actFlag = BinMatrix{},
            controlBits = BinMatrix{},
            tempVec = std::vector<u8>{},
            dataOffsets = std::vector<OmJoin::Offset>{},
            tempOffsets  = std::vector<OmJoin::Offset>{},
            prepro = macoro::eager_task<>{},
            sPerm = AdditivePerm{},
            perm = ComposedPerm{}
        );

        loadKeys(groupByCol, groupByCol.mTable.mIsActive, prng, compressKeys);

        if (mInsecurePrint)
        {
            std::cout << "------------- Average Starts here ---------- " << std::endl;
            tempOffsets = { OmJoin::Offset{ 0, compressKeys.bitsPerEntry(), "Compress Key*" } };
            MC_AWAIT(OmJoin::print(compressKeys, controlBits, sock, mPartyIdx, "Compress keys", tempOffsets));
        }
        // mSort.mDebug = true;
        mSort.preprocess();
        prepro = mSort.genPrePerm(sock, prng) | macoro::make_eager();

        // get the stable sorting permutation sPerm
        MC_AWAIT(mSort.genPerm(compressKeys, sPerm, sock, prng));

        MC_AWAIT(sPerm.validate(sock));

        mPerm.preprocess();
        MC_AWAIT(prepro);

        // Concat Columns
        concatColumns(groupByCol, avgCol, groupByCol.mTable.mIsActive, compressKeys, data);
        if (mInsecurePrint)
            MC_AWAIT(OmJoin::print(data, controlBits, sock, mPartyIdx, "preSort", mOffsets));

        // Apply the sortin permutation.
        temp.resize(data.numEntries(), data.bitsPerEntry());

        MC_AWAIT(mPerm.generate(sock, prng, data.rows(), perm));

        MC_AWAIT(perm.validate(sock));

        MC_AWAIT(perm.derandomize(sPerm, sock));

        MC_AWAIT(perm.apply<u8>(PermOp::Inverse, data, temp, sock));
        std::swap(data, temp);

        if (mInsecurePrint)
            MC_AWAIT(OmJoin::print(data, controlBits, sock, mPartyIdx, "sort", mOffsets));

        // Removing keys info from the offsets 
        dataOffsets.resize(mOffsets.size() - 3);

        for(u64 i = 0; i < mOffsets.size() - 3; i++)
            dataOffsets[i] = mOffsets[i];
        
        // All the Key Related information is in tempOffSet
        tempOffsets.resize(3);
        for(u64 i = 0; i < 3; i++)
            tempOffsets[i] = mOffsets[mOffsets.size() - 3 + i];

        // Take out the Keys + activeflag + compressKeys from the data
        // After this data only has avgCols & count*
        extractKeyInfo(data, sortedgroupByData, compressKeys, actFlag, tempOffsets);

        // compare adjacent keys. controlBits[i] = 1 if k[i]==k[i-1].
        MC_AWAIT(getControlBits(compressKeys, sock, controlBits));

        if (mInsecurePrint)
            MC_AWAIT(OmJoin::print(data, controlBits, sock, mPartyIdx, "control", dataOffsets));

        MC_AWAIT(mAggTree.apply(data, controlBits, sock, prng, temp));
        std::swap(data, temp);

        if (mInsecurePrint)
            MC_AWAIT(OmJoin::print(data, controlBits, sock, mPartyIdx, "agg-data", dataOffsets));

        MC_AWAIT(updateActiveFlag(actFlag, controlBits, temp, sock));
        std::swap(actFlag, temp);

        if (mInsecurePrint)
        {
            tempOffsets = { OmJoin::Offset{ 0, actFlag.bitsPerEntry(), "Act Flag" }};
            MC_AWAIT(OmJoin::print(actFlag, controlBits, sock, mPartyIdx, "isActive", tempOffsets));
        }

        getOutput(out, avgCol, groupByCol, data, sortedgroupByData, actFlag, dataOffsets);

        // if (remDummies)
        // {
        //     MC_AWAIT(getOutput(out, avgCol, groupByCol, keys, data, offsets, keyOffsets,
        //         ole, sock, prng, !mInsecureMockSubroutines, randPerm));
        // }
        // else
        //     getOutput(out, avgCol, groupByCol, keys, data, controlBits, offsets, keyOffsets);

        MC_END();
    }


    void Average::getOutput(
        SharedTable& out,
        std::vector<ColRef> avgCol,
        ColRef groupByCol,
        BinMatrix& data,
        BinMatrix& sortedgroupByData,
        BinMatrix& actFlag,
        std::vector<OmJoin::Offset>& offsets)
    {
        assert(data.numEntries() == sortedgroupByData.numEntries());

        u64 nEntries = data.numEntries();
        populateOutTable(out, avgCol, groupByCol, nEntries);

        out.mIsActive.resize(nEntries);

        for (u64 i = 0; i < data.numEntries(); i++)
        {
            // Storing the Group By Column
            memcpy(out.mColumns[0].mData.data(i), sortedgroupByData.data(i), out.mColumns[0].getByteCount());

            // Copying the average columns
            for (u64 j = 0; j < offsets.size(); j++)
            {
                memcpy(out.mColumns[j + 1].mData.data(i),
                    &data(i, offsets[j].mStart / 8),
                    out.mColumns[j + 1].getByteCount());

            }

            // Adding Active Flag
            memcpy(&out.mIsActive[i], actFlag.data(i), 1);
        }

    }

    // Call this getOutput for removing Dummies
    macoro::task<> Average::getOutput(
        SharedTable& out,
        std::vector<ColRef> avgCol,
        ColRef groupByCol,
        BinMatrix& keys,
        BinMatrix& data,
        std::vector<OmJoin::Offset>& offsets,
        std::vector<OmJoin::Offset>& keyOffsets,
        CorGenerator& ole,
        coproto::Socket& sock,
        oc::PRNG& prng,
        bool securePerm,
        Perm& randPerm)
    {
        MC_BEGIN(macoro::task<>, &out, avgCol, groupByCol, &keys, &data, &offsets,
            &keyOffsets, &ole, &sock, &prng, securePerm, &randPerm,
            temp = BinMatrix{},
            actFlag = BinMatrix{},
            curOutRow = u64{},
            nOutRows = u64{},
            tempPerm = Perm{},
            i = u64()
        );

        assert(data.numEntries() == keys.numEntries());

        actFlag.resize(keys.rows(), 1);

        // Extracting Active Flag
        for (u64 i = 0; i < keys.rows(); ++i)
            actFlag(i) = *oc::BitIterator(keys.data(i), keyOffsets[1].mStart);

        // Revealing the active flag
        MC_AWAIT(OmJoin::revealActFlag(actFlag, temp, sock, ole.partyIdx()));
        std::swap(actFlag, temp);

        nOutRows = 0;
        for (u64 i = 0; i < actFlag.numEntries(); i++)
        {
            if (actFlag.mData(i, 0) == 1)
                nOutRows++;
        }

        populateOutTable(out, avgCol, groupByCol, nOutRows);
        // out.mIsActive.resize(nOutRows);

        curOutRow = 0;
        for (u64 i = 0; i < data.numEntries(); i++)
        {
            // assert(curOutRow <= nOutRows);
            if (actFlag.mData(i, 0) == 1)
            {
                // Storing the Group By Column
                memcpy(out.mColumns[0].mData.data(curOutRow), keys.data(i),
                    out.mColumns[0].mData.bytesPerEntry());

                // Copying the average columns
                for (u64 j = 0; j < offsets.size(); j++)
                {
                    memcpy(out.mColumns[j + 1].mData.data(curOutRow),
                        &data(i, offsets[j].mStart / 8),
                        out.mColumns[j + 1].getByteCount());

                }
                // out.mIsActive[curOutRow] = *oc::BitIterator(keys.data(i), keyOffsets[1].mStart);
                curOutRow++;
            }

            // We got all our entries
            if (curOutRow == nOutRows)
                break;
        }

        if (randPerm.size() == 0 && nOutRows > 1)
        {
            tempPerm.randomize(nOutRows, prng);
            randPerm = tempPerm;
        }

        // A Better way could have been to permute the keys & data
        // But since we want to compare it expected result in the test
        // We need to permute only the final remaining rows
        if (nOutRows > 1)
        {
            for (i = 0; i < out.cols(); i++)
            {
                MC_AWAIT(OmJoin::applyRandPerm(out.mColumns[i].mData, temp, ole,
                    prng, randPerm, sock, securePerm));
                std::swap(out.mColumns[i].mData, temp);
            }
        }

        // MC_AWAIT(OmJoin::applyRandPerm(keys, temp, ole, prng, *randPerm, sock, securePerm));
        // std::swap(keys, temp);


        MC_END();
    }

    AggTree::Operator Average::getAddCircuit(std::vector<OmJoin::Offset>& offsets,
        oc::BetaLibrary::Optimized op)
    {
        return [&, op](
            oc::BetaCircuit& cd,
            const oc::BetaBundle& left,
            const oc::BetaBundle& right,
            oc::BetaBundle& out)
            {
                u64 currIndex = 0;
                for (u64 i = 0; i < offsets.size(); i++)
                {
                    auto size = offsets[i].mSize;
                    // std::cout << "Offset size is " <<  size << std::endl;
                    auto beginIndex = currIndex;
                    auto endIndex = currIndex + size;
                    BetaBundle a, b, c;

                    a.mWires.reserve(size);
                    b.mWires.reserve(size);
                    c.mWires.reserve(size);
                    for (u64 j = beginIndex; j < endIndex; j++)
                    {
                        a.mWires.emplace_back(left[j]);
                        b.mWires.emplace_back(right[j]);
                        c.mWires.emplace_back(out[j]);
                    }

                    BetaBundle t(op == oc::BetaLibrary::Optimized::Size ? 4 : size * 2);
                    cd.addTempWireBundle(t);
                    osuCrypto::BetaLibrary::add_build(cd, a, b, c, t, oc::BetaLibrary::IntType::TwosComplement, op);

                    // std::cout << "Circuit Gen for " << offsets[i].mName << std::endl;
                    currIndex = endIndex;
                }

            };
    }

    macoro::task<> Average::getControlBits(
        BinMatrix& keys,
        coproto::Socket& sock,
        BinMatrix& out)
    {
        MC_BEGIN(macoro::task<>, this, &keys, &sock, &out,
            cir = oc::BetaCircuit{},
            sKeys = BinMatrix{},
            n = u64{},
            keyByteSize = u64{},
            keyBitCount = u64{});

        n = keys.numEntries();
        keyByteSize = keys.bytesPerEntry();
        keyBitCount = keys.bitsPerEntry();
        
        sKeys.resize(n + 1, keyBitCount);
        memcpy(sKeys.data(1), keys.data(0), n * keyByteSize);

        mControlBitGmw.setInput(0, sKeys.subMatrix(0, n));
        mControlBitGmw.setInput(1, sKeys.subMatrix(1, n));

        MC_AWAIT(mControlBitGmw.run(sock));

        out.resize(n, 1);
        mControlBitGmw.getOutput(0, out);
        out.mData(0) = 0;

        MC_END();
    }


}