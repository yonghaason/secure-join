#include "Average.h"

namespace secJoin {

    // concatinate all the columns in `average` that are part of the table.
    // Then append 1's the end for the count
    void Average::concatColumns(
        ColRef groupByCol,
        std::vector<ColRef> avgCol,
        BinMatrix& ret,
        std::vector<OmJoin::Offset>& offsets,
        CorGenerator& ole)
    {
        u64 m = avgCol.size();
        u64 n0 = groupByCol.mCol.rows();
        u64 rowSize = 0;

        std::vector<BinMatrix*> avg;

        offsets.clear();
        offsets.reserve(m + 1);
        for (u64 i = 0; i < m; ++i)
        {
            if (&groupByCol.mTable == &avgCol[i].mTable)
            {
                auto bytes = oc::divCeil(avgCol[i].mCol.getBitCount(), 8);
                assert(avgCol[i].mCol.rows() == n0);
                avg.emplace_back(&avgCol[i].mCol.mData);
                offsets.emplace_back(OmJoin::Offset{ rowSize * 8, avgCol[i].mCol.mData.bitsPerEntry(), avgCol[i].mCol.mName });
                rowSize += bytes;
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
        if (ole.partyIdx())
        {
            for (oc::u64 i = 0; i < n0; i++)
                ones(i, 0) = 1;
        }

        offsets.emplace_back(OmJoin::Offset{ rowSize * 8, sizeof(oc::u64) * 8, "count*" });
        avg.emplace_back(&ones);

        ret.resize(n0, (rowSize + sizeof(oc::u64)) * 8);
        OmJoin::concatColumns(ret, avg);

    }


    // Active Flag = (Controlbits)^-1 & Active Flag
    macoro::task<> Average::updateActiveFlag(
        BinMatrix& data,
        BinMatrix& choice,
        BinMatrix& out,
        CorGenerator& ole,
        coproto::Socket& sock)
    {
        MC_BEGIN(macoro::task<>, &data, &choice, &out, &ole, &sock,
            gmw = Gmw{},
            cir = oc::BetaCircuit{},
            temp = BinMatrix{},
            a = BetaBundle{},
            b = BetaBundle{},
            c = BetaBundle{},
            offset = u64{}
        );
        // Circuit Design
        a.mWires.resize(1);
        b.mWires.resize(1);
        c.mWires.resize(1);

        cir.addInputBundle(a);
        cir.addInputBundle(b);
        cir.addOutputBundle(c);

        cir.addGate(a.mWires[0], b.mWires[0], oc::GateType::na_And, c.mWires[0]);
        gmw.init(data.rows(), cir);
        gmw.request(ole);

        if (data.bitsPerEntry() % 8 != 1)
        {
            std::cout << "logic error, need to fix. " << LOCATION << std::endl;
            throw RTE_LOC;
        }

        offset = data.bitsPerEntry() / 8;
        temp.resize(data.rows(), 1);

        for (u64 i = 0; i < data.rows(); ++i)
            temp(i) = data(i, offset);

        gmw.setInput(0, choice);
        gmw.setInput(1, temp);

        MC_AWAIT(gmw.run(sock));

        gmw.getOutput(0, temp);
        out.resize(data.rows(), data.bitsPerEntry());
        for (u64 i = 0; i < data.rows(); ++i)
        {
            memcpy(out[i].subspan(0, offset), data[i].subspan(0, offset));
            out(i, offset) = temp(i);
        }

        MC_END();    
    }


    void appendFlagToKey(
        BinMatrix &keys, 
        std::vector<u8>& actFlagVec, 
        BinMatrix &ret,
        std::vector<OmJoin::Offset>& keyOffsets)
    {

        std::vector<BinMatrix*> temp;
        temp.emplace_back(&keys);
        u64 offset = keys.bytesPerEntry();

        keyOffsets = { OmJoin::Offset{0, offset * 8, "key"},
            OmJoin::Offset{offset * 8, 1, "ActFlag"} };

        // key size will become of multiple of 8 after the concatColumn operation
        OmJoin::concatColumns(ret, temp);

        assert(keys.rows() == actFlagVec.size());
        for (u64 i = 0; i < keys.rows(); ++i)
            *oc::BitIterator((u8*)ret.data(i), offset * 8) = actFlagVec[i];
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
        Perm* randPerm)
    {

        MC_BEGIN(macoro::task<>, this, groupByCol, avgCol, &out, &prng, &ole, &sock, remDummies,
            randPerm,
            keys = BinMatrix{},
            data = BinMatrix{},
            temp = BinMatrix{},
            sPerm = AdditivePerm{},
            sort = RadixSort{},
            controlBits = BinMatrix{},
            offsets = std::vector<OmJoin::Offset>{},
            keyOffsets = std::vector<OmJoin::Offset>{},
            addCir = AggTree::Operator{},
            aggTree = AggTree{},
            actFlagVec = std::vector<u8>{},
            tempVec= std::vector<u8>{}
        );

        // Appending Active Flag to the key
        keys = groupByCol.mCol.mData;
        actFlagVec = groupByCol.mTable.mIsActive;

        temp.resize(keys.numEntries(), keys.bytesPerEntry() * 8 + 1);
        appendFlagToKey(keys, actFlagVec, temp, keyOffsets);
        std::swap(keys, temp);

        if (mInsecurePrint)
        {
            std::cout << "------------- Average Starts here ---------- " << std::endl;
            MC_AWAIT(OmJoin::print(keys, controlBits, sock, ole.partyIdx(), "keys", keyOffsets));
        }

        sort.mInsecureMock = mInsecureMockSubroutines;
        sPerm.mInsecureMock = mInsecureMockSubroutines;

        // need to set sort ole.
        sort.init(ole.partyIdx(), keys.rows(), keys.bitsPerEntry(), data.bytesPerEntry() + keys.bytesPerEntry());
        sort.request(ole);

        MC_AWAIT(sort.genPerm(keys, sPerm, sock, prng));
        concatColumns(groupByCol, avgCol, data, offsets, ole);
        
        if (mInsecurePrint)
            MC_AWAIT(OmJoin::print(data, controlBits, sock, ole.partyIdx(), "preSort", offsets));

        temp.resize(data.numEntries(), data.bytesPerEntry() * 8);

        // Apply the sortin permutation to both keys & concat columns
        MC_AWAIT(sPerm.apply(PermOp::Inverse, data, temp, prng, sock));
        std::swap(data, temp);

        if (mInsecurePrint)
            MC_AWAIT(OmJoin::print(data, controlBits, sock, ole.partyIdx(), "sort-data", offsets));

        temp.resize(keys.numEntries(), keys.bitsPerEntry());
        MC_AWAIT(sPerm.apply(PermOp::Inverse, keys, temp, prng, sock));
        std::swap(keys, temp);
        
        if (mInsecurePrint)
            MC_AWAIT(OmJoin::print(keys, controlBits, sock, ole.partyIdx(), "sort-keys", keyOffsets));

        // compare adjacent keys. controlBits[i] = 1 if k[i]==k[i-1].
        MC_AWAIT(getControlBits(keys, sock, controlBits, ole));


        if (mInsecurePrint)
            MC_AWAIT(OmJoin::print(data, controlBits, sock, ole.partyIdx(), "control", offsets));
            // MC_AWAIT(print(controlBits, sock, ole.partyIdx(), "controlbits"));

        // oc::BetaLibrary::Optimized::Depth shouldn't be hardcoded 
        addCir = getAddCircuit(offsets, op);


        MC_AWAIT(aggTree.apply(data, controlBits, addCir, AggTreeType::Suffix, sock, ole, prng, temp));
        std::swap(data, temp);

        if (mInsecurePrint)
            MC_AWAIT(OmJoin::print(data, controlBits, sock, ole.partyIdx(), "agg-data", offsets));

        MC_AWAIT(updateActiveFlag(keys, controlBits, temp, ole, sock));
        std::swap(keys, temp);

        if (mInsecurePrint)
            MC_AWAIT(OmJoin::print(keys, controlBits, sock, ole.partyIdx(), "isActive", keyOffsets));

        if(remDummies)
        {
            MC_AWAIT(getOutput(out, avgCol, groupByCol, keys, data, offsets, keyOffsets,
                ole, sock, prng, !mInsecureMockSubroutines, randPerm));
        }
        else
            getOutput(out, avgCol, groupByCol, keys, data, controlBits, offsets, keyOffsets);

        MC_END();
    }


    void Average::getOutput(
        SharedTable& out,
        std::vector<ColRef> avgCol,
        ColRef groupByCol,
        BinMatrix& keys,
        BinMatrix& data,
        BinMatrix& controlBits,
        std::vector<OmJoin::Offset>& offsets,
        std::vector<OmJoin::Offset>& keyOffsets)
    {
        assert(data.numEntries() == keys.numEntries());

        u64 nEntries = data.numEntries();
        populateOutTable(out, avgCol, groupByCol, nEntries);
           
        out.mIsActive.resize(nEntries);
        
        for (u64 i = 0; i < data.numEntries(); i++)
        {
            // Storing the Group By Column
            memcpy(out.mColumns[0].mData.data(i), keys.data(i), out.mColumns[0].getByteCount());

            // Copying the average columns
            for (u64 j = 0; j < offsets.size(); j++)
            {
                memcpy(out.mColumns[j + 1].mData.data(i),
                    &data(i, offsets[j].mStart / 8),
                    out.mColumns[j + 1].getByteCount());

            }

            // Adding Active Flag
            out.mIsActive[i] = *oc::BitIterator(keys.data(i), keyOffsets[1].mStart);
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
        Perm* randPerm)
    {
        MC_BEGIN(macoro::task<>, &out, avgCol, groupByCol, &keys, &data, &offsets, 
            &keyOffsets, &ole, &sock, &prng, securePerm, randPerm,
            temp = BinMatrix{},
            actFlag = BinMatrix{},
            curOutRow = u64{},
            nOutRows = u64{},
            perm = ComposedPerm{},
            tempPerm = Perm{},
            i = u64()
            );

        assert(data.numEntries() == keys.numEntries());

        actFlag.resize(keys.rows(), 1);

        for (u64 i = 0; i < keys.rows(); ++i)
            actFlag(i) = *oc::BitIterator(keys.data(i), keyOffsets[1].mStart);

        // Revealing the active flag
        if (ole.partyIdx() == 0)
        {
            temp.resize(actFlag.numEntries(), actFlag.bitsPerEntry());
            MC_AWAIT(sock.recv(temp.mData));
            temp = reveal(temp, actFlag);
            std::swap(actFlag, temp);
            MC_AWAIT(sock.send(coproto::copy(actFlag.mData)));
        }
        else
        {
            MC_AWAIT(sock.send(coproto::copy(actFlag.mData)));
            temp.resize(actFlag.numEntries(), actFlag.bitsPerEntry());
            MC_AWAIT(sock.recv(temp.mData));
            std::swap(actFlag, temp);
        }
        
        nOutRows = 0;
        for (u64 i = 0; i < actFlag.numEntries(); i++)
        {
            if (actFlag.mData(i, 0)  == 1)
                nOutRows++;
        }

        populateOutTable(out, avgCol, groupByCol, nOutRows);
        // out.mIsActive.resize(nOutRows);

        curOutRow = 0;
        for (u64 i = 0; i < data.numEntries(); i++)
        {
            assert(curOutRow <= nOutRows);
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
            if(curOutRow == nOutRows)
                break;
        }

        if(randPerm == nullptr)
        {
            tempPerm.randomize(nOutRows, prng);
            randPerm = &tempPerm;
        }

        // A Better way could have been to permute the keys & data
        // But since we want to compare it expected result in the test
        // We need to permute only the final remaining rows
        for(i = 0; i < out.cols(); i++)
        {
            MC_AWAIT(OmJoin::applyRandPerm(out.mColumns[i].mData, temp, ole, 
                prng, *randPerm, sock, securePerm));
            std::swap(out.mColumns[i].mData, temp);
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

                for (u64 i = 0; i < offsets.size(); i++)
                {
                    auto size = offsets[i].mSize;
                    auto beginIndex = offsets[i].mStart;
                    auto endIndex = offsets[i].mStart + size;
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

                }

            };
    }

    macoro::task<> Average::getControlBits(
        BinMatrix& keys,
        coproto::Socket& sock,
        BinMatrix& out,
        CorGenerator& ole)
    {
        MC_BEGIN(macoro::task<>, &keys, &sock, &out, &ole,
            cir = oc::BetaCircuit{},
            sKeys = BinMatrix{},
            bin = Gmw{},
            n = u64{},
            keyByteSize = u64{},
            keyBitCount = u64{});

        n = keys.numEntries();
        keyByteSize = keys.bytesPerEntry();
        keyBitCount = keys.bitsPerEntry();
        cir = OmJoin::getControlBitsCircuit(keyBitCount);
        sKeys.resize(n + 1, keyBitCount);
        memcpy(sKeys.data(1), keys.data(0), n * keyByteSize);
        // for (u64 i = 0; i < n; ++i)
        // {
        //     memcpy(sKeys.data(i + 1), keys.data(i), keyByteSize);
        // }
        bin.init(n, cir);
        bin.request(ole);

        bin.setInput(0, sKeys.subMatrix(0, n));
        bin.setInput(1, sKeys.subMatrix(1, n));

        MC_AWAIT(bin.run(sock));

        out.resize(n, 1);
        bin.getOutput(0, out);
        out.mData(0) = 0;

        MC_END();
    }


}