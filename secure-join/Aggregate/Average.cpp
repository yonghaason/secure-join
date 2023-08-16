#include "Average.h"
// #include "secure-join/Join/OmJoin.h"

namespace secJoin {

    // concatinate all the columns in `average` that are part of the table.
    // Then append 1's the end for the count
    void Average::concatColumns(
        ColRef groupByCol,
        std::vector<ColRef> avgCol,
        BinMatrix& ret,
        std::vector<OmJoin::Offset>& offsets,
        OleGenerator& ole)
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
        if (ole.mRole == OleGenerator::Role::Receiver)
        {
            for (oc::u64 i = 0; i < n0; i++)
                ones(i, 0) = 1;
        }


        offsets.emplace_back(OmJoin::Offset{ rowSize * 8, sizeof(oc::u64) * 8, "count*" });
        avg.emplace_back(&ones);

        ret.resize(n0, (rowSize + sizeof(oc::u64)) * 8);
        OmJoin::concatColumns(ret, avg);

    }


    macoro::task<> print(
        const BinMatrix& data,
        coproto::Socket& sock,
        int role,
        std::string name,
        std::vector<OmJoin::Offset>& offsets)
    {
        MC_BEGIN(macoro::task<>, &data, &sock, role, name, &offsets,
            D = BinMatrix{},
            C = BinMatrix{});
        if (role)
            MC_AWAIT(sock.send(data));
        else
        {
            D.resize(data.numEntries(), data.bytesPerEntry() * 8);
            MC_AWAIT(sock.recv(D));

            for (u64 i = 0; i < D.size(); ++i)
                D(i) ^= data(i);

            std::cout << name << std::endl << "        ";
            for (auto o : offsets)
                std::cout << o.mName << "  ";
            std::cout << std::endl;

            oc::BitVector bv;

            for (u64 i = 0; i < D.numEntries(); ++i)
            {
                std::cout << i << ": ";
                for (auto o : offsets)
                {
                    assert(D.bitsPerEntry() >= o.mSize + o.mStart);
                    bv.resize(0);
                    bv.append(D[i].data(), o.mSize, o.mStart);
                    trimSpan(bv.getSpan<u8>(), bv.size());
                    std::cout << bv.hex() << " ";
                }
                std::cout << std::endl;
            }

        }

        MC_END();


    }


    macoro::task<> print(
        const BinMatrix& data,
        coproto::Socket& sock,
        int role,
        std::string name)
    {
        MC_BEGIN(macoro::task<>, &data, &sock, role, name,
            D = BinMatrix{},
            C = BinMatrix{});
        if (role)
            MC_AWAIT(sock.send(data));
        else
        {
            D.resize(data.numEntries(), data.bytesPerEntry() * 8);
            MC_AWAIT(sock.recv(D));

            for (u64 i = 0; i < D.size(); ++i)
                D(i) ^= data(i);

            std::cout << name << std::endl;

            printMatrix(D.mData);
        }

        MC_END();


    }



    // Assumptions: 
    // 1) Both Average Col & Group by Col are not null
    // 2) Currently one group by column is supported
    macoro::task<> Average::avg(
        ColRef groupByCol,
        std::vector<ColRef> avgCol,
        SharedTable& out,
        oc::PRNG& prng,
        OleGenerator& ole,
        coproto::Socket& sock)
    {

        MC_BEGIN(macoro::task<>, this, groupByCol, avgCol, &out, &prng, &ole, &sock,
            keys = BinMatrix{},
            data = BinMatrix{},
            temp = BinMatrix{},
            sPerm = AdditivePerm{},
            sort = RadixSort{},
            controlBits = BinMatrix{},
            offsets = std::vector<OmJoin::Offset>{},
            addCir = AggTree::Operator{},
            aggTree = AggTree{},
            perm = ComposedPerm{}
        );

        keys = groupByCol.mCol.mData;

        if (mInsecurePrint)
            MC_AWAIT(print(keys, sock, (int)ole.mRole, "preSort-keys"));


        sort.mInsecureMock = mInsecureMockSubroutines;
        sPerm.mInsecureMock = mInsecureMockSubroutines;

        MC_AWAIT(sort.genPerm(keys, sPerm, ole, sock));
        concatColumns(groupByCol, avgCol, data, offsets, ole);

        if (mInsecurePrint)
            MC_AWAIT(print(data, sock, (int)ole.mRole, "preSort-data", offsets));

        temp.resize(data.numEntries(), data.bytesPerEntry() * 8);
        // temp1.resize(keys.numEntries(), keys.bitsPerEntry());
        // Apply the sortin permutation to both keys & concat columns
        MC_AWAIT(sPerm.apply(data, temp, prng, sock, ole, true));
        std::swap(data, temp);

        if (mInsecurePrint)
            MC_AWAIT(print(data, sock, (int)ole.mRole, "sort-data", offsets));

        temp.resize(keys.numEntries(), keys.bytesPerEntry() * 8);
        MC_AWAIT(sPerm.apply(keys, temp, prng, sock, ole, true));
        std::swap(keys, temp);

        if (mInsecurePrint)
            MC_AWAIT(print(keys, sock, (int)ole.mRole, "sort-keys"));

        // compare adjacent keys. controlBits[i] = 1 if k[i]==k[i-1].
        MC_AWAIT(getControlBits(keys, sock, controlBits, ole));

        if (mInsecurePrint)
            MC_AWAIT(print(controlBits, sock, (int)ole.mRole, "controlbits"));


        // oc::BetaLibrary::Optimized::Depth shouldn't be hardcoded 
        addCir = getAddCircuit(offsets, op);

        MC_AWAIT(aggTree.apply(data, controlBits, addCir, AggTreeType::Suffix, sock, ole, temp));
        std::swap(data, temp);

        if (mInsecurePrint)
            MC_AWAIT(print(data, sock, (int)ole.mRole, "agg-data", offsets));

        // TODO, i dont think this is the right variable name.
        // Should this still be here? is there a better way, if(debug) copy state to members;
        if (!mInsecureMockSubroutines)
        {
            perm.init(data.numEntries(), (int)ole.mRole, prng);

            //TODO: add perm prococessing once peter merges the new code.

            temp.resize(data.numEntries(), data.bytesPerEntry() * 8);
            MC_AWAIT(perm.apply<u8>(data.mData, temp.mData, sock, ole, true));
            std::swap(data, temp);

            temp.resize(keys.numEntries(), keys.bytesPerEntry() * 8);
            MC_AWAIT(perm.apply<u8>(keys.mData, temp.mData, sock, ole, true));
            std::swap(keys, temp);

            temp.resize(controlBits.numEntries(), controlBits.bytesPerEntry() * 8);
            MC_AWAIT(perm.apply<u8>(controlBits.mData, temp.mData, sock, ole, true));
            std::swap(controlBits, temp);
        }


        // Revealing control bits
        if (ole.mRole == OleGenerator::Role::Receiver)
        {
            temp.resize(controlBits.numEntries(), controlBits.bitsPerEntry());
            MC_AWAIT(sock.recv(temp.mData));
            temp = reveal(temp, controlBits);
            std::swap(controlBits, temp);
            MC_AWAIT(sock.send(coproto::copy(controlBits.mData)));
        }
        else
        {
            MC_AWAIT(sock.send(coproto::copy(controlBits.mData)));
            temp.resize(controlBits.numEntries(), controlBits.bitsPerEntry());
            MC_AWAIT(sock.recv(temp.mData));
            std::swap(controlBits, temp);
        }


        getOutput(out, avgCol, groupByCol, keys, data, controlBits, offsets);

        // TODO: remove, no mIsActive =  all active.
        // Manually setting the isActive flag
        out.mIsActive.resize(out.mColumns[0].mData.numEntries());
        if (ole.mRole == OleGenerator::Role::Receiver)
        {
            for (u64 i = 0; i < out.mIsActive.size(); i++)
                out.mIsActive[i] = 1;
        }

        MC_END();
    }


    void Average::getOutput(
        SharedTable& out,
        std::vector<ColRef> avgCol,
        ColRef groupByCol,
        BinMatrix& keys,
        BinMatrix& data,
        BinMatrix& controlBits,
        std::vector<OmJoin::Offset>& offsets)
    {
        // Need to update the mIsActive somewhere

        // Counting the total number of rows in the 
        u64 nOutRows = 0;
        assert(data.numEntries() == keys.numEntries());
        for (u64 i = 0; i < data.numEntries(); i++)
        {
            // Only where Control Bit is zero, we have our desire value
            if (controlBits.mData(i, 0) == 0)
                nOutRows++;
        }

        // populateOutTable() can be used here
        u64 nAvg = avgCol.size();
        out.mColumns.resize(nAvg + 2); // Average Cols + Group By Cols + Count Col

        // Adding the group by column info
        out.mColumns[0].mName = groupByCol.mCol.mName;
        out.mColumns[0].mBitCount = groupByCol.mCol.getByteCount() * 8;
        out.mColumns[0].mType = groupByCol.mCol.mType;
        out.mColumns[0].mData.resize(nOutRows, groupByCol.mCol.mBitCount);

        // Adding the average cols
        for (u64 i = 0; i < nAvg; i++)
        {
            out.mColumns[i + 1].mName = avgCol[i].mCol.mName;
            out.mColumns[i + 1].mBitCount = avgCol[i].mCol.getByteCount() * 8;
            out.mColumns[i + 1].mType = avgCol[i].mCol.mType;
            out.mColumns[i + 1].mData.resize(nOutRows, avgCol[i].mCol.mBitCount);
        }

        // Adding the count col
        out.mColumns[nAvg + 1].mName = "Count";
        out.mColumns[nAvg + 1].mBitCount = sizeof(oc::u64) * 8;
        out.mColumns[nAvg + 1].mType = TypeID::IntID;
        out.mColumns[nAvg + 1].mData.resize(nOutRows, sizeof(oc::u64) * 8);


        assert(data.numEntries() == keys.numEntries());
        u64 curOutRow = 0;
        for (u64 i = 0; i < data.numEntries(); i++)
        {
            assert(curOutRow <= nOutRows);
            if (controlBits.mData(i, 0) == 0)
            {
                // Storing the Group By Column
                assert(out.mColumns[0].mData.cols() == keys.cols());
                memcpy(out.mColumns[0].mData.data(curOutRow), keys.data(i), keys.cols());

                // Copying the average columns
                for (u64 j = 0; j < offsets.size(); j++)
                {
                    memcpy(out.mColumns[j + 1].mData.data(curOutRow),
                        &data(i, offsets[j].mStart / 8),
                        out.mColumns[j + 1].getByteCount());

                }
                curOutRow++;
            }
        }

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
        OleGenerator& ole)
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
        bin.init(n, cir, ole);

        bin.setInput(0, sKeys.subMatrix(0, n));
        bin.setInput(1, sKeys.subMatrix(1, n));

        MC_AWAIT(bin.run(sock));

        out.resize(n, 1);
        bin.getOutput(0, out);
        out.mData(0) = 0;

        MC_END();
    }


}