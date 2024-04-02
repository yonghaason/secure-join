#include "Table.h"
#include "secure-join/Util/Util.h"
#include "secure-join/Sort/RadixSort.h"
#include "secure-join/Aggregate/Where.h"
#include "secure-join/Join/OmJoin.h"

namespace secJoin
{

    void populateOutTable(Table& out, BinMatrix& actFlag, BinMatrix& data)
    {
        if(out.getColumnInfo().size() == 0)
            throw std::runtime_error("out table not initialzied with column info " LOCATION);

        if(actFlag.numEntries() == 0)
            throw std::runtime_error("ActFlag is empty " LOCATION);

        u64 nOutRows = out.rows();

        u64 curPtr = 0;
        for(u64 i = 0; i < actFlag.numEntries(); i++)
        {
            u64 byteStartIdx = 0;
            if(actFlag(i, 0) == 1)
            {
                // dump data into the out
                for(u64 j = 0; j < out.cols(); j++)
                {
                    auto bytes = out.mColumns[j].getByteCount();
                    memcpy(out.mColumns[j].mData.data(curPtr), &data.mData(i, byteStartIdx) ,bytes);
                    byteStartIdx += bytes;
                }
                curPtr++;
            }

            if(curPtr >=  nOutRows)
                break;
        }
    }



    u64 countActiveRows(Table& T)
    {
        return countActiveRows(T.mIsActive);
    }

    u64 countActiveRows(std::vector<u8>& actFlag)
    {
        oc::MatrixView<u8> oo(actFlag.data(), actFlag.size(), 1);
        return countActiveRows( oo);
    }

    u64 countActiveRows(oc::MatrixView<u8> actFlag)
    {
        u64 nOutRows = 0;
        for(u64 i = 0; i < actFlag.rows(); i++)
        {
            assert(actFlag(i, 0) == 1 || actFlag(i, 0) == 0);
//            if( *oc::BitIterator((u8*)actFlag.data(i), 0) == 1)
            nOutRows += actFlag(i,0);


        }
        return nOutRows;
    }

    void concatTable(Table& T, BinMatrix& out)
    {
        std::vector<OmJoin::Offset> offsets;
        std::vector<BinMatrix*> data;

        u64 cols = T.cols();
        offsets.reserve(cols);
        data.reserve(cols);

        u64 dateBitsPerEntry = 0;

        // Setting up the offset for OmJoin::concatColumns
        for(u64 i = 0; i < cols; i++)
        {
            auto name  = T.mColumns[i].mName;
            auto bytes = T.mColumns[i].getByteCount();
            auto bits = T.mColumns[i].getBitCount();
            offsets.emplace_back( OmJoin::Offset{ dateBitsPerEntry, bits, name } );
            dateBitsPerEntry += bytes * 8;

            data.emplace_back(&T.mColumns[i].mData);
        }

        u64 actFlagSize = T.mIsActive.size() > 0 ? 8 : 0;

        out.resize(T.rows(), dateBitsPerEntry + actFlagSize);
        OmJoin::concatColumns(out, data, offsets);

        // Appending the ActFlag
        if(actFlagSize)
        {
            for(u64 i = 0; i < T.rows(); i++)
                out(i , dateBitsPerEntry/8) = T.mIsActive[i];
        }

    }


    macoro::task<> revealLocal(const Table& share, coproto::Socket& sock, Table& out)
    {
        MC_BEGIN(macoro::task<>, &share, &sock, &out,
            remoteShare = Table(),
            i = u64()
        );

        remoteShare.init(share.rows(), share.getColumnInfo());
        for (i = 0; i < remoteShare.mColumns.size(); i++)
        {
            MC_AWAIT(sock.recv(remoteShare.mColumns[i].mData.mData));
        }
        if (share.mIsActive.size() > 0)
        {
            remoteShare.mIsActive.resize(share.mIsActive.size());
            MC_AWAIT(sock.recv(remoteShare.mIsActive));
        }
        out = reveal(share, remoteShare, false);

        MC_END();
    }


    macoro::task<> revealRemote(const Table& share, coproto::Socket& sock)
    {
        MC_BEGIN(macoro::task<>, &share, &sock, i = u64());

        for (i = 0; i < share.mColumns.size(); i++)
        {
            MC_AWAIT(sock.send(coproto::copy(share.mColumns[i].mData.mData)));
        }

        // std::move() will the delete the local share
        if (share.mIsActive.size() > 0)
        {
            MC_AWAIT(sock.send(coproto::copy(share.mIsActive)));
        }
        MC_END();
    }

    void readBinFile(Table& tb, std::istream& in, oc::u64 rowCount)
    {
        u64 totalBytes = 0;
        for (u64 i = 0; i < tb.cols(); i++)
            totalBytes += tb.mColumns[i].getByteCount();

        std::vector<char> buffer(totalBytes * BATCH_READ_ENTRIES, 0);
        u64 rowPtr = 0;
        while (!in.eof()) {
            in.read(buffer.data(), buffer.size());
            std::streamsize readBytes = in.gcount();

            // Checking if the file has enough bytes
            if (readBytes % totalBytes != 0)
                throw RTE_LOC;

            u64 rows = readBytes / totalBytes;

            if (rowPtr + rows > rowCount)
                throw RTE_LOC;

            u64 buffptr = 0;
            for (oc::u64 rowNum = 0; rowNum < rows; rowNum++, rowPtr++)
            {
                for (oc::u64 colNum = 0; colNum < tb.cols(); colNum++)
                {
                    u64 bytes = tb.mColumns[colNum].getByteCount();
                    memcpy(tb.mColumns[colNum].mData.data(rowPtr),
                        &buffer[buffptr],
                        bytes);
                    buffptr += bytes;
                }
            }
        }
    }

    void readTxtFile(Table& tb, std::istream& in, oc::u64 rowCount)
    {
        std::string line, word;

        // Skipping the header
        getline(in, line);

        for (oc::u64 rowNum = 0; rowNum < rowCount; rowNum++)
        {
            getline(in, line);

            oc::u64 colNum = 0;
            std::stringstream str(line);
            while (getline(str, word, CSV_COL_DELIM))
            {
                if (tb.mColumns[colNum].getTypeID() == TypeID::StringID)
                {
                    oc::u64 minSize = tb.mColumns[colNum].getByteCount() > word.size() ?
                        word.size() : tb.mColumns[colNum].getByteCount();

                    memcpy(tb.mColumns[colNum].mData.data(rowNum), word.data(), minSize);
                }
                else if (tb.mColumns[colNum].getTypeID() == TypeID::IntID)
                {
                    if (tb.mColumns[colNum].getByteCount() <= 4)
                    {
                        oc::i32 number = stoi(word);
                        memcpy(tb.mColumns[colNum].mData.data(rowNum), &number, sizeof(i32));
                    }
                    else if (tb.mColumns[colNum].getByteCount() <= 8)
                    {
                        oc::i64 number = stoll(word);
                        memcpy(tb.mColumns[colNum].mData.data(rowNum), &number, sizeof(i64));
                    }
                    else
                    {
                        std::string temp = tb.mColumns[colNum].mName
                            + " can't be stored as int type\n"
                            + LOCATION;
                        throw std::runtime_error(temp);
                    }

                }

                colNum++;
            }
        }
    }

    void populateTable(Table& tb, std::istream& in, oc::u64 rowCount, bool isBin)
    {
        if (isBin)
            readBinFile(tb, in, rowCount);
        else
            readTxtFile(tb, in, rowCount);
    }

    void populateTable(Table& tb, std::string& fileName, oc::u64 rowCount, bool isBin)
    {
        std::ifstream file;
        if (isBin)
            file.open(fileName, std::ifstream::binary);
        else
            file.open(fileName, std::ios::in);

        if (!file.good())
        {
            std::cout << "Could not open the file " << fileName << std::endl;
            throw RTE_LOC;
        }
        populateTable(tb, file, rowCount, isBin);
        file.close();
    }

    void share(Table& table,
        std::array<Table, 2>& shares,
        PRNG& prng)
    {
        shares[0].mColumns.resize(table.mColumns.size());
        shares[1].mColumns.resize(table.mColumns.size());
        for (oc::u64 i = 0; i < table.mColumns.size(); i++)
        {
            std::array<BinMatrix, 2> temp;
            share(table.mColumns[i].mData, temp[0], temp[1], prng);

            for (u64 k = 0;k < 2; ++k)
            {
                shares[k].mColumns[i].mBitCount = table.mColumns[i].mBitCount;
                shares[k].mColumns[i].mName = table.mColumns[i].mName;
                shares[k].mColumns[i].mType = table.mColumns[i].mType;
                shares[k].mColumns[i].mData = temp[k];
            }
        }

        shares[0].mIsActive.resize(table.mIsActive.size());
        shares[1].mIsActive.resize(table.mIsActive.size());

        prng.get(shares[0].mIsActive.data(), shares[0].mIsActive.size());
        for (u64 i = 0; i < table.mIsActive.size(); i++)
            shares[1].mIsActive[i] = shares[0].mIsActive[i] ^ table.mIsActive[i];

    }

    bool eq(span<const u8> l, span<const u8> r)
    {
        assert(l.size() == r.size());
        for (u64 i = 0; i < l.size(); ++i)
            if (l[i] != r[i])
                return false;
        return true;
    }

    // bool lessThan(span<const u8> l, span<const u8> r)
    // {
    //     assert(l.size() == r.size());
    //     for (u64 i = l.size() - 1; i < l.size(); --i)
    //         if (l[i] < r[i])
    //             return true;
    //     return false;
    // }
    Perm sort(const ColRef& x)
    {
        return sort(x.mCol.mData);
        // Perm res(x.mCol.rows());

        // std::stable_sort(res.begin(), res.end(),
        //     [&](const auto& a, const auto& b) {
        //         return lessThan(x.mCol.mData[a], x.mCol.mData[b]);
        //         // return (k64[a] < k64[b]);
        //         // for (u64 i = x.mCol.cols() - 1; i < x.mCol.cols(); --i)
        //         //     if (x.mCol.mData(a, i) < x.mCol.mData(b, i))
        //         //         return true;
        //         // return false;
        //     });
        // return res;
    }

    Table average(ColRef groupByCol,
        std::vector<ColRef> avgCol,
        bool remDummies,
        Perm randPerm)
    {
        u64 m = avgCol.size();
        u64 n0 = groupByCol.mCol.rows();
        std::vector<u8> actFlag = groupByCol.mTable.mIsActive;

        // Generating the permutation
        auto groupByPerm = sort(groupByCol);


        auto permForward = PermOp::Regular;
        BinMatrix temp;
        temp.resize(groupByCol.mCol.mData.numEntries(), groupByCol.mCol.mData.bytesPerEntry() * 8);
        groupByPerm.apply<u8>(groupByCol.mCol.mData, temp, permForward);
        std::swap(groupByCol.mCol.mData, temp);

        if(actFlag.size() > 0)
            actFlag = groupByPerm.apply<u8>(actFlag);


        // Applying permutation to all the average cols
        for (u64 i = 0; i < m; i++)
        {
            temp.resize(avgCol[i].mCol.mData.numEntries(),
                avgCol[i].mCol.mData.bytesPerEntry() * 8);
            groupByPerm.apply<u8>(avgCol[i].mCol.mData, temp, permForward);
            std::swap(avgCol[i].mCol.mData, temp);
        }


        // Adding a Columns of 1's for calculating average
        BinMatrix ones(n0, sizeof(oc::u64) * 8);
        for (oc::u64 i = 0; i < n0; i++)
            ones(i, 0) = 1;

        Table out;

        populateOutTable(out, avgCol, groupByCol, n0);
        out.mIsActive.resize(n0);

        // Base Case
        if(n0 == 0)
            return out;

        // Creating a vector of inputs for Beta Circuit evaluation
        std::vector<oc::BetaCircuit*> cir;
        cir.resize(m + 1);
        std::vector<oc::BitVector> inputs(2 * cir.size()), outputs(cir.size());

        oc::BetaLibrary lib;
        for (u64 i = 0; i < m; i++)
        {
            u64 size = avgCol[i].mCol.getByteCount() * 8;
            cir[i] = lib.int_int_add(size, size, size, oc::BetaLibrary::Optimized::Depth);
            inputs[2 * i].reset(size);
            outputs[i].reset(size);

        }

        // Adding the ciruit for the BinMatrix of ones
        u64 size = ones.bytesPerEntry() * 8;
        cir[m] = lib.int_int_add(size, size, size, oc::BetaLibrary::Optimized::Depth);
        inputs[2 * m].reset(size);
        outputs[m].reset(size);

        for (i64 row = n0 - 1; row >= 0; row--)
        {

            if( (row < n0 - 1) && !eq(groupByCol.mCol.mData[row], groupByCol.mCol.mData[row + 1]))
            {
                copyTableEntry(out, groupByCol, avgCol, inputs, actFlag, row + 1);

                // reset the 2 * i location for input
                for (u64 i = 0; i < m; i++)
                {
                    u64 size = avgCol[i].mCol.getByteCount() * 8;
                    inputs[2 * i].reset(size);
                }
                u64 size = ones.bytesPerEntry() * 8;
                inputs[2 * m].reset(size);
            }


            // Running Circuit for each cols
            for (u64 col = 0; col < m; col++)
            {
                std::vector<oc::BitVector> tempInputs =
                        { inputs[2 * col], inputs[2 * col + 1] };

                inputs[2 * col] = cirEval(cir[col], tempInputs,
                                          outputs[col], avgCol[col].mCol.mData.data(row),
                                          avgCol[col].mCol.getBitCount(),
                                          avgCol[col].mCol.getByteCount()
                                            );
            }

            // Run the circuit of ones:
            std::vector<oc::BitVector> tempInputs = { inputs[2 * m], inputs[2 * m + 1] };
            inputs[2 * m] = cirEval(cir[m], tempInputs,
                                    outputs[m], ones.mData.data(row),
                                    ones.bitsPerEntry(),
                                    ones.bytesPerEntry()
                                    );

            if(row == 0)
                    copyTableEntry(out, groupByCol, avgCol, inputs, actFlag, row);

        }

        // Applying inverse perm to all the columns
        auto permBackward = PermOp::Inverse;

        auto backPerm = remDummies && randPerm.size() > 0
                        ? randPerm : groupByPerm;


        for (u64 i = 0; i < out.cols(); i++)
        {
            temp.resize(out[i].mCol.mData.numEntries(),
                        out[i].mCol.mData.bytesPerEntry() * 8);
            backPerm.apply<u8>(out[i].mCol.mData, temp, permBackward);
            std::swap(out[i].mCol.mData, temp);
        }

        // Applying inverse perm to the active flag
        out.mIsActive = backPerm.applyInv<u8>(out.mIsActive);

        if(remDummies)
        {
            Table temp = removeDummies(out);
            std::swap(temp, out);;
        }

        return out;
    }


    Table removeDummies(Table& T)
    {
        if(T.mIsActive.size() == 0)
            return T;

        u64 nOutRows = countActiveRows(T);

        Table out(nOutRows, T.getColumnInfo());
        out.mIsActive.resize(nOutRows);

        u64 curPtr = 0;
        for(u64 i = 0; i < T.rows(); i++)
        {
            if(T.mIsActive[i] == 1)
            {
                for(u64 j = 0; j < T.cols(); j++)
                {
                    memcpy( out.mColumns[j].mData.data(curPtr) ,
                            T.mColumns[j].mData.data(i),
                            T.mColumns[j].getByteCount());
                }
                out.mIsActive[curPtr] = T.mIsActive[i];
                curPtr++;
            }

            if(curPtr >=  nOutRows)
                break;
        }

        return out;

    }

    Table where(Table& T,
        const std::vector<ArrGate>& gates,
        const std::vector<std::string>& literals,
        const std::vector<std::string>& literalsType,
        const u64 totalCol,
        const std::unordered_map<u64, u64>& map,
        bool print,
        bool remDummies,
        Perm randPerm)
    {
        Where wh;
        BetaCircuit cd = wh.genWhCir(T, gates, literals, literalsType, totalCol, map, print);
        u64 nT = T.rows();

        std::vector<u8> outActFlags;
        outActFlags.resize(nT);

        for (u64 j = 0; j < nT; j++)
        {
            std::vector<oc::BitVector> inputs;
            inputs.reserve(wh.mGmwIn.size());
            oc::BitVector tmp(1);
            std::vector<BitVector> outputs = { tmp };
            for (u64 k = 0; k < wh.mGmwIn.size(); k++)
            {
                BitVector bitVec(wh.mGmwIn[k].mData.data(j), wh.mGmwIn[k].bytesPerEntry() * 8);
                inputs.emplace_back(bitVec);
            }

            cd.evaluate(inputs, outputs);
            outActFlags[j] = outputs[0][0];
        }
        Table out(nT, T.getColumnInfo());
        out.mIsActive.resize(nT);
        for (u64 j = 0; j < nT; j++)
        {
            if (outActFlags[j] == 1)
            {
                for (u64 k = 0; k < T.mColumns.size(); k++)
                {
                    memcpy(out.mColumns[k].mData.data(j),
                        T.mColumns[k].mData.data(j),
                        T.mColumns[k].getByteCount());
                }
                out.mIsActive[j] = 1;
            }
        }

        if(remDummies)
        {
            // Applying rand perm to all the columns
            auto permBackward = PermOp::Inverse;

            if(randPerm.size() <= 1)
                return out;

            for (u64 i = 0; i < out.cols(); i++)
            {
                BinMatrix temp(out[i].mCol.mData.numEntries(),
                            out[i].mCol.mData.bytesPerEntry() * 8);
                randPerm.apply<u8>(out[i].mCol.mData, temp, permBackward);
                std::swap(out[i].mCol.mData, temp);
            }
            // Applying rand perm to the active flag
            out.mIsActive = randPerm.applyInv<u8>(out.mIsActive);

            Table temp = removeDummies(out);
            std::swap(temp, out);;
        }


        return out;

    }

    void copyTableEntry(
        Table& out,
        ColRef groupByCol,
        std::vector<ColRef> avgCol,
        std::vector<oc::BitVector>& inputs,
        std::vector<u8>& oldActFlag,
        u64 row)
    {

        out.mIsActive[row] = oldActFlag.size() > 0 ? oldActFlag[row] : 1;

        if(out.mIsActive[row] == 0)
            return;

        u64 m = avgCol.size();
        u64 totRows = out.rows();
        assert(row < totRows);
        // Copying the groupby column
        assert(out.mColumns[0].mData.cols() == groupByCol.mCol.mData.cols());
        memcpy(out.mColumns[0].mData.data(row),
            groupByCol.mCol.mData.data(row ),
            groupByCol.mCol.mData.cols());

        // Copying the average column
        for (u64 col = 0; col < m; col++)
        {
            assert(out.mColumns[col + 1].mData.bytesPerEntry() == inputs[2 * col].sizeBytes());
            memcpy(out.mColumns[col + 1].mData.data(row),
                inputs[2 * col].data(), inputs[2 * col].sizeBytes());
        }

        // Copying the ones column 
        memcpy(out.mColumns[m + 1].mData.data(row),
            inputs[2 * m].data(), inputs[2 * m].sizeBytes());

    }

    void populateOutTable(
        Table& out,
        std::vector<ColRef> avgCol,
        ColRef groupByCol,
        u64 nOutRows)
    {
        u64 m = avgCol.size();
        // u64 n0 = groupByCol.mCol.rows();

        out.mColumns.resize(m + 2); // Average Cols + Group By Cols + Count Col

        // Adding the group by column info
        out.mColumns[0].mName = groupByCol.mCol.mName;
        auto bits = groupByCol.mCol.getByteCount() * 8;
        out.mColumns[0].mBitCount = bits;
        out.mColumns[0].mType = groupByCol.mCol.mType;
        out.mColumns[0].mData.resize(nOutRows, bits);

        // Adding the average cols
        for (u64 i = 0; i < m; i++)
        {
            out.mColumns[i + 1].mName = avgCol[i].mCol.mName;
            auto bits = avgCol[i].mCol.getByteCount() * 8;
            out.mColumns[i + 1].mBitCount = bits;
            out.mColumns[i + 1].mType = avgCol[i].mCol.mType;
            out.mColumns[i + 1].mData.resize(nOutRows, bits);
        }

        // Adding the count col
        out.mColumns[m + 1].mName = "Count";
        out.mColumns[m + 1].mBitCount = sizeof(oc::u64) * 8;
        out.mColumns[m + 1].mType = TypeID::IntID;
        out.mColumns[m + 1].mData.resize(nOutRows, sizeof(oc::u64) * 8);

    }

    oc::BitVector cirEval(oc::BetaCircuit* cir, std::vector<oc::BitVector>& inputs,
        oc::BitVector& output, u8* data, u64 bits, u64 bytes)
    {

        auto size = bytes * 8;
        // Filling extra bits with zero
        u64 rem = size - bits;
        inputs[1].reset(rem);
        inputs[1].append(data, bits);

        // i64 cc = 0;
        // memcpy(&cc, inputs[0].data(), inputs[0].sizeBytes());  
        // std::cout << " input1: " << cc;                  

        std::vector<oc::BitVector> tempOutputs = { output };
        cir->evaluate(inputs, tempOutputs);

        return tempOutputs[0];
    }

    Table join(const ColRef& l, const ColRef& r, std::vector<ColRef> select)
    {
        if (l.mCol.getBitCount() != r.mCol.getBitCount())
            throw RTE_LOC;
        // std::unordered_map<oc::block, u64>
        auto LPerm = sort(l);
        auto RPerm = sort(r);

        // std::cout << " L " << std::endl;
        // for (u64 i = 0; i < LPerm.size(); ++i)
        // {
        //     std::cout << i << ": " << hex(l.mCol.mData[LPerm[i]]) << std::endl;
        // }

        std::vector<std::array<u64, 2>> I;
        std::vector<u64> rIdx(r.mCol.rows());
        I.reserve(r.mCol.rows());

        u64 lIdx = 0;
        for (u64 i = 0; i < r.mCol.rows(); ++i)
        {
            while (
                lIdx < l.mCol.rows() &&
                lessThan(l.mCol.mData[LPerm[lIdx]], r.mCol.mData[RPerm[i]]))
            {
                if (lIdx)
                {
                    if (eq(l.mCol.mData[LPerm[lIdx - 1]], l.mCol.mData[LPerm[lIdx]]))
                        throw RTE_LOC;// L duplicate key
                }
                ++lIdx;
            }

            if (lIdx < l.mCol.rows())
            {
                if (eq(l.mCol.mData[LPerm[lIdx]], r.mCol.mData[RPerm[i]]))
                {
                    I.push_back({ LPerm[lIdx], RPerm[i] });
                    rIdx[RPerm[i]] = 1;
                }
            }
        }

        for (u64 i = 1; i < rIdx.size(); ++i)
        {
            rIdx[i] += rIdx[i - 1];
        }
        if (rIdx.back() != I.size())
            throw RTE_LOC;

        std::vector<ColumnInfo> colInfo(select.size());
        for (u64 i = 0; i < colInfo.size(); ++i)
        {
            if (&select[i].mTable != &l.mTable &&
                &select[i].mTable != &r.mTable)
                throw std::runtime_error("select statement doesnt match Left and Right table.");

            colInfo[i] = select[i].mCol.getColumnInfo();
        }
        Table ret(I.size(), colInfo);

        for (u64 i = 0; i < I.size(); ++i)
        {

            for (u64 j = 0; j < colInfo.size(); ++j)
            {
                auto d = rIdx[I[i][1]] - 1;
                auto lr = (&select[j].mTable == &r.mTable) ? 1 : 0;
                auto src = select[j].mCol.mData.data(I[i][lr]);
                auto dst = ret.mColumns[j].mData.data(d);
                auto size = ret.mColumns[j].mData.cols();

                memcpy(dst, src, size);
            }
        }

        return ret;
    }

    std::ostream& operator<<(std::ostream& o, const Table& t)
    {
        auto width = 8;
        auto separator = ' ';
        auto printElem = [&](auto&& t)
            {
                o << std::left << std::setw(width) << std::setfill(separator) << t << " ";
            };

        o << "      ";
        for (u64 i = 0; i < t.mColumns.size(); ++i)
            printElem(t.mColumns[i].mName);

        std::cout << "\n-------------------------------" << std::endl;
        for (u64 i = 0; i < t.rows(); ++i)
        {
            o << std::setw(2) << std::setfill(' ') << i << " ";
            if (t.mIsActive.size())
                o << (int)t.mIsActive[i];
            else
                o << 1;

            o << ": ";
            for (u64 j = 0; j < t.mColumns.size(); ++j)
            {
                if (t.mColumns[j].mType == TypeID::StringID)
                    printElem(std::string((const char*)t.mColumns[j].mData.data(i), t.mColumns[j].getByteCount()));
                else
                    printElem(hex(t.mColumns[j].mData.data(i), t.mColumns[j].getByteCount()));
            }
            o << "\n";

        }

        return o;

    }

    Table applyPerm(Table& T, Perm& perm)
    {
        Table permT = T;

        for (u64 i = 0; i < T.cols(); i++)
        {
            BinMatrix temp(permT.mColumns[i].mData.numEntries(),
                permT.mColumns[i].mData.bitsPerEntry());
            perm.apply<u8>(permT.mColumns[i].mData, temp, PermOp::Regular);
            std::swap(permT.mColumns[i].mData, temp);
        }

        if (permT.mIsActive.size() > 0)
        {
            std::vector<u8> temp = perm.apply<u8>(permT.mIsActive);
            std::swap(permT.mIsActive, temp);
        }

        return permT;
    }


}
