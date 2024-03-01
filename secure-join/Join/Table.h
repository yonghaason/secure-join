#pragma once

#include "coproto/Common/span.h"
#include <cryptoTools/Common/MatrixView.h>
#include <fstream>
#include "secure-join/Util/Matrix.h"
#include "secure-join/Defines.h"
#include "coproto/coproto.h"
#include "cryptoTools/Common/BitVector.h"
#include "cryptoTools/Circuit/BetaCircuit.h"
#include "secure-join/Util/ArrGate.h"
#include "secure-join/Perm/Permutation.h"
#include <vector>

namespace secJoin
{
    enum class TypeID
    {
        IntID = 0,
        StringID = 1
    };
    struct ColumnInfo
    {
        ColumnInfo() = default;
        ColumnInfo(std::string name, TypeID type, u64 size)
            : mName(std::move(name))
            , mType(type)
            , mBitCount(size)
        {
            if (mType == TypeID::StringID && mBitCount % 8)
                throw std::runtime_error("String type must have a multiple of 8 bits. " LOCATION);
        }

        u64 getBitCount() const { return mBitCount; }
        u64 getByteCount() const { return oc::divCeil(mBitCount, 8); }

        std::string mName;
        TypeID mType;
        u64 mBitCount = 0;


        bool operator==(const ColumnInfo& o) const
        {
            return mName == o.mName && mType == o.mType && mBitCount == o.mBitCount;
        }
        bool operator!=(const ColumnInfo& o) const
        {
            return !(*this == o);
        }
    };

    class Column : public ColumnInfo
    {
    public:
        Column() = default;
        Column(const Column&) = default;
        Column(Column&&) = default;
        Column& operator=(const Column&) = default;
        Column& operator=(Column&&) = default;

        Column(std::string name, TypeID type, u64 size)
            : ColumnInfo(std::move(name), type, size)
        {}

        u64 getByteCount() const { return (getBitCount() + 7) / 8; }
        u64 getBitCount() const { return mBitCount; }
        TypeID getTypeID() const { return mType; }

        secJoin::BinMatrix mData;

        u8* data() { return mData.data(); }
        auto size() { return mData.size(); }
        const u8* data() const { return mData.data(); }
        u64 rows() { return mData.rows(); }
        u64 cols() { return mData.cols(); }


        ColumnInfo getColumnInfo() const
        {
            return { mName, mType, mBitCount };
        }

        bool operator!=(const Column& o) const
        {
            return !(*this == o);
        }
        bool operator==(const Column& o) const
        {
            if (mBitCount != o.mBitCount)
                return false;
            if (mName != o.mName)
                return false;
            return mData == o.mData;
        }
    };

    class Table;

    struct ColRef
    {
        Table& mTable;
        Column& mCol;

        ColRef(Table& t, Column& c)
            : mTable(t), mCol(c)
        {
        }

        ColRef(const ColRef&) = default;
        ColRef(ColRef&&) = default;
    };


    class Table
    {
    public:
        std::vector<u8> mIsActive;
        std::vector<Column> mColumns;

        Table() = default;
        Table(const Table&) = default;
        Table(Table&&) = default;

        Table& operator=(const Table&) = default;
        Table& operator=(Table&&) = default;

        Table(u64 rows, std::vector<ColumnInfo> columns)
        {
            init(rows, columns);
        }

        void init(u64 rows, std::vector<ColumnInfo> columns)
        {
            mColumns.reserve(columns.size());
            // mColumns.resize(columns.size());
            for (u64 i = 0; i < columns.size(); ++i)
            {
                mColumns.emplace_back(
                    columns[i].mName,
                    columns[i].mType,
                    columns[i].mBitCount);
                // auto size = (std::get<2>(columns[i]) + 7) / 8;
                mColumns.back().mData.resize(rows, columns[i].mBitCount);
            }
        }

        std::vector<ColumnInfo> getColumnInfo() const
        {
            std::vector<ColumnInfo> ret(mColumns.size());
            for (u64 i = 0; i < ret.size(); ++i)
            {
                ret[i] = mColumns[i].getColumnInfo();
            }
            return ret;
        }

        void resize(u64 n)
        {
            for (u64 i = 0; i < mColumns.size(); ++i)
                mColumns[i].mData.resize(n, mColumns[i].mBitCount);
        }

        u64 rows() const { return mColumns.size() ? mColumns[0].mData.numEntries() : 0; }

        u64 cols() { return mColumns.size() ? mColumns.size() : 0; }

        ColRef operator[](std::string c)
        {
            for (u64 i = 0; i < mColumns.size(); ++i)
            {
                if (mColumns[i].mName == c)
                    return { *this, mColumns[i] };
            }

            throw std::runtime_error(c + " Col not found " + LOCATION + "\n");
        }

        ColRef operator[](u64 i)
        {
            return { *this, mColumns[i] };
        }

        bool operator!=(const Table& o) const
        {
            return !(*this == o);
        }
        bool operator==(const Table& o) const
        {
            if (getColumnInfo() != o.getColumnInfo())
                return false;
            if (rows() != o.rows())
                return false;

            for (u64 j = 0; j < mColumns.size(); ++j)
            {
                if (mColumns[j] != o.mColumns[j])
                    return false;
            }

            return true;
        }
    };


    std::ostream& operator<<(std::ostream& o, const Table& t);

    struct JoinQuerySchema
    {
        struct SelectCol
        {
            ColumnInfo mCol;
            bool mIsLeftColumn;
            u64 getBitCount() const { return mCol.getBitCount(); }
            u64 getByteCount() const { return mCol.getByteCount(); }
            std::string name() const { return mCol.mName; }
        };
        u64 mLeftSize = 0, mRightSize = 0;
        ColumnInfo mKey;
        std::vector<SelectCol> mSelect;
    };

    struct JoinQuery
    {
        // the unique join key.
        ColRef mLeftKey;

        // the join key with duplicates.
        ColRef mRightKey;

        // the columns to be selected.
        std::vector<ColRef> mSelect;


        JoinQuery(const ColRef& leftKey, const ColRef& rightKey, std::vector<ColRef> select)
            : mLeftKey(leftKey)
            , mRightKey(rightKey)
            , mSelect(std::move(select))
        {
            for (auto& c : mSelect)
            {
                if (&c.mTable != &mLeftKey.mTable &&
                    &c.mTable != &mRightKey.mTable)
                    throw RTE_LOC;
            }
        }

        operator JoinQuerySchema()
        {
            JoinQuerySchema ret;
            ret.mLeftSize = mLeftKey.mTable.rows();
            ret.mRightSize = mRightKey.mTable.rows();
            ret.mKey = mLeftKey.mCol.getColumnInfo();
            for (auto& c : mSelect)
            {
                ret.mSelect.push_back({ c.mCol.getColumnInfo(), &c.mTable == &mLeftKey.mTable });
            }
            return ret;
        }
    };

    void populateTable(Table& tb, std::string& fileName, oc::u64 rowCount, bool isBin);
    void populateTable(Table& tb, std::istream& in, oc::u64 rowCount, bool isBin);

    macoro::task<> revealLocal(const Table& share, coproto::Socket& sock, Table& out);
    macoro::task<> revealRemote(const Table& share, coproto::Socket& sock);

    void share(Table& table, std::array<Table, 2>& shares,
        PRNG& prng);
    Table join(const ColRef& l, const ColRef& r, std::vector<ColRef> select);
    oc::BitVector cirEval(oc::BetaCircuit* cir, std::vector<oc::BitVector>& inputs,
        oc::BitVector& output, u8* data, u64 bits, u64 bytes);
    void populateOutTable(Table& out, std::vector<ColRef> avgCol,
        ColRef groupByCol, u64 nOutRows);
    void copyTableEntry(Table& out, ColRef groupByCol, std::vector<ColRef> avgCol,
        std::vector<oc::BitVector>& inputs, BinMatrix& ones,
        u64 curOutRow, u64 nOutRows, u64 row);
    Table average(ColRef groupByCol, std::vector<ColRef> avgCol);
    Table where(Table& T, const std::vector<ArrGate>& gates, const std::vector<std::string>& literals,
        const std::vector<std::string>& literalsType, const u64 totalCol,
        const std::unordered_map<u64, u64>& map, bool print);
    Table applyPerm(Table& T, Perm& perm);

}
