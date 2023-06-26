#pragma once

#include <cryptoTools/Common/MatrixView.h>

#include <fstream>
#include "Matrix.h"
#include "Util.h"

namespace secJoin
{
    enum class TypeID
    {
        IntID = 0,
        StringID = 1
    };

    class ColumnBase
    {
    public:
        TypeID mType;
        u64 mBitCount = 0;
        std::string mName;


        ColumnBase() = default;
        ColumnBase(const ColumnBase&) = default;
        ColumnBase(ColumnBase&&) = default;

        ColumnBase(std::string name, TypeID type, u64 size)
            : mType(type)
            , mBitCount(size)
            , mName(std::move(name))
        {
            if(mType == TypeID::StringID && mBitCount % 8)
                throw std::runtime_error("String type must have a multiple of 8 bits. " LOCATION);
        }

		ColumnBase& operator=(const ColumnBase&) = default;

        u64 getByteCount() const { return (getBitCount() + 7) / 8; }
        u64 getBitCount() const { return mBitCount; }
        TypeID getTypeID() const { return mType; }
    };

    class Column : public ColumnBase
    {
    public:

        Column() = delete;
        Column(const Column&) = default;
        Column(Column&&) = default;

        Column(std::string name, TypeID type, u64 size)
            : ColumnBase(std::move(name), type, size)
        { }



        // aby3::i64Matrix mData;
        secJoin::BinMatrix mData;
    };

    // class SharedColumn : public ColumnBase, public aby3::sbMatrix
    // {
    // public:

    //     SharedColumn() = default;
    //     SharedColumn(const SharedColumn&) = default;
    //     SharedColumn(SharedColumn&&) = default;

    //     SharedColumn(std::string name, TypeID type, u64 size)
    //         : ColumnBase(std::move(name), type, size)
    //     { }

	// 	SharedColumn& operator=(const SharedColumn&) = default;
    // };

    using ColumnInfo = std::tuple<std::string, TypeID, u64>;

    class Table
    {
    public:
        std::vector<Column> mColumns;

        struct ColRef
        {
            Table& mTable;
            Column& mCol;

            ColRef(Table& t, Column& c)
                : mTable(t), mCol(c)
            {}

            ColRef(const ColRef&) = default;
            ColRef(ColRef&&) = default;

        };

        Table() = default;
        Table(const Table&) = default;
        Table(Table&&) = default;
        Table(u64 rows, std::vector<ColumnInfo> columns)
        {
            init(rows, columns);
        }

        void init(u64 rows, std::vector<ColumnInfo>& columns)
        {
            mColumns.reserve(columns.size());
            // mColumns.resize(columns.size());
            for (u64 i = 0; i < columns.size(); ++i)
            {
                mColumns.emplace_back(
                    std::get<0>(columns[i]),
                    std::get<1>(columns[i]),
                    std::get<2>(columns[i])
                );
                // auto size = (std::get<2>(columns[i]) + 7) / 8;
                mColumns.back().mData.resize(rows, std::get<2>(columns[i]));
            }
        }

        u64 rows() { return mColumns.size() ? mColumns[0].mData.numEntries() : 0; }

    };

    void populateTable(Table& tb, std::string& fileName, oc::u64 rowCount);
    void populateTable(Table& tb, std::istream& in, oc::u64 rowCount);
    void secretShareTable(Table& table,std::array<Table,2>& shares,
                        oc::PRNG &prng);

    // class SharedTable
    // {
    // public:
    //     // shared keys are stored in packed binary format. i.e. XOR shared and trasposed.
    //     std::vector<SharedColumn> mColumns;

    //     struct ColRef
    //     {
    //         SharedTable& mTable;
    //         SharedColumn& mCol;

    //         ColRef(SharedTable& t, SharedColumn& c)
    //             : mTable(t), mCol(c)
    //         {}

    //         ColRef(const ColRef&) = default;
    //         ColRef(ColRef&&) = default;

    //     };


    //     ColRef operator[](std::string c)
    //     {
    //         for (u64 i = 0; i < mColumns.size(); ++i)
    //         {
    //             if (mColumns[i].mName == c)
    //                 return { *this, mColumns[i] };
    //         }

    //         throw RTE_LOC;
    //     }

    //     ColRef operator[](u64 i)
    //     {
    //         return { *this, mColumns[i] };
    //     }


    //     u64 rows();
    // };

    // namespace selectDetails
    // {

    //     enum SelectOp
    //     {
    //         BitwiseOr,
    //         BitwiseAnd,
    //         Multiply,
    //         Add,
    //         LessThan,
    //         Inverse
    //     };
    //     struct Gate
    //     {
    //         SelectOp op;
    //         int mIn1, mIn2, mOut;
    //     };
    //     struct Input;
    //     struct Output;


    //     struct Mem
    //     {
    //         std::shared_ptr<const DataType> mType;
    //         Gate* mGate = nullptr;
    //         //Input* mInputPtr = nullptr;
    //         //Output* mOutputPtr = nullptr;
    //         int mInputIdx = -1;
    //         int mOutputIdx = -1;
    //         int mIdx = -1;
    //         bool mUsed = false;

    //         bool isInput() const { return mInputIdx != -1; }
    //         bool isOutput() const { return mOutputIdx != -1; }
    //     };

    //     struct Input
    //     {
    //         Input(int memIdx, SharedTable::ColRef& c, int p)
    //             : mMemIdx(memIdx)
    //             , mCol(c)
    //             , mPosition(p)
    //         {}

    //         int mMemIdx;
    //         SharedTable::ColRef mCol;
    //         int mPosition;
    //     };

    //     struct Output
    //     {

    //         Output(int memIdx, std::string& c, int p)
    //             : mMemIdx(memIdx)
    //             , mName(c)
    //             , mPosition(p)
    //         {}
    //         int mMemIdx;
    //         std::string mName;
    //         int mPosition;
    //     };

    // }

    // class SelectQuery;
    // class SelectBundle
    // {
    // public:
    //     SelectQuery & mSelect;
    //     int mMemIdx;

	// 	SelectBundle(const SelectBundle&) = default;
	// 	SelectBundle(SelectBundle&&) = default;

    //     SelectBundle(SelectQuery& cir, int memIdx)
    //         : mSelect(cir)
    //         , mMemIdx(memIdx)
    //     {}

    //     SelectBundle operator!() const;
    //     SelectBundle operator|(const SelectBundle& r) const;
    //     SelectBundle operator&(const SelectBundle& r) const;
    //     SelectBundle operator<(const SelectBundle& r) const;
    //     SelectBundle operator*(const SelectBundle& r) const;
    //     SelectBundle operator+(const SelectBundle& r) const;
    // };                                                

    // class SelectQuery
    // {
    // public:

    //     std::string mNoRevealName;
    //     bool mIsUnion = false;

    //     SharedTable * mLeftTable = nullptr;
    //     SharedTable * mRightTable = nullptr;
    //     SharedColumn * mLeftCol = nullptr;
    //     SharedColumn * mRightCol = nullptr;

    //     std::vector<selectDetails::Mem> mMem;
    //     std::vector<selectDetails::Input> mInputs;
    //     std::vector<selectDetails::Output> mOutputs;
    //     std::vector<selectDetails::Gate> mGates;

    //     std::vector<selectDetails::Input*> 
    //         mLeftInputs, 
    //         mRightInputs;

    //     //SelectQuery(std::vector<SharedTable::ColRef> passThrough)
    //     //{
    //     //    for (auto& p : passThrough)
    //     //        addOutput(p.mCol.mName, addInput(p));
    //     //}

    //     SelectQuery() = default;

        

    //     SelectBundle addInput(SharedTable::ColRef column);

    //     SelectBundle joinOn(SharedTable::ColRef left, SharedTable::ColRef right);

    //     int addOp(selectDetails::SelectOp op, int wire1, int wire2);

    //     int addOp(selectDetails::SelectOp op, int wire1);

    //     void addOutput(std::string name, const SelectBundle& column);

    //     void apply(BetaCircuit& cir, span<BetaBundle> inputs, span<BetaBundle> outputs) const;

    //     void noReveal(std::string columnName)
    //     {
    //         mNoRevealName = std::move(columnName);
    //     }

    //     bool isNoReveal() const
    //     {
    //         return mNoRevealName.size();
    //     }

    //     void isUnion(bool b) { mIsUnion = b; }
    //     bool isUnion() const { return mIsUnion; }

    //     bool isLeftPassthrough(selectDetails::Output output)const;
    //     bool isRightPassthrough(selectDetails::Output output)const;
    //     bool isCircuitInput(selectDetails::Input input)const;
    // };
}

