#pragma once
#include "coproto/Socket/BufferingSocket.h"
#include "secure-join/Join/Table.h"
#include "secure-join/Join/OmJoin.h"
#include "secure-join/Aggregate/Average.h"

namespace secJoin
{
    struct State
    {
        std::vector<ColumnInfo> mLColInfo, mRColInfo;
        std::vector<ColRef> selectCols; // Remove this later
        Table mLTable, mRTable, mJoinTable, mOutTable, mAggTable;
        oc::PRNG mPrng;
        OmJoin mJoin;
        Average mAvg;
        OleGenerator mOle;
        coproto::BufferingSocket mSock;
        macoro::eager_task<void> mProtocol;
    };
}