#pragma once
#include "coproto/Socket/BufferingSocket.h"
#include "secure-join/Join/Table.h"
#include "secure-join/Join/OmJoin.h"
#include "secure-join/Aggregate/Where.h"
#include "secure-join/Aggregate/Average.h"
#include "secure-join/Util/ArrGate.h"
#include <unordered_map>

namespace secJoin
{
    struct WrapperState
    {
        // Do I need mLTb  & mRTb?
        Table mLTb, mRTb, mJoinTb, mOutTb, mAggTb, mWhTb;
        std::vector<std::string> mLiterals, mLiteralsType;
        std::unordered_map<oc::u64, oc::u64> mMap;
        std::vector<oc::u64> mJoinCols, mSelectCols, mGroupByCols, mAvgCols;
        std::vector<secJoin::ArrGate> mGates;
        oc::PRNG mPrng;
        OmJoin mJoin;
        Average mAvg;
        Where mWh;
        CorGenerator mOle;
        coproto::BufferingSocket mSock;
        macoro::eager_task<void> mProtocol;
        oc::u64 mTotCol;
        bool mInsecurePrint, mInsecureMockSubroutines, mRemDummies;
    };
}