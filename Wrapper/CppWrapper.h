#pragma once
#include "secure-join/Util/CSVParser.h"
#include "coproto/Socket/BufferingSocket.h"
#include "secure-join/Join/Table.h"
#include "secure-join/Join/OmJoin.h"
#include "macoro/optional.h"

namespace secJoin
{
        struct State
        {
        std::vector<secJoin::ColumnInfo> mLColInfo, mRColInfo;
        secJoin::Table mLTable, mRTable, mShareTable, mOutTable;
        oc::PRNG mPrng;
        secJoin::OmJoin mJoin;
        secJoin::OleGenerator mOle;
        coproto::BufferingSocket mSock;
        macoro::eager_task<void> mProtocol;
        };
        
        void testApi(std::string& str);
        long initState(std::string& csvPath, std::string& visaMetaDataPath, std::string& clientMetaDataPath, 
                std::string& visaJoinCols, std::string& clientJoinCols, std::string& selectVisaCols,
                std::string& selectClientCols, bool isUnique);
        macoro::optional<std::vector<oc::u8>> runJoin(long stateAddress, std::vector<oc::u8>& buff);
        void releaseState(long memoryAddress);
        bool isProtocolReady(long stateAddress);
        void getOtherShare(long stateAddress, bool isUnique);
        void getJoinTable(long stateAddress, std::string csvPath, std::string metaDataPath, bool isUnique);

}


