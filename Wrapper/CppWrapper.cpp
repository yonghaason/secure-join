#include "CppWrapper.h"

namespace secJoin
{
    void testApi(std::string& str)
    {
        std::cout << str << std::endl;
    }

    WrapperState* initState(std::string& csvPath, std::string& visaMetaDataPath, std::string& clientMetaDataPath,
        std::vector<std::string>& literals, std::vector<oc::i64>& opInfo, bool isUnique,
        bool verbose, bool mock, bool debug)
    {
        auto cState = std::make_unique<WrapperState>();
        cState->mLiterals = literals; //  This will fail, need to make a copy of literals
        oc::u64 lRowCount = 0, rRowCount = 0, lColCount = 0, rColCount = 0;

        // Current assumption are that Visa always provides table with unique keys 
        // Which means Visa always has to be left Table
        getFileInfo(visaMetaDataPath, cState->mLColInfo, lRowCount, lColCount);
        getFileInfo(clientMetaDataPath, cState->mRColInfo, rRowCount, rColCount);
        cState->mLTable.init(lRowCount, cState->mLColInfo);
        cState->mRTable.init(rRowCount, cState->mRColInfo);
        if (isUnique)
            populateTable(cState->mLTable, csvPath, lRowCount);
        else
            populateTable(cState->mRTable, csvPath, rRowCount);

        parseColsArray(cState->mJoinCols, cState->mSelectCols, cState->mGroupByCols,
            cState->mAvgCols, cState->mGates, opInfo, verbose);
        u64 totalCol = lColCount + rColCount;
        updateSelectCols(cState->mSelectCols, cState->mGroupByCols, cState->mAvgCols, 
        cState->mGates, totalCol, verbose);



        // Current Assumptions is that there is only one Join Columns
        auto lJoinColRef = cState->mLTable[cState->mJoinCols[0]];
        oc::u64 index = getRColIndex(cState->mJoinCols[1], lColCount, rColCount);
        auto rJoinColRef = cState->mRTable[index];

        // Constructing Select Col Ref
        std::vector<secJoin::ColRef> selectColRefs = getSelectColRef(cState->mSelectCols, 
            cState->mLTable, cState->mRTable, lColCount, rColCount);
        
        // Create a new mapping and store the new mapping in the cState
        createNewMapping(cState->mMap, cState->mSelectCols);


        // Initializing the join protocol
        cState->mPrng.SetSeed(oc::sysRandomSeed());
        cState->mJoin.mInsecurePrint = verbose;
        cState->mJoin.mInsecureMockSubroutines = mock;

        // Current assumption are that Visa always provides table with unique keys 
        // Which means Visa always has to be left Table
        if (isUnique)
            cState->mOle.init(cState->mSock.fork(), cState->mPrng, 0, 1<<18, mock);
            //cState->mOle.mock(CorGenerator::Role::Sender);
        else
            cState->mOle.init(cState->mSock.fork(), cState->mPrng, 1, 1<<18, mock);
            //cState->mOle.mock(CorGenerator::Role::Receiver);

        cState->mProtocol =
            cState->mJoin.join(lJoinColRef, rJoinColRef, selectColRefs,
                cState->mJoinTable, cState->mPrng, cState->mOle, cState->mSock) | macoro::make_eager();

        
        return cState.release();
    }


    std::vector<oc::u8> runProtocol(WrapperState* cState, std::vector<oc::u8>& buff)
    {
        cState->mSock.processInbound(buff);

        auto b = cState->mSock.getOutbound();

        if (!b.has_value())
        {
            macoro::sync_wait(cState->mProtocol);
            throw RTE_LOC;
        }

        return *b;
        // return b.value();

    }

    void releaseState(WrapperState* state)
    {
        delete state;
    }

    bool isProtocolReady(WrapperState* cState)
    {
        return cState->mProtocol.is_ready();

    }

    void getOtherShare(WrapperState* cState, bool isUnique, bool isAgg)
    {

        Table& table = cState->mJoinTable;
        if(isAgg)
            table = cState->mAggTable;

        // Assuming Visa always receives the client's share
        if (isUnique)
        {
            cState->mProtocol = revealLocal(cState->mJoinTable, cState->mSock, cState->mOutTable)
                | macoro::make_eager();
        }
        else
        {
            cState->mProtocol = revealRemote(cState->mJoinTable, cState->mSock)
                | macoro::make_eager();
        }
    }

    void getJoinTable(WrapperState* cState, std::string csvPath, std::string metaDataPath, bool isUnique)
    {
        writeFileInfo(metaDataPath, cState->mOutTable);
        writeFileData(csvPath, cState->mOutTable);
    }


    void aggFunc(WrapperState* cState)
    {
        if(cState->mAvgCols.size() > 0)
        {
            if(cState->mGroupByCols.size() == 0)
            {
                std::string temp("Group By Table not present in json for Average operation\n");
                throw std::runtime_error(temp + LOCATION);
            }

            std::vector<secJoin::ColRef> avgCols = 
                getColRefFromMapping(cState->mMap, cState->mAvgCols, cState->mJoinTable);

            // Current Assumption we only have 
            oc::u64 groupByColIndex = getMapVal(cState->mMap, cState->mGroupByCols[0]);
            secJoin::ColRef grpByCol = cState->mJoinTable[groupByColIndex];


            cState->mProtocol =
                cState->mAvg.avg( grpByCol, avgCols, cState->mAggTable,
                    cState->mPrng, cState->mOle, cState->mSock) | macoro::make_eager();
    
        }

    }

}
