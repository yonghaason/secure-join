#include "CppWrapper.h"

namespace secJoin
{
    void testApi(std::string& str)
    {
        std::cout << str << std::endl;
    }

    macoro::task<> start(WrapperState* cState, JoinQuery query)
    {
        MC_BEGIN(macoro::task<>, cState, query);

        MC_AWAIT(
            macoro::when_all_ready(
                cState->mOle.start(),
                cState->mJoin.join(query,
                    cState->mJoinTb, cState->mPrng, cState->mSock)
            ));

        MC_END();
    }

    WrapperState* initState(std::string& csvPath,
        std::string& visaMetaDataPath,
        std::string& clientMetaDataPath,
        std::vector<std::string>& literals,
        std::vector<std::string>& literalsType,
        std::vector<oc::i64>& opInfo,
        bool isUnique,
        bool verbose,
        bool mock,
        bool remDummies,
        Perm randPerm)
    {
        mock = true; // Remove this once Peter fixes the Join bug
        auto cState = std::make_unique<WrapperState>();
        cState->mLiterals = literals;
        cState->mLiteralsType = literalsType;
        oc::u64 lRowCount = 0, rRowCount = 0, lColCount = 0, rColCount = 0;

        // Current assumption are that Visa always provides table with unique keys 
        // Which means Visa always has to be left Table
        std::vector<ColumnInfo> lColInfo, rColInfo;
        bool isBin;
        getFileInfo(visaMetaDataPath, lColInfo, lRowCount, lColCount, isBin);
        getFileInfo(clientMetaDataPath, rColInfo, rRowCount, rColCount, isBin);
        cState->mLTb.init(lRowCount, lColInfo);
        cState->mRTb.init(rRowCount, rColInfo);
        if (isUnique)
            populateTable(cState->mLTb, csvPath, lRowCount, isBin);
        else
            populateTable(cState->mRTb, csvPath, rRowCount, isBin);

        parseColsArray(cState->mJoinCols, cState->mSelectCols, cState->mGroupByCols,
            cState->mAvgCols, cState->mGates, opInfo, verbose);
        cState->mTotCol = lColCount + rColCount;
        updateSelectCols(cState->mSelectCols, cState->mGroupByCols, cState->mAvgCols,
            cState->mGates, cState->mTotCol, verbose);

        // Current Assumptions is that there is only one Join Columns
        auto lJoinColRef = cState->mLTb[cState->mJoinCols[0]];
        oc::u64 index = getRColIndex(cState->mJoinCols[1], lColCount, rColCount);
        auto rJoinColRef = cState->mRTb[index];

        // Constructing Select Col Ref
        std::vector<secJoin::ColRef> selectColRefs = getSelectColRef(cState->mSelectCols,
            cState->mLTb, cState->mRTb);

        // Create a new mapping and store the new mapping in the cState
        createNewMapping(cState->mMap, cState->mSelectCols);


        // Initializing the join protocol
        cState->mPrng.SetSeed(oc::sysRandomSeed());
        cState->mJoin.mInsecurePrint = verbose;
        cState->mJoin.mInsecureMockSubroutines = mock;
        cState->mInsecurePrint = verbose;
        cState->mInsecureMockSubroutines = mock;
        cState->mRemDummies = remDummies;
        cState->mPerm = randPerm;


        // Current assumption are that Visa always provides table with unique keys 
        // Which means Visa always has to be left Table
        if (isUnique)
            cState->mOle.init(cState->mSock.fork(), cState->mPrng, 0, 1 << 18, mock);
        //cState->mOle.mock(CorGenerator::Role::Sender);
        else
            cState->mOle.init(cState->mSock.fork(), cState->mPrng, 1, 1 << 18, mock);
        //cState->mOle.mock(CorGenerator::Role::Receiver);

        JoinQuery query(lJoinColRef, rJoinColRef, selectColRefs);
        cState->mJoin.init(query, cState->mOle);

        cState->mProtocol = start(cState.get(), query) | macoro::make_eager();


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
    }

    void releaseState(WrapperState* state)
    {
        delete state;
    }

    bool isProtocolReady(WrapperState* cState)
    {
        return cState->mProtocol.is_ready();
    }

    void saveSecretShareData(WrapperState* cState, std::string csvPath, std::string metaDataPath)
    {
        Table& table = cState->mJoinTb;
        if (cState->mAggTb.cols() > 0)
            table = cState->mAggTb;
        else if (cState->mWhTb.cols() > 0)
            table = cState->mWhTb;

        writeFileInfo(metaDataPath, table, true);
        writeFileData(csvPath, table, true);
    }

    void getOtherShare(WrapperState* cState, bool isUnique)
    {
        Table& table = cState->mJoinTb;
        if (cState->mAggTb.cols() > 0)
            table = cState->mAggTb;
        else if (cState->mWhTb.cols() > 0)
            table = cState->mWhTb;

        // Assuming Visa always receives the client's share
        if (isUnique)
        {
            cState->mProtocol = revealLocal(table, cState->mSock, cState->mOutTb)
                | macoro::make_eager();
        }
        else
        {
            cState->mProtocol = revealRemote(table, cState->mSock)
                | macoro::make_eager();
        }
    }

    void getFinalTable(WrapperState* cState, std::string csvPath, std::string metaDataPath, bool isUnique)
    {
        // Only Visa can call this API 
        // Bcoz it has the final result
        if (!isUnique)
            throw RTE_LOC;
        writeFileInfo(metaDataPath, cState->mOutTb);
        writeFileData(csvPath, cState->mOutTb);
    }


    void whereFunc(WrapperState* cState)
    {
        if (cState->mGates.size() == 0)
        {
            std::string temp("Gates Information not present for Where operation\n");
            throw std::runtime_error(temp + LOCATION);
        }

        cState->mWh.mInsecureMockSubroutines = cState->mInsecureMockSubroutines;

        // cState->mProtocol = cState->mWh.where(cState->mJoinTb, cState->mGates, cState->mLiterals,
        //     cState->mLiteralsType, cState->mTotCol, cState->mWhTb, cState->mMap, cState->mOle,
        //     cState->mSock, cState->mInsecurePrint, cState->mPrng, cState->mRemDummies,
        //     cState->mPerm)
        //     | macoro::make_eager();

    }

    void aggFunc(WrapperState* cState)
    {
        if (cState->mAvgCols.size() > 0)
        {
            if (cState->mGroupByCols.size() == 0)
            {
                std::string temp("Group By Table not present for Average operation\n");
                throw std::runtime_error(temp + LOCATION);
            }
            Table& inTb = cState->mJoinTb;
            if (cState->mWhTb.cols() > 0)
                inTb = cState->mWhTb;

            std::vector<secJoin::ColRef> avgCols =
                getColRefFromMapping(cState->mMap, cState->mAvgCols, inTb);

            // Current Assumption we only have 
            oc::u64 groupByColIndex = getMapVal(cState->mMap, cState->mGroupByCols[0]);
            secJoin::ColRef grpByCol = inTb[groupByColIndex];

            cState->mAvg.mInsecurePrint = cState->mInsecurePrint;
            cState->mAvg.mInsecureMockSubroutines = cState->mInsecureMockSubroutines;

            cState->mProtocol =
                cState->mAvg.avg(grpByCol, avgCols, cState->mAggTb, cState->mPrng,
                    cState->mOle, cState->mSock, cState->mRemDummies, cState->mPerm) | macoro::make_eager();

        }

    }

}
