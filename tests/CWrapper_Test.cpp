
#include "CWrapper_Test.h"
#include "secure-join/config.h"
#include "cryptoTools/Common/TestCollection.h"
#include "Wrapper/state.h"

using namespace secJoin;

std::vector<secJoin::ColRef> genSelectCols(secJoin::WrapperState* primaryState, secJoin::WrapperState* secondaryState)
{
    std::vector<secJoin::ColRef> select;
    auto lColCount = primaryState->mLTb.cols();
    auto rColCount = primaryState->mRTb.cols();

    for(oc::u64 i=0; i < primaryState->mSelectCols.size(); i++)
    {
        oc::u64 colNum = primaryState->mSelectCols[i];
        if(colNum < lColCount)            
            select.emplace_back(primaryState->mLTb[colNum]);
        else if(colNum < (lColCount + rColCount)) 
        {
            oc::u64 index = secJoin::getRColIndex(colNum, lColCount, rColCount);
            select.emplace_back(secondaryState->mRTb[index]);
        }       
        else
        {
            std::string temp = "Select Col Num = "+ std::to_string(colNum) 
                + " is not present in any table" + "\n" + LOCATION;
            throw std::runtime_error(temp);
        }

    }
    return select;
}   

void runProtocol(secJoin::WrapperState* primaryState, secJoin::WrapperState* secondaryState,
    bool verbose)
{
    std::vector<oc::u8> buff;

    bool progress = true;
    bool first = true;
    while (
        !secJoin::isProtocolReady(primaryState) ||
        !secJoin::isProtocolReady(secondaryState)
        )
    {
        if (first || !secJoin::isProtocolReady(primaryState))
        {
            if (progress == false && buff.size() == 0)
            {
                std::cout << "primary not ready but has received 0 bytes" << std::endl;
                throw RTE_LOC;
            }

            buff = secJoin::runProtocol(primaryState, buff);
            progress = buff.size() || secJoin::isProtocolReady(primaryState);

            if (verbose)
            {
                std::cout << "primary is sending " << buff.size() << " bytes" << std::endl;
            }
        }
        else
        {

            if (buff.size())
                std::cout << "warning, primary is done but secondary sent a message" << std::endl;
            buff = {};
        }

        if (first || !secJoin::isProtocolReady(secondaryState))
        {
            if (first == false && progress == false && buff.size() == 0)
            {
                std::cout << "secondary not ready but has received 0 bytes" << std::endl;
                throw RTE_LOC;
            }

            buff = secJoin::runProtocol(secondaryState, buff);

            progress = buff.size() || secJoin::isProtocolReady(secondaryState);
            if (verbose)
                std::cout << "secondary is sending " << buff.size() << " bytes" << std::endl;
        }
        else
        {
            if (buff.size())
                std::cout << "warning, secondary is done but primary sent a message" << std::endl;
            buff = {};
        }

        first = false;
        //progress = false;
    }

    assert(secJoin::isProtocolReady(primaryState));
    assert(secJoin::isProtocolReady(secondaryState));
}



void OmJoin_wrapper_join_test(const oc::CLP& cmd)
{
    throw oc::UnitTestSkipped("not functional");
    // std::string str("Hello World!");
    // testApi(str);
    std::string rootPath(SEC_JOIN_ROOT_DIRECTORY);
    std::string primaryCsvPath = rootPath + "/tests/tables/primary.csv";
    std::string secondaryCsvPath = rootPath + "/tests/tables/secondary.csv";
    std::string primaryMetaDataPath = rootPath + "/tests/tables/primary_meta.txt";
    std::string clientMetaDataPath = rootPath + "/tests/tables/secondary_meta.txt";
    std::string joinCsvPath = rootPath + "/tests/tables/joindata.csv";
    std::string joinMetaPath = rootPath + "/tests/tables/joindata_meta.txt";
    bool isUnique = true;
    bool verbose = cmd.isSet("v");
    bool mock = cmd.getOr("mock", 1);
    bool remDummies = cmd.isSet("remDummies");

    // Literals & opInfo are dynamically generated on java side
    std::vector<std::string> literals{"ID", "Score", "Date", "ID", "Balance",
        "Score"};
    std::vector<std::string> literalsType = { WHBUNDLE_COL_TYPE, WHBUNDLE_COL_TYPE, 
        WHBUNDLE_COL_TYPE, WHBUNDLE_COL_TYPE, WHBUNDLE_COL_TYPE, WHBUNDLE_COL_TYPE};
    std::vector<oc::i64> opInfo{ 2, 0, 3, 4, 0, 1, 4, 5, -1};

    std::unique_ptr<secJoin::WrapperState> primaryState(secJoin::initState(primaryCsvPath, primaryMetaDataPath, clientMetaDataPath, 
        literals, literalsType, opInfo, isUnique, verbose, mock, remDummies));

    std::unique_ptr<secJoin::WrapperState> secondaryState(secJoin::initState(secondaryCsvPath, primaryMetaDataPath, clientMetaDataPath,
        literals, literalsType, opInfo, !isUnique, verbose, mock, remDummies));

    auto lColCount = primaryState->mLTb.cols();
    auto rColCount = primaryState->mRTb.cols();

    auto select = genSelectCols(primaryState.get(), secondaryState.get());

    oc::u64 rJoinColIndex = secJoin::getRColIndex(secondaryState->mJoinCols[1], lColCount, rColCount);
    auto exp = secJoin::join(
        primaryState->mLTb[primaryState->mJoinCols[0]],
        secondaryState->mRTb[rJoinColIndex],
        select);

    if (verbose)
    {
        std::cout << "primary L table:\n" << primaryState->mLTb << std::endl;
        std::cout << "secondary R table:\n" << secondaryState->mRTb << std::endl;
    }


    runProtocol(primaryState.get(), secondaryState.get(), verbose);

    if(verbose)
        std::cout << "Join Protocol Completed" << std::endl;

    secJoin::getOtherShare(primaryState.get());
    secJoin::getOtherShare(secondaryState.get());

    runProtocol(primaryState.get(), secondaryState.get(), verbose);

    if (primaryState->mOutTb != exp)
    {

        // std::cout << "L \n" << primaryState->mLTb << std::endl;
        // std::cout << "R \n" << secondaryState->mRTb << std::endl;
        // std::cout << "exp \n" << exp << std::endl;
        // std::cout << "act \n" << primaryState->mOutTb << std::endl;
        secJoin::releaseState(primaryState.release());
        secJoin::releaseState(secondaryState.release());
        throw RTE_LOC;
    }

    secJoin::releaseState(primaryState.release());
    secJoin::releaseState(secondaryState.release());
}



void OmJoin_wrapper_avg_test(const oc::CLP& cmd)
{
    throw oc::UnitTestSkipped("not functional");

    std::string rootPath(SEC_JOIN_ROOT_DIRECTORY);
    std::string primaryCsvPath = rootPath + "/tests/tables/primary.csv";
    std::string secondaryCsvPath = rootPath + "/tests/tables/secondary.csv";
    std::string primaryMetaDataPath = rootPath + "/tests/tables/primary_meta.txt";
    std::string clientMetaDataPath = rootPath + "/tests/tables/secondary_meta.txt";
    std::string joinCsvPath = rootPath + "/tests/tables/joindata.csv";
    std::string joinMetaPath = rootPath + "/tests/tables/joindata_meta.txt";
    bool isUnique = true;
    bool verbose = cmd.isSet("v");
    bool mock = cmd.getOr("mock", 1);
    bool remDummies = cmd.isSet("remDummies");
    
    // Literals & opInfo are dynamically generated on java side
    std::vector<std::string> literals{"ID", "Score", "Date", "ID", "Balance",
        "Score"};
    std::vector<std::string> literalsType = { WHBUNDLE_COL_TYPE, WHBUNDLE_COL_TYPE, 
        WHBUNDLE_COL_TYPE, WHBUNDLE_COL_TYPE, WHBUNDLE_COL_TYPE, WHBUNDLE_COL_TYPE};
    std::vector<oc::i64> opInfo{ 2, 0, 3, 4, 0, 1, 4, 5, 1, 0, 2, 1, 4, -1};

    std::unique_ptr<secJoin::WrapperState> primaryState(secJoin::initState(primaryCsvPath, primaryMetaDataPath, clientMetaDataPath,
        literals, literalsType, opInfo, isUnique, verbose, mock, remDummies));

    std::unique_ptr<secJoin::WrapperState> secondaryState(secJoin::initState(secondaryCsvPath, primaryMetaDataPath, clientMetaDataPath,
        literals, literalsType, opInfo, !isUnique, verbose, mock, remDummies));

    auto select = genSelectCols(primaryState.get(), secondaryState.get());
    auto lColCount = primaryState->mLTb.cols();
    auto rColCount = primaryState->mRTb.cols();

    oc::u64 rJoinColIndex = secJoin::getRColIndex(secondaryState->mJoinCols[1], lColCount, rColCount);
    auto joinExp = secJoin::join(
        primaryState->mLTb[primaryState->mJoinCols[0]],
        secondaryState->mRTb[rJoinColIndex],
        select);
    

    if (verbose)
    {
        std::cout << "primary L table:\n" << primaryState->mLTb << std::endl;
        std::cout << "secondary R table:\n" << secondaryState->mRTb << std::endl;
    }

    runProtocol(primaryState.get(), secondaryState.get(), verbose);

    if(verbose)
        std::cout << "Join Protocol Completed" << std::endl;

    secJoin::getOtherShare(primaryState.get());
    secJoin::getOtherShare(secondaryState.get());

    runProtocol(primaryState.get(), secondaryState.get(), verbose);

    if (primaryState->mOutTb != joinExp)
    {

        std::cout << "L \n" << primaryState->mLTb << std::endl;
        std::cout << "R \n" << secondaryState->mRTb << std::endl;
        std::cout << "exp \n" << joinExp << std::endl;
        std::cout << "act \n" << primaryState->mOutTb << std::endl;
        secJoin::releaseState(primaryState.release());
        secJoin::releaseState(secondaryState.release());
        throw RTE_LOC;
    }
    std::cout << " Join is complete & outtable" << std::endl;
    std::cout << "act \n" << primaryState->mOutTb << std::endl;

    secJoin::aggFunc(primaryState.get());
    secJoin::aggFunc(secondaryState.get());

    runProtocol(primaryState.get(), secondaryState.get(), verbose);

    if(verbose)
        std::cout << "Average Protocol Completed" << std::endl;

    secJoin::getOtherShare(primaryState.get());
    secJoin::getOtherShare(secondaryState.get());

    runProtocol(primaryState.get(), secondaryState.get(), verbose);
    
    // Calculating average in plain text
    if(primaryState->mAvgCols.size() == 0)
    {
        std::string temp("Average column not present\n");
        throw std::runtime_error(temp + LOCATION);
    }
    if(primaryState->mGroupByCols.size() == 0)
    {
        std::string temp("Group By Table not present for Average operation\n");
        throw std::runtime_error(temp + LOCATION);
    }
    std::vector<oc::u64> colList = primaryState->mAvgCols;
    std::vector<secJoin::ColRef> avgCols;
    for(oc::u64 i =0; i< colList.size(); i++)
    {
        oc::u64 avgColIndex = primaryState->mMap[primaryState->mAvgCols[i]];
        avgCols.emplace_back(joinExp[avgColIndex]);
    }

    // Current Assumption we only have 
    oc::u64 groupByColIndex = primaryState->mMap[primaryState->mGroupByCols[0]];
    secJoin::ColRef grpByCol = joinExp[groupByColIndex];

    auto exp = secJoin::average(grpByCol, avgCols);

    if (primaryState->mOutTb != exp)
    {
        // std::cout << "L \n" << primaryState->mLTable << std::endl;
        // std::cout << "R \n" << secondaryState->mRTable << std::endl;
        std::cout << "exp \n" << exp << std::endl;
        std::cout << "act \n" << primaryState->mOutTb << std::endl;
        secJoin::releaseState(primaryState.release());
        secJoin::releaseState(secondaryState.release());
        throw RTE_LOC;
    }

    secJoin::releaseState(primaryState.release());
    secJoin::releaseState(secondaryState.release());
}



void OmJoin_wrapper_where_test(const oc::CLP& cmd)
{
    throw oc::UnitTestSkipped("not functional");

    std::string rootPath(SEC_JOIN_ROOT_DIRECTORY);
    std::string primaryCsvPath = rootPath + "/tests/tables/primary.csv";
    std::string secondaryCsvPath = rootPath + "/tests/tables/secondary.csv";
    std::string primaryMetaDataPath = rootPath + "/tests/tables/primary_meta.txt";
    std::string clientMetaDataPath = rootPath + "/tests/tables/secondary_meta.txt";
    std::string joinCsvPath = rootPath + "/tests/tables/joindata.csv";
    std::string joinMetaPath = rootPath + "/tests/tables/joindata_meta.txt";
    bool isUnique = true;
    bool verbose = cmd.isSet("v");
    bool mock = cmd.getOr("mock", 1);
    bool remDummies = cmd.isSet("remDummies");
    
    // Literals & opInfo are dynamically generated on java side
    //Where Clause ID == 52522546320168 || ID == 52474898920631 || Balance + Score == 8375
    std::vector<std::string> literals = {"ID", "Score", "Date", "ID", "Balance", 
        "Score", "52522546320168", "52474898920631", "8375"};
    std::vector<std::string> literalsType = { WHBUNDLE_COL_TYPE, WHBUNDLE_COL_TYPE, 
        WHBUNDLE_COL_TYPE, WHBUNDLE_COL_TYPE, WHBUNDLE_COL_TYPE, WHBUNDLE_COL_TYPE, 
        WHBUNDLE_NUM_TYPE, WHBUNDLE_NUM_TYPE, WHBUNDLE_NUM_TYPE};
    std::vector<i64> opInfo{ 2, 0, 3, 4, 1, 0, 4, 5, 1, 0, 2, 1, 4, 6, 1, 0, 6, 9,
        1, 0, 7, 10, 4, 9, 10, 11, 5, 4, 5, 12, 1, 12, 8, 13, 4, 11, 13, 14, -1};

    std::unique_ptr<secJoin::WrapperState> primaryState(secJoin::initState(primaryCsvPath, primaryMetaDataPath, clientMetaDataPath,
        literals, literalsType, opInfo, isUnique, verbose, mock, remDummies));

    std::unique_ptr<secJoin::WrapperState> secondaryState(secJoin::initState(secondaryCsvPath, primaryMetaDataPath, clientMetaDataPath,
        literals, literalsType, opInfo, !isUnique, verbose, mock, remDummies));

    auto select = genSelectCols(primaryState.get(), secondaryState.get());
    auto lColCount = primaryState->mLTb.cols();
    auto rColCount = primaryState->mRTb.cols();

    oc::u64 rJoinColIndex = secJoin::getRColIndex(secondaryState->mJoinCols[1], lColCount, rColCount);
    auto joinExp = secJoin::join(
        primaryState->mLTb[primaryState->mJoinCols[0]],
        secondaryState->mRTb[rJoinColIndex],
        select);
    

    if (verbose)
    {
        std::cout << "primary L table:\n" << primaryState->mLTb << std::endl;
        std::cout << "secondary R table:\n" << secondaryState->mRTb << std::endl;
    }

    runProtocol(primaryState.get(), secondaryState.get(), verbose);

    if(verbose)
        std::cout << "Join Protocol Completed" << std::endl;

    secJoin::getOtherShare(primaryState.get());
    secJoin::getOtherShare(secondaryState.get());

    runProtocol(primaryState.get(), secondaryState.get(), verbose);

    if (primaryState->mOutTb != joinExp)
    {
        std::cout << "L \n" << primaryState->mLTb << std::endl;
        std::cout << "R \n" << secondaryState->mRTb << std::endl;
        std::cout << "exp \n" << joinExp << std::endl;
        std::cout << "act \n" << primaryState->mOutTb << std::endl;
        secJoin::releaseState(primaryState.release());
        secJoin::releaseState(secondaryState.release());
        throw RTE_LOC;
    }

    secJoin::whereFunc(primaryState.get());
    secJoin::whereFunc(secondaryState.get());

    runProtocol(primaryState.get(), secondaryState.get(), verbose);

    Table whExp = where(joinExp, primaryState->mGates, literals, literalsType, 
        primaryState->mTotCol, primaryState->mMap, verbose);

    if(verbose)
        std::cout << "Where Protocol Completed" << std::endl;

    secJoin::getOtherShare(primaryState.get());
    secJoin::getOtherShare(secondaryState.get());

    runProtocol(primaryState.get(), secondaryState.get(), verbose);

    if (primaryState->mOutTb != whExp)
    {
        std::cout << "L \n" << primaryState->mLTb << std::endl;
        std::cout << "R \n" << secondaryState->mRTb << std::endl;
        std::cout << "exp \n" << whExp << std::endl;
        std::cout << "act \n" << primaryState->mOutTb << std::endl;
        secJoin::releaseState(primaryState.release());
        secJoin::releaseState(secondaryState.release());
        throw RTE_LOC;
    }

    
    
    secJoin::aggFunc(primaryState.get());
    secJoin::aggFunc(secondaryState.get());

    runProtocol(primaryState.get(), secondaryState.get(), verbose);

    if(verbose)
        std::cout << "Average Protocol Completed" << std::endl;

    secJoin::getOtherShare(primaryState.get());
    secJoin::getOtherShare(secondaryState.get());

    runProtocol(primaryState.get(), secondaryState.get(), verbose);
    
    // Calculating average in plain text
    if(primaryState->mAvgCols.size() == 0)
    {
        std::string temp("Average column not present\n");
        throw std::runtime_error(temp + LOCATION);
    }
    if(primaryState->mGroupByCols.size() == 0)
    {
        std::string temp("Group By Table not present for Average operation\n");
        throw std::runtime_error(temp + LOCATION);
    }
    std::vector<oc::u64> colList = primaryState->mAvgCols;
    std::vector<secJoin::ColRef> avgCols;
    for(oc::u64 i =0; i< colList.size(); i++)
    {
        oc::u64 avgColIndex = primaryState->mMap[primaryState->mAvgCols[i]];
        avgCols.emplace_back(whExp[avgColIndex]);
    }

    // Current Assumption we only have 
    oc::u64 groupByColIndex = primaryState->mMap[primaryState->mGroupByCols[0]];
    secJoin::ColRef grpByCol = whExp[groupByColIndex];

    auto exp = secJoin::average(grpByCol, avgCols);

    if (primaryState->mOutTb != exp)
    {
        std::cout << "exp \n" << exp << std::endl;
        std::cout << "act \n" << primaryState->mOutTb << std::endl;
        secJoin::releaseState(primaryState.release());
        secJoin::releaseState(secondaryState.release());
        throw RTE_LOC;
    }
    secJoin::releaseState(primaryState.release());
    secJoin::releaseState(secondaryState.release());
}