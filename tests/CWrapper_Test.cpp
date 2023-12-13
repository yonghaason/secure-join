
#include "CWrapper_Test.h"
#include "secure-join/config.h"
#include "Wrapper/state.h"

using namespace secJoin;

std::vector<secJoin::ColRef> genSelectCols(secJoin::WrapperState* visaState, secJoin::WrapperState* bankState)
{
    std::vector<secJoin::ColRef> select;
    auto lColCount = visaState->mLTb.cols();
    auto rColCount = visaState->mRTb.cols();

    for(oc::u64 i=0; i < visaState->mSelectCols.size(); i++)
    {
        oc::u64 colNum = visaState->mSelectCols[i];
        if(colNum < lColCount)            
            select.emplace_back(visaState->mLTb[colNum]);
        else if(colNum < (lColCount + rColCount)) 
        {
            oc::u64 index = secJoin::getRColIndex(colNum, lColCount, rColCount);
            select.emplace_back(bankState->mRTb[index]);
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

void runProtocol(secJoin::WrapperState* visaState, secJoin::WrapperState* bankState,
    bool verbose)
{
    std::vector<oc::u8> buff;

    bool progress = true;
    bool first = true;
    while (
        !secJoin::isProtocolReady(visaState) ||
        !secJoin::isProtocolReady(bankState)
        )
    {
        if (first || !secJoin::isProtocolReady(visaState))
        {
            if (progress == false && buff.size() == 0)
            {
                std::cout << "visa not ready but has received 0 bytes" << std::endl;
                throw RTE_LOC;
            }

            buff = secJoin::runProtocol(visaState, buff);
            progress = buff.size() || secJoin::isProtocolReady(visaState);

            if (verbose)
            {
                std::cout << "Visa is sending " << buff.size() << " bytes" << std::endl;
            }
        }
        else
        {

            if (buff.size())
                std::cout << "warning, visa is done but bank sent a message" << std::endl;
            buff = {};
        }

        if (first || !secJoin::isProtocolReady(bankState))
        {
            if (first == false && progress == false && buff.size() == 0)
            {
                std::cout << "bank not ready but has received 0 bytes" << std::endl;
                throw RTE_LOC;
            }

            buff = secJoin::runProtocol(bankState, buff);

            progress = buff.size() || secJoin::isProtocolReady(bankState);
            if (verbose)
                std::cout << "Bank is sending " << buff.size() << " bytes" << std::endl;
        }
        else
        {
            if (buff.size())
                std::cout << "warning, bank is done but visa sent a message" << std::endl;
            buff = {};
        }

        first = false;
        //progress = false;
    }

    assert(secJoin::isProtocolReady(visaState));
    assert(secJoin::isProtocolReady(bankState));
}



void OmJoin_wrapper_join_test(const oc::CLP& cmd)
{

    // std::string str("Hello World!");
    // testApi(str);
    std::string rootPath(SEC_JOIN_ROOT_DIRECTORY);
    std::string visaCsvPath = rootPath + "/tests/tables/visa.csv";
    std::string bankCsvPath = rootPath + "/tests/tables/bank.csv";
    std::string visaMetaDataPath = rootPath + "/tests/tables/visa_meta.txt";
    std::string clientMetaDataPath = rootPath + "/tests/tables/bank_meta.txt";
    std::string joinCsvPath = rootPath + "/tests/tables/joindata.csv";
    std::string joinMetaPath = rootPath + "/tests/tables/joindata_meta.txt";
    bool isUnique = true;
    bool verbose = cmd.isSet("v");
    bool mock = cmd.getOr("mock", 1);
    bool debug = cmd.isSet("debug");

    // Literals & opInfo are dynamically generated on java side
    std::vector<std::string> literals{"PAN", "Risk_Score", "Date", "PAN", "Balance",
        "Risk_Score"};
    std::vector<std::string> literalsType = { WHBUNDLE_COL_TYPE, WHBUNDLE_COL_TYPE, 
        WHBUNDLE_COL_TYPE, WHBUNDLE_COL_TYPE, WHBUNDLE_COL_TYPE, WHBUNDLE_COL_TYPE};
    std::vector<oc::i64> opInfo{ 2, 0, 3, 4, 0, 1, 4, 5, -1};

    std::unique_ptr<secJoin::WrapperState> visaState(secJoin::initState(visaCsvPath, visaMetaDataPath, clientMetaDataPath, 
        literals, literalsType, opInfo, isUnique, verbose, mock, debug));

    std::unique_ptr<secJoin::WrapperState> bankState(secJoin::initState(bankCsvPath, visaMetaDataPath, clientMetaDataPath,
        literals, literalsType, opInfo, !isUnique, verbose, mock, debug));

    auto lColCount = visaState->mLTb.cols();
    auto rColCount = visaState->mRTb.cols();

    auto select = genSelectCols(visaState.get(), bankState.get());

    oc::u64 rJoinColIndex = secJoin::getRColIndex(bankState->mJoinCols[1], lColCount, rColCount);
    auto exp = secJoin::join(
        visaState->mLTb[visaState->mJoinCols[0]],
        bankState->mRTb[rJoinColIndex],
        select);

    if (verbose)
    {
        std::cout << "visa L table:\n" << visaState->mLTb << std::endl;
        std::cout << "bank R table:\n" << bankState->mRTb << std::endl;
    }


    runProtocol(visaState.get(), bankState.get(), verbose);

    if(verbose)
        std::cout << "Join Protocol Completed" << std::endl;

    secJoin::getOtherShare(visaState.get(), isUnique);
    secJoin::getOtherShare(bankState.get(), !isUnique);

    runProtocol(visaState.get(), bankState.get(), verbose);

    if (visaState->mOutTb != exp)
    {

        std::cout << "L \n" << visaState->mLTb << std::endl;
        std::cout << "R \n" << bankState->mRTb << std::endl;
        std::cout << "exp \n" << exp << std::endl;
        std::cout << "act \n" << visaState->mOutTb << std::endl;
        secJoin::releaseState(visaState.release());
        secJoin::releaseState(bankState.release());
        throw RTE_LOC;
    }

    secJoin::releaseState(visaState.release());
    secJoin::releaseState(bankState.release());
}



void OmJoin_wrapper_avg_test(const oc::CLP& cmd)
{
    std::string rootPath(SEC_JOIN_ROOT_DIRECTORY);
    std::string visaCsvPath = rootPath + "/tests/tables/visa.csv";
    std::string bankCsvPath = rootPath + "/tests/tables/bank.csv";
    std::string visaMetaDataPath = rootPath + "/tests/tables/visa_meta.txt";
    std::string clientMetaDataPath = rootPath + "/tests/tables/bank_meta.txt";
    std::string joinCsvPath = rootPath + "/tests/tables/joindata.csv";
    std::string joinMetaPath = rootPath + "/tests/tables/joindata_meta.txt";
    bool isUnique = true;
    bool verbose = cmd.isSet("v");
    bool mock = cmd.getOr("mock", 1);
    bool debug = cmd.isSet("debug");
    
    // Literals & opInfo are dynamically generated on java side
    std::vector<std::string> literals{"PAN", "Risk_Score", "Date", "PAN", "Balance",
        "Risk_Score"};
    std::vector<std::string> literalsType = { WHBUNDLE_COL_TYPE, WHBUNDLE_COL_TYPE, 
        WHBUNDLE_COL_TYPE, WHBUNDLE_COL_TYPE, WHBUNDLE_COL_TYPE, WHBUNDLE_COL_TYPE};
    std::vector<oc::i64> opInfo{ 2, 0, 3, 4, 0, 1, 4, 5, 1, 0, 2, 1, 4, -1};

    std::unique_ptr<secJoin::WrapperState> visaState(secJoin::initState(visaCsvPath, visaMetaDataPath, clientMetaDataPath,
        literals, literalsType, opInfo, isUnique, verbose, mock, debug));

    std::unique_ptr<secJoin::WrapperState> bankState(secJoin::initState(bankCsvPath, visaMetaDataPath, clientMetaDataPath,
        literals, literalsType, opInfo, !isUnique, verbose, mock, debug));

    auto select = genSelectCols(visaState.get(), bankState.get());
    auto lColCount = visaState->mLTb.cols();
    auto rColCount = visaState->mRTb.cols();

    oc::u64 rJoinColIndex = secJoin::getRColIndex(bankState->mJoinCols[1], lColCount, rColCount);
    auto joinExp = secJoin::join(
        visaState->mLTb[visaState->mJoinCols[0]],
        bankState->mRTb[rJoinColIndex],
        select);
    

    if (verbose)
    {
        std::cout << "visa L table:\n" << visaState->mLTb << std::endl;
        std::cout << "bank R table:\n" << bankState->mRTb << std::endl;
    }

    runProtocol(visaState.get(), bankState.get(), verbose);

    if(verbose)
        std::cout << "Join Protocol Completed" << std::endl;

    secJoin::getOtherShare(visaState.get(), isUnique);
    secJoin::getOtherShare(bankState.get(), !isUnique);

    runProtocol(visaState.get(), bankState.get(), verbose);

    if (visaState->mOutTb != joinExp)
    {

        std::cout << "L \n" << visaState->mLTb << std::endl;
        std::cout << "R \n" << bankState->mRTb << std::endl;
        std::cout << "exp \n" << joinExp << std::endl;
        std::cout << "act \n" << visaState->mOutTb << std::endl;
        secJoin::releaseState(visaState.release());
        secJoin::releaseState(bankState.release());
        throw RTE_LOC;
    }
    
    secJoin::aggFunc(visaState.get());
    secJoin::aggFunc(bankState.get());

    runProtocol(visaState.get(), bankState.get(), verbose);

    if(verbose)
        std::cout << "Average Protocol Completed" << std::endl;

    secJoin::getOtherShare(visaState.get(), isUnique);
    secJoin::getOtherShare(bankState.get(), !isUnique);

    runProtocol(visaState.get(), bankState.get(), verbose);
    
    // Calculating average in plain text
    if(visaState->mAvgCols.size() == 0)
    {
        std::string temp("Average column not present\n");
        throw std::runtime_error(temp + LOCATION);
    }
    if(visaState->mGroupByCols.size() == 0)
    {
        std::string temp("Group By Table not present for Average operation\n");
        throw std::runtime_error(temp + LOCATION);
    }
    std::vector<oc::u64> colList = visaState->mAvgCols;
    std::vector<secJoin::ColRef> avgCols;
    for(oc::u64 i =0; i< colList.size(); i++)
    {
        oc::u64 avgColIndex = visaState->mMap[visaState->mAvgCols[i]];
        avgCols.emplace_back(joinExp[avgColIndex]);
    }

    // Current Assumption we only have 
    oc::u64 groupByColIndex = visaState->mMap[visaState->mGroupByCols[0]];
    secJoin::ColRef grpByCol = joinExp[groupByColIndex];

    auto exp = secJoin::average(grpByCol, avgCols);

    if (visaState->mOutTb != exp)
    {
        // std::cout << "L \n" << visaState->mLTable << std::endl;
        // std::cout << "R \n" << bankState->mRTable << std::endl;
        std::cout << "exp \n" << exp << std::endl;
        std::cout << "act \n" << visaState->mOutTb << std::endl;
        secJoin::releaseState(visaState.release());
        secJoin::releaseState(bankState.release());
        throw RTE_LOC;
    }

    secJoin::releaseState(visaState.release());
    secJoin::releaseState(bankState.release());
}



void OmJoin_wrapper_where_test(const oc::CLP& cmd)
{
    std::string rootPath(SEC_JOIN_ROOT_DIRECTORY);
    std::string visaCsvPath = rootPath + "/tests/tables/visa.csv";
    std::string bankCsvPath = rootPath + "/tests/tables/bank.csv";
    std::string visaMetaDataPath = rootPath + "/tests/tables/visa_meta.txt";
    std::string clientMetaDataPath = rootPath + "/tests/tables/bank_meta.txt";
    std::string joinCsvPath = rootPath + "/tests/tables/joindata.csv";
    std::string joinMetaPath = rootPath + "/tests/tables/joindata_meta.txt";
    bool isUnique = true;
    bool verbose = cmd.isSet("v");
    bool mock = cmd.getOr("mock", 1);
    bool debug = cmd.isSet("debug");
    
    // Literals & opInfo are dynamically generated on java side
    //Where Clause PAN == 52522546320168 || PAN == 52474898920631 || Balance + Risk_Score == 8375
    std::vector<std::string> literals = {"PAN", "Risk_Score", "Date", "PAN", "Balance", 
        "Risk_Score", "52522546320168", "52474898920631", "8375"};
    std::vector<std::string> literalsType = { WHBUNDLE_COL_TYPE, WHBUNDLE_COL_TYPE, 
        WHBUNDLE_COL_TYPE, WHBUNDLE_COL_TYPE, WHBUNDLE_COL_TYPE, WHBUNDLE_COL_TYPE, 
        WHBUNDLE_NUM_TYPE, WHBUNDLE_NUM_TYPE, WHBUNDLE_NUM_TYPE};
    std::vector<i64> opInfo{ 2, 0, 3, 4, 1, 0, 4, 5, 1, 0, 2, 1, 4, 6, 1, 0, 6, 9,
        1, 0, 7, 10, 4, 9, 10, 11, 5, 4, 5, 12, 1, 12, 8, 13, 4, 12, 13, 14, -1};

    std::unique_ptr<secJoin::WrapperState> visaState(secJoin::initState(visaCsvPath, visaMetaDataPath, clientMetaDataPath,
        literals, literalsType, opInfo, isUnique, verbose, mock, debug));

    std::unique_ptr<secJoin::WrapperState> bankState(secJoin::initState(bankCsvPath, visaMetaDataPath, clientMetaDataPath,
        literals, literalsType, opInfo, !isUnique, verbose, mock, debug));

    auto select = genSelectCols(visaState.get(), bankState.get());
    auto lColCount = visaState->mLTb.cols();
    auto rColCount = visaState->mRTb.cols();

    oc::u64 rJoinColIndex = secJoin::getRColIndex(bankState->mJoinCols[1], lColCount, rColCount);
    auto joinExp = secJoin::join(
        visaState->mLTb[visaState->mJoinCols[0]],
        bankState->mRTb[rJoinColIndex],
        select);
    

    if (verbose)
    {
        std::cout << "visa L table:\n" << visaState->mLTb << std::endl;
        std::cout << "bank R table:\n" << bankState->mRTb << std::endl;
    }

    runProtocol(visaState.get(), bankState.get(), verbose);

    if(verbose)
        std::cout << "Join Protocol Completed" << std::endl;

    secJoin::getOtherShare(visaState.get(), isUnique);
    secJoin::getOtherShare(bankState.get(), !isUnique);

    runProtocol(visaState.get(), bankState.get(), verbose);

    if (visaState->mOutTb != joinExp)
    {
        std::cout << "L \n" << visaState->mLTb << std::endl;
        std::cout << "R \n" << bankState->mRTb << std::endl;
        std::cout << "exp \n" << joinExp << std::endl;
        std::cout << "act \n" << visaState->mOutTb << std::endl;
        secJoin::releaseState(visaState.release());
        secJoin::releaseState(bankState.release());
        throw RTE_LOC;
    }

    secJoin::whereFunc(visaState.get());
    secJoin::whereFunc(bankState.get());

    runProtocol(visaState.get(), bankState.get(), verbose);

    Table whExp = where(joinExp, visaState->mGates, literals, literalsType, 
        visaState->mTotCol, visaState->mMap, verbose);

    if(verbose)
        std::cout << "Where Protocol Completed" << std::endl;

    secJoin::getOtherShare(visaState.get(), isUnique);
    secJoin::getOtherShare(bankState.get(), !isUnique);

    runProtocol(visaState.get(), bankState.get(), verbose);

    if (visaState->mOutTb != whExp)
    {

        std::cout << "L \n" << visaState->mLTb << std::endl;
        std::cout << "R \n" << bankState->mRTb << std::endl;
        std::cout << "exp \n" << whExp << std::endl;
        std::cout << "act \n" << visaState->mOutTb << std::endl;
        secJoin::releaseState(visaState.release());
        secJoin::releaseState(bankState.release());
        throw RTE_LOC;
    }

    
    
    secJoin::aggFunc(visaState.get());
    secJoin::aggFunc(bankState.get());

    runProtocol(visaState.get(), bankState.get(), verbose);

    if(verbose)
        std::cout << "Average Protocol Completed" << std::endl;

    secJoin::getOtherShare(visaState.get(), isUnique);
    secJoin::getOtherShare(bankState.get(), !isUnique);

    runProtocol(visaState.get(), bankState.get(), verbose);
    
    // Calculating average in plain text
    if(visaState->mAvgCols.size() == 0)
    {
        std::string temp("Average column not present\n");
        throw std::runtime_error(temp + LOCATION);
    }
    if(visaState->mGroupByCols.size() == 0)
    {
        std::string temp("Group By Table not present for Average operation\n");
        throw std::runtime_error(temp + LOCATION);
    }
    std::vector<oc::u64> colList = visaState->mAvgCols;
    std::vector<secJoin::ColRef> avgCols;
    for(oc::u64 i =0; i< colList.size(); i++)
    {
        oc::u64 avgColIndex = visaState->mMap[visaState->mAvgCols[i]];
        avgCols.emplace_back(whExp[avgColIndex]);
    }

    // Current Assumption we only have 
    oc::u64 groupByColIndex = visaState->mMap[visaState->mGroupByCols[0]];
    secJoin::ColRef grpByCol = whExp[groupByColIndex];

    auto exp = secJoin::average(grpByCol, avgCols);

    if (visaState->mOutTb != exp)
    {
        std::cout << "L \n" << visaState->mLTb << std::endl;
        std::cout << "R \n" << bankState->mRTb << std::endl;
        std::cout << "exp \n" << exp << std::endl;
        std::cout << "act \n" << visaState->mOutTb << std::endl;
        secJoin::releaseState(visaState.release());
        secJoin::releaseState(bankState.release());
        throw RTE_LOC;
    }
    secJoin::releaseState(visaState.release());
    secJoin::releaseState(bankState.release());
}