
#include "CWrapper_Test.h"
#include "secure-join/config.h"
#include "Wrapper/state.h"
void OmJoin_wrapper_join_test(const oc::CLP& cmd)
{
    // std::string str("Hello World!");
    // testApi(str);

    std::string rootPath(SEC_JOIN_ROOT_DIRECTORY);
    std::string visaCsvPath = rootPath + "/tests/tables/visa.csv";
    std::string bankCsvPath = rootPath + "/tests/tables/bank.csv";
    std::string visaMetaDataPath = rootPath + "/tests/tables/visa_meta.txt";
    std::string clientMetaDataPath = rootPath + "/tests/tables/bank_meta.txt";
    std::string joinVisaCols("PAN");
    std::string joinClientCols("PAN");
    std::string selectVisaCols("Risk_Score,PAN");
    std::string selectClientCols("Balance");
    std::string joinCsvPath = rootPath + "/tests/tables/joindata.csv";
    std::string joinMetaPath = rootPath + "/tests/tables/joindata_meta.txt";
    bool isUnique = true;
    bool isAgg = false;
    bool verbose = cmd.isSet("v");
    bool mock = cmd.isSet("mock");
    bool debug = cmd.isSet("debug");

    secJoin::State* visaState = secJoin::initState(visaCsvPath, visaMetaDataPath, clientMetaDataPath, joinVisaCols,
        joinClientCols, selectVisaCols, selectClientCols, isUnique, verbose, mock, debug);


    secJoin::State* bankState = secJoin::initState(bankCsvPath, visaMetaDataPath, clientMetaDataPath, joinVisaCols,
        joinClientCols, selectVisaCols, selectClientCols, !isUnique, verbose, mock, debug);

    // auto select = visaState->selectCols;
    std::vector<secJoin::ColRef> select;
    for (secJoin::u64 i = 0; i < visaState->selectCols.size(); ++i)
        if (&visaState->selectCols[i].mTable == &visaState->mLTable)
            select.emplace_back(visaState->mLTable[visaState->selectCols[i].mCol.mName]);
        else
            select.emplace_back(bankState->mRTable[visaState->selectCols[i].mCol.mName]);

    auto exp = secJoin::join(
        visaState->mLTable[joinVisaCols],
        bankState->mRTable[joinClientCols],
        select);

    if (verbose)
    {
        std::cout << "visa L table:\n" << visaState->mLTable << std::endl;
        std::cout << "bank R table:\n" << bankState->mRTable << std::endl;
    }


    runProtocol(visaState, bankState, verbose);

    if(verbose)
        std::cout << "Join Protocol Completed" << std::endl;

    secJoin::getOtherShare(visaState, isUnique, isAgg);
    secJoin::getOtherShare(bankState, !isUnique, isAgg);

    runProtocol(visaState, bankState, verbose);

    if (visaState->mOutTable != exp)
    {

        std::cout << "L \n" << visaState->mLTable << std::endl;
        std::cout << "R \n" << bankState->mRTable << std::endl;
        std::cout << "exp \n" << exp << std::endl;
        std::cout << "act \n" << visaState->mOutTable << std::endl;
        throw RTE_LOC;
    }

    secJoin::releaseState(visaState);
    secJoin::releaseState(bankState);
}


void runProtocol(secJoin::State* visaState, secJoin::State* bankState,
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



void OmJoin_wrapper_avg_test(const oc::CLP& cmd)
{
    // std::string str("Hello World!");
    // testApi(str);

    std::string rootPath(SEC_JOIN_ROOT_DIRECTORY);
    std::string visaCsvPath = rootPath + "/tests/tables/visa.csv";
    std::string bankCsvPath = rootPath + "/tests/tables/bank.csv";
    std::string visaMetaDataPath = rootPath + "/tests/tables/visa_meta.txt";
    std::string clientMetaDataPath = rootPath + "/tests/tables/bank_meta.txt";
    std::string joinVisaCols("PAN");
    std::string joinClientCols("PAN");
    std::string selectVisaCols("Risk_Score,PAN");
    std::string selectClientCols("Balance");
    std::string joinCsvPath = rootPath + "/tests/tables/joindata.csv";
    std::string joinMetaPath = rootPath + "/tests/tables/joindata_meta.txt";
    std::string jsonString = "{ \"Average\": \"Risk_Score,Balance\", \"Group by\": \"PAN\" }";
    bool isUnique = true;
    bool isAgg = true;
    bool verbose = cmd.isSet("v");
    bool mock = cmd.isSet("mock");
    bool debug = cmd.isSet("debug");

    secJoin::State* visaState = secJoin::initState(visaCsvPath, visaMetaDataPath, clientMetaDataPath, joinVisaCols,
        joinClientCols, selectVisaCols, selectClientCols, isUnique, verbose, mock, debug);


    secJoin::State* bankState = secJoin::initState(bankCsvPath, visaMetaDataPath, clientMetaDataPath, joinVisaCols,
        joinClientCols, selectVisaCols, selectClientCols, !isUnique, verbose, mock, debug);

    // auto select = visaState->selectCols;
    std::vector<secJoin::ColRef> select;
    for (secJoin::u64 i = 0; i < visaState->selectCols.size(); ++i)
        if (&visaState->selectCols[i].mTable == &visaState->mLTable)
            select.emplace_back(visaState->mLTable[visaState->selectCols[i].mCol.mName]);
        else
            select.emplace_back(bankState->mRTable[visaState->selectCols[i].mCol.mName]);

    auto joinResult = secJoin::join(
        visaState->mLTable[joinVisaCols],
        bankState->mRTable[joinClientCols],
        select);
    

    if (verbose)
    {
        std::cout << "visa L table:\n" << visaState->mLTable << std::endl;
        std::cout << "bank R table:\n" << bankState->mRTable << std::endl;
    }

    runProtocol(visaState, bankState, verbose);

    if(verbose)
        std::cout << "Join Protocol Completed" << std::endl;

    // visaState->mAvg.mInsecurePrint = true;
    // bankState->mAvg.mInsecurePrint = true;
    secJoin::aggFunc(visaState, jsonString);
    secJoin::aggFunc(bankState, jsonString);

    runProtocol(visaState, bankState, verbose);

    if(verbose)
        std::cout << "Average Protocol Completed" << std::endl;

    secJoin::getOtherShare(visaState, isUnique, isAgg);
    secJoin::getOtherShare(bankState, !isUnique, isAgg);

    runProtocol(visaState, bankState, verbose);


    nlohmann::json j = nlohmann::json::parse(jsonString);
    
    if(j[secJoin::AVERAGE_JSON_LITERAL].empty())
    {
        std::string temp("Average column not present in json\n");
        throw std::runtime_error(temp + LOCATION);
    }
    if(j[secJoin::GROUP_BY_JSON_LITERAL].empty())
    {
        std::string temp("Group By Table not present in json for Average operation\n");
        throw std::runtime_error(temp + LOCATION);
    }

    std::vector<secJoin::ColRef> avgCols;
    std::string avgColNm;
    std::string temp = j[secJoin::AVERAGE_JSON_LITERAL];
    std::stringstream avgColNmList(temp);
    while (getline(avgColNmList, avgColNm, ','))
        avgCols.emplace_back(joinResult[avgColNm]);

    
    std::string grpByColNm = j[secJoin::GROUP_BY_JSON_LITERAL];
    secJoin::ColRef grpByCol = joinResult[grpByColNm];

    auto exp = secJoin::average(grpByCol, avgCols);


    if (visaState->mOutTable != exp)
    {

        std::cout << "L \n" << visaState->mLTable << std::endl;
        std::cout << "R \n" << bankState->mRTable << std::endl;
        std::cout << "exp \n" << exp << std::endl;
        std::cout << "act \n" << visaState->mOutTable << std::endl;
        throw RTE_LOC;
    }

    secJoin::releaseState(visaState);
    secJoin::releaseState(bankState);
}