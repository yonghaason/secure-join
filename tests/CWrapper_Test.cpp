
#include "CWrapper_Test.h"
#include "secure-join/config.h"
#include "Wrapper/state.h"
void wrapper_test(const oc::CLP& cmd)
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

    secJoin::State* visaState = secJoin::initState(visaCsvPath, visaMetaDataPath, clientMetaDataPath, joinVisaCols,
        joinClientCols, selectVisaCols, selectClientCols, isUnique);


    secJoin::State* bankState = secJoin::initState(bankCsvPath, visaMetaDataPath, clientMetaDataPath, joinVisaCols,
        joinClientCols, selectVisaCols, selectClientCols, !isUnique);

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

    if (cmd.isSet("v"))
    {
        std::cout << "visa L table:\n" << visaState->mLTable << std::endl;
        std::cout << "bank R table:\n" << bankState->mRTable << std::endl;

        visaState->mJoin.mInsecurePrint = true;
        bankState->mJoin.mInsecurePrint = true;
    }

    if (cmd.isSet("mock"))
    {
        visaState->mJoin.mInsecureMockSubroutines = true;
        bankState->mJoin.mInsecureMockSubroutines = true;
    }


    runProtocol(visaState, bankState);

    std::cout << "Join Protocol Completed" << std::endl;

    secJoin::getOtherShare(visaState, isUnique);
    secJoin::getOtherShare(bankState, !isUnique);

    runProtocol(visaState, bankState);

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


void runProtocol(secJoin::State* visaState, secJoin::State* bankState)
{
    std::vector<oc::u8> buff;

    while (!secJoin::isProtocolReady(visaState))
    {
        buff = secJoin::runJoin(visaState, buff);
        // std::cout << "Visa is sending " << buff.size() << " bytes" << std::endl;
        buff = secJoin::runJoin(bankState, buff);
        // std::cout << "Bank is sending " << buff.size() << " bytes" << std::endl;
    }
    assert(secJoin::isProtocolReady(visaState));
    assert(secJoin::isProtocolReady(bankState));
}
