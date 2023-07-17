
#include "CWrapper_Test.h"
#if SECUREJOIN_ENABLE_WRAPPER

void wrapper_test()
{
    // std::string str("Hello World!");
    // testApi(str);

    std::string rootPath(SEC_JOIN_ROOT_DIRECTORY);
    std::string visaCsvPath = rootPath + "/tests/tables/visa.csv";
    std::string bankCsvPath  = rootPath + "/tests/tables/bank.csv";
    std::string visaMetaDataPath = rootPath + "/tests/tables/visa_meta.txt";
    std::string clientMetaDataPath = rootPath + "/tests/tables/bank_meta.txt";
    std::string joinVisaCols("PAN");
    std::string joinClientCols("PAN");
    std::string selectVisaCols("Risk_Score,PAN");
    std::string selectClientCols("Balance");
    std::string joinCsvPath = rootPath + "/tests/tables/joindata.csv";
    std::string joinMetaPath= rootPath + "/tests/tables/joindata_meta.txt";
    bool isUnique = true;

    long visaState = secJoin::initState(visaCsvPath, visaMetaDataPath, clientMetaDataPath, joinVisaCols,
                joinClientCols,  selectVisaCols, selectClientCols, isUnique);


    long bankState = secJoin::initState(bankCsvPath, visaMetaDataPath, clientMetaDataPath, joinVisaCols,
            joinClientCols,  selectVisaCols, selectClientCols, !isUnique);


    runProtocol(visaState, bankState);

    std::cout << "Join Protocol Completed" << std::endl;

    secJoin::getOtherShare(visaState, isUnique);
    secJoin::getOtherShare(bankState, !isUnique);

    runProtocol(visaState, bankState);

    // secJoin::getJoinTable(visaState, joinCsvPath, joinMetaPath, isUnique);

    void *state = (void *) visaState;
    secJoin::State* vWrapperState = (secJoin::State*)state;

    void *state1 = (void *) bankState;
    secJoin::State* bWrapperState = (secJoin::State*)state1;

    auto exp = secJoin::join(vWrapperState->mLTable[joinVisaCols], 
                             bWrapperState->mRTable[joinClientCols],
                             vWrapperState->selectCols);

    if (vWrapperState->mOutTable != exp)
    {
        std::cout << "exp \n" << exp << std::endl;
        std::cout << "act \n" << vWrapperState->mOutTable << std::endl;
        throw RTE_LOC;
    }

    secJoin::releaseState(visaState);
    secJoin::releaseState(bankState);

}


void runProtocol(long visaState, long bankState)
{
    std::vector<oc::u8> buff;

    while (!secJoin::isProtocolReady(visaState))
    {
        buff = secJoin::runJoin(visaState, buff);
        // std::cout << "Visa is sending " << buff.size() << " bytes" << std::endl;
        buff = secJoin::runJoin(bankState, buff);
        // std::cout << "Bank is sending " << buff.size() << " bytes" << std::endl;
    }
    
}

#endif