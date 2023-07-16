
#include "CWrapper_Test.h"

void wrapper_test()
{
    std::string str("Harshal");
    testApi(str);

    std::string visaCsvPath("/Users/harshah/Documents/Core/secure-join/tests/tables/visa.csv");
    std::string bankCsvPath("/Users/harshah/Documents/Core/secure-join/tests/tables/bank.csv");
    std::string visaMetaDataPath("/Users/harshah/Documents/Core/secure-join/tests/tables/visa_meta.txt");
    std::string clientMetaDataPath("/Users/harshah/Documents/Core/secure-join/tests/tables/bank_meta.txt");
    std::string joinVisaCols("PAN");
    std::string joinClientCols("PAN");
    std::string selectVisaCols("Risk_Score,PAN");
    std::string selectClientCols("Balance");
    std::string joinCsvPath("/Users/harshah/Documents/Core/secure-join/tests/tables/joindata.csv");
    std::string joinMetaPath("/Users/harshah/Documents/Core/secure-join/tests/tables/joindata_meta.txt");
    bool isUnique = true;

    long visaState = initState(visaCsvPath, visaMetaDataPath, clientMetaDataPath, joinVisaCols,
                joinClientCols,  selectVisaCols, selectClientCols, isUnique);


    long bankState = initState(bankCsvPath, visaMetaDataPath, clientMetaDataPath, joinVisaCols,
            joinClientCols,  selectVisaCols, selectClientCols, !isUnique);


    runProtocol(visaState, bankState);

    std::cout << "Join Protocol Completed" << std::endl;

    getOtherShare(visaState, isUnique);
    getOtherShare(bankState, !isUnique);

    runProtocol(visaState, bankState);

    getJoinTable(visaState, joinCsvPath, joinMetaPath, isUnique);


    releaseState(visaState);
    releaseState(bankState);
}


void runProtocol(long visaState, long bankState)
{
    std::vector<oc::u8> buff;

    while (!isProtocolReady(visaState))
    {
        buff = runJoin(visaState, buff);
        std::cout << "Visa is sending " << buff.size() << " bytes" << std::endl;
        buff = runJoin(bankState, buff);
        std::cout << "Bank is sending " << buff.size() << " bytes" << std::endl;
    }
    
}