#pragma once
#include <string>
#include <vector>
#include "secure-join/Defines.h"
#include "Debug.h"
#include "state.h"
#include "secure-join/Util/CSVParser.h"

namespace secJoin
{
    struct State;

    void testApi(std::string& str);
    State* initState(std::string& csvPath, std::string& visaMetaDataPath, std::string& clientMetaDataPath,
        std::string& visaJoinCols, std::string& clientJoinCols, std::string& selectVisaCols,
        std::string& selectClientCols, bool isUnique,
        bool verbose, bool mock, bool debug);

    std::vector<u8> runJoin(State* stateAddress, std::vector<u8>& buff);
    void releaseState(State* memoryAddress);
    bool isProtocolReady(State* stateAddress);
    void getOtherShare(State* stateAddress, bool isUnique);
    void getJoinTable(State* stateAddress, std::string csvPath, std::string metaDataPath, bool isUnique);

}


