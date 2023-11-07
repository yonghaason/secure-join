#pragma once
#include <string>
#include <vector>
#include "secure-join/Defines.h"
#include "Debug.h"
#include "state.h"
#include "secure-join/Util/CSVParser.h"
#include "nlohmann/json.hpp"
#include "Defines.h"
#include "secure-join/Util/ArrGate.h"
#include "PkgReqParser.h"

namespace secJoin
{
    struct State;

    void testApi(std::string& str);
    State* initState(std::string& csvPath, std::string& visaMetaDataPath, std::string& clientMetaDataPath,
        std::vector<std::string>& literals, std::vector<oc::i64>& opInfo, bool isUnique,
        bool verbose, bool mock, bool debug);
    std::vector<u8> runProtocol(State* stateAddress, std::vector<u8>& buff);
    void releaseState(State* memoryAddress);
    bool isProtocolReady(State* stateAddress);
    void getOtherShare(State* stateAddress, bool isUnique, bool isAgg);
    void getJoinTable(State* stateAddress, std::string csvPath, std::string metaDataPath, bool isUnique);
    oc::u64 getRColIndex(oc::u64 relativeIndex, oc::u64 lColCount, oc::u64 rColCount);
    void aggFunc(State* cState);
}


