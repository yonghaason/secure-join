#pragma once
#include "Wrapper/CppWrapper.h"
#include "cryptoTools/Common/CLP.h"

void OmJoin_wrapper_test(const oc::CLP& cmd);
void runProtocol(secJoin::State* visaState, secJoin::State* bankState, bool verbose);