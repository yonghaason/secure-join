

#include "../pnmcrg/pnMCRG.h"

using namespace oc;
/*
bOPRF + OKVS = bOPPRF

pECRG + bOPPRF = pMCRG

pMCRG + nECRG = pnMCRG
*/


// balanced ePSU use pnMCRG and one-time pad
std::vector<block> balanced_ePSU(u32 idx, std::vector<block> &set, u32 numThreads);