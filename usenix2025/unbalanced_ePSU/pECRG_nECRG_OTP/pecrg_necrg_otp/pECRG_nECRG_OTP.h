#include "../pnecrg/pnECRG.h"
#include "define.h"
#include <coproto/Socket/AsioSocket.h>
#include <volePSI/config.h>
#include <volePSI/Defines.h>
#include <cryptoTools/Network/Channel.h>
#include <string> 
#include <fstream>
#include <iostream>
#include <istream>

#include <algorithm>

using namespace oc;


void pECRG_nECRG_OTP(u32 isSender, u32 numThreads);