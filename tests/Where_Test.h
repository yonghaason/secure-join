#pragma once
#include "cryptoTools/Common/BitVector.h"
// #include <cstdlib>
#include "secure-join/config.h"
#include "cryptoTools/Common/CLP.h"
#include "Wrapper/PkgReqParser.h"
#include "secure-join/Util/CSVParser.h"
#include "secure-join/Aggregate/Where.h"
#include "secure-join/Join/OmJoin.h"
#include "secure-join/Util/Util.h"
#include "secure-join/Aggregate/Average.h"

void Where_genWhBundle_Test(const oc::CLP& cmd);
void Where_ArrType_Less_Than_Test(const oc::CLP& cmd);
void Where_ArrType_Greater_Than_Equals_Test(const oc::CLP& cmd);
void Where_ArrType_Addition_Test(const oc::CLP& cmd);
void Where_ArrType_Equals_Test(const oc::CLP& cmd);
void Where_ArrType_Not_Equals_Test(const oc::CLP& cmd);
void Where_ArrType_And_Or_Test(const oc::CLP& cmd);
void Where_join_where_Test(const oc::CLP& cmd);
void Where_join_where_csv_Test(const oc::CLP& cmd);
void Where_avg_where_csv_Test(const oc::CLP& cmd);
