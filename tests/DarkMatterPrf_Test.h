#pragma once

#include "cryptoTools/Common/CLP.h"

void DarkMatter22Prf_plain_test();
void DarkMatter22Prf_util_test();
void DarkMatter22Prf_proto_test(const oc::CLP& cmd);

void DarkMatter32Prf_plain_test();
void DarkMatter32Prf_proto_test(const oc::CLP& cmd);



void DLpnPrf_mod3BitDecompostion_test();
void DLpnPrf_BMult_test();
void DLpnPrf_mod2_test(const oc::CLP& cmd);
void DLpnPrf_plain_test();
void DLpnPrf_proto_test(const oc::CLP& cmd);

