#pragma once
#include "secure-join/LowMCPerm.h"
#include "cryptoTools/Common/CLP.h"


void LocMC_eval_test(const oc::CLP& cmd);
void LowMCPerm_perm_test(const oc::CLP& cmd);
void LowMCPerm_inv_perm_test();
void LowMCPerm_secret_shared_input_inv_perm_test();
void LowMCPerm_secret_shared_input_perm_test();
// void LowMCPerm_replicated_perm_test();
oc::Matrix<secJoin::u8> reconstruct_from_shares(oc::Matrix<secJoin::u8> v1, oc::Matrix<secJoin::u8> v2);
std::array<oc::Matrix<secJoin::u8>, 2> share(oc::Matrix<secJoin::u8> v, oc::PRNG& prng);
void check_inv_results(oc::Matrix<secJoin::u8> &x,std::array<oc::Matrix<secJoin::u8>, 2> &sout);
void check_results(oc::Matrix<secJoin::u8>& x, std::array<oc::Matrix<secJoin::u8>, 2>& sout, secJoin::Perm& pi, bool invPerm);
// void check_results(Matrix<u8> &x, std::array<Matrix<u8>, 2> &sout, std::vector<u64> &pi0, std::vector<u64> &pi1);