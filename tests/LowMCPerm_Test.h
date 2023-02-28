#include "secure-join/LowMCPerm.h"

void LowMCPerm_perm_test();
void LowMCPerm_inv_perm_test();
void LowMCPerm_secret_shared_input_inv_perm_test();
void LowMCPerm_secret_shared_input_perm_test();
// void LowMCPerm_replicated_perm_test();
Matrix<u8> reconstruct_from_shares(Matrix<u8> v1, Matrix<u8> v2);
std::array<Matrix<u8>, 2> share(Matrix<u8> v, PRNG& prng);
void check_inv_results(Matrix<u8> &x,std::array<Matrix<u8>, 2> &sout);
void check_results(Matrix<u8> &x, std::array<Matrix<u8>, 2> &sout, std::vector<u64> &pi, bool invPerm);
// void check_results(Matrix<u8> &x, std::array<Matrix<u8>, 2> &sout, std::vector<u64> &pi0, std::vector<u64> &pi1);