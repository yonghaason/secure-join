#include "secure-join/LowMCPerm.h"

void LowMCPerm_basic_test();
void LowMCPerm_secret_shared_input_test();
void LowMCPerm_replicated_perm_test();
std::array<Matrix<u8>, 2> share(Matrix<u8> v, PRNG& prng);
void checkResults(Matrix<u8> &x, std::array<Matrix<u8>, 2> &sout, std::vector<u64> &pi);
void checkResults(Matrix<u8> &x, std::array<Matrix<u8>, 2> &sout, std::vector<u64> &pi0, std::vector<u64> &pi1);