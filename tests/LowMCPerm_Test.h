#include "secure-join/LowMCPerm.h"

void LowMCPerm_basic_test();
std::array<Matrix<u8>, 2> share(Matrix<u8> v, PRNG& prng);
void checkResults(Matrix<u8> &x, std::array<Matrix<u8>, 2> &sout, std::vector<u64> &pi);