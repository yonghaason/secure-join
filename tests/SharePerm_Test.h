#include "secure-join/SharePerm.h"

void SharePerm_replicated_perm_test();
std::array<Matrix<u8>, 2> share(Matrix<u8> v, PRNG& prng);
void check_results(Matrix<u8> &x, std::array<Matrix<u8>, 2> &sout, std::vector<u64> &pi0, std::vector<u64> &pi1);