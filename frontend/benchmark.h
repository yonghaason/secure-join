#include "cryptoTools/Common/CLP.h"
#include <chrono>

namespace secJoin
{
    void CorGen_benchmark(const oc::CLP& cmd);
    void Radix_benchmark(const oc::CLP& cmd);
    void OmJoin_benchmark(const oc::CLP& cmd);
    void AltMod_benchmark(const oc::CLP& cmd);
    void OT_benchmark(const oc::CLP& cmd);
    void F4_benchmark(const oc::CLP& cmd);
    void AltModPerm_benchmark(const oc::CLP& cmd);
    void AltMod_compressB_benchmark(const oc::CLP& cmd);
    void AltMod_encodeX_benchmark(const oc::CLP& cmd);
    void AltMod_expandA_benchmark(const oc::CLP& cmd);
    void AltMod_sampleMod3_benchmark(const oc::CLP& cmd);
    void AltModPsu_benchmark(const oc::CLP& cmd);
    void AltModPsu_debug_benchmark(const oc::CLP& cmd);
    void AltModPsu_correctness_benchmark(const oc::CLP& cmd);
    void AltModPsu_run_gmw_test_benchmark(const oc::CLP& cmd);
    void AltModPsu_unbalance_benchmark(const oc::CLP& cmd);
    
    void PprfPerm_benchmark(const oc::CLP& cmd);
    void transpose_benchmark(const oc::CLP& cmd);

}
