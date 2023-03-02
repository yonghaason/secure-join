#include "LowMCPerm.h"



namespace secJoin
{

    const LowMC2<> LowMCPerm::mLowMc(false);

    const oc::BetaCircuit LowMCPerm::mLowMcCir = []() {
        LowMC2<> lowmc(false);
        oc::BetaCircuit cir;
        lowmc.to_enc_circuit(cir, true);
        cir.levelByAndDepth();
        return cir;
    }();
    

}