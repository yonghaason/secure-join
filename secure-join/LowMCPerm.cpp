#include "LowMCPerm.h"



namespace secJoin
{

    const LowMC2<>& LowMCPerm::mLowMc()
    {
        static const LowMC2<> m(false);
        return m;
    }

    const oc::BetaCircuit& LowMCPerm::mLowMcCir() {
        static oc::BetaCircuit cir;
        if (cir.mGates.size() == 0)
        {

            LowMCPerm::mLowMc().to_enc_circuit(cir, true);
            cir.levelByAndDepth();
        }
        return cir;
    };


}