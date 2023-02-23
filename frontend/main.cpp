#include "tests/UnitTests.h"
#include "cryptoTools/Common/CLP.h"

int main(int argc, char** argv)
{
    oc::CLP clp(argc, argv);
    clp.set("-u");
    secJoin_Tests::Tests.runIf(clp);
    // secJoin_Tests::Tests.runAll();
    return 0;
}