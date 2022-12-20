

#include "cryptoTools/Common/Log.h"
#include <functional>
#include "UnitTests.h"

#include "LowMCPerm_Test.h"
#include "PaillierPerm_Test.h"

namespace secJoin_Tests
{
    oc::TestCollection Tests([](oc::TestCollection& t) {
        
        t.add("PaillierPerm_basic_test       ", PaillierPerm_basic_test);
        t.add("LowMCPerm_basic_test       ", LowMCPerm_basic_test);

    });
}
