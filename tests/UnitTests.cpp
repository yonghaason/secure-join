

#include "cryptoTools/Common/Log.h"
#include <functional>
#include "UnitTests.h"

#include "PaillierPerm_Test.h"

namespace secJoin_Tests
{
    oc::TestCollection Tests([](oc::TestCollection& t) {
        
        t.add("PaillierPerm_basic_test       ", PaillierPerm_basic_test);

    });
}
