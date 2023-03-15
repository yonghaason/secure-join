#include "UnitTests.h"

namespace secJoin_Tests
{
    oc::TestCollection Tests([](oc::TestCollection& t) {
        

        t.add("PaillierPerm_basic_test                       ", PaillierPerm_basic_test);
        t.add("LowMCPerm_perm_test                           ", LowMCPerm_perm_test);
        t.add("LowMCPerm_secret_shared_input_perm_test       ", LowMCPerm_secret_shared_input_perm_test);
        //t.add("LowMCPerm_secret_shared_input_inv_perm_test   ", LowMCPerm_secret_shared_input_inv_perm_test);
        t.add("SharePerm_replicated_perm_test                ", SharePerm_replicated_perm_test);
        t.add("VectorPerm_basic_test                           ", VectorPerm_basic_test);

    });
}
