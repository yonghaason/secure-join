#include "UnitTests.h"

#include "LowMCPerm_Test.h"
#include "PaillierPerm_Test.h"
#include "SharePerm_Test.h"
#include "DarkMatterPrf_Test.h"
namespace secJoin_Tests
{
    oc::TestCollection Tests([](oc::TestCollection& t) {
        

        t.add("PaillierPerm_basic_test                       ", PaillierPerm_basic_test);
        t.add("LowMCPerm_perm_test                           ", LowMCPerm_perm_test);
        t.add("LowMCPerm_inv_perm_test                       ", LowMCPerm_inv_perm_test);
        t.add("LowMCPerm_secret_shared_input_perm_test       ", LowMCPerm_secret_shared_input_perm_test);
        t.add("LowMCPerm_secret_shared_input_inv_perm_test   ", LowMCPerm_secret_shared_input_inv_perm_test);
        t.add("SharePerm_replicated_perm_test                ", SharePerm_replicated_perm_test);
        t.add("DarkMatterPrf_plain_test                      ", DarkMatterPrf_plain_test);
        t.add("DarkMatterPrf_util_test                       ", DarkMatterPrf_util_test);
        t.add("DarkMatterPrf_proto_test                      ", DarkMatterPrf_proto_test);
        

    });
}
