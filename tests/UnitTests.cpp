#include "UnitTests.h"

#include "LowMCPerm_Test.h"
#include "PaillierPerm_Test.h"
#include "SharePerm_Test.h"
#include "DarkMatterPrf_Test.h"
#include "OleGenerator_Test.h"

namespace secJoin_Tests
{
    oc::TestCollection Tests([](oc::TestCollection& t) {
        

        t.add("PaillierPerm_basic_test                       ", PaillierPerm_basic_test);
        t.add("LocMC_eval_test                               ", LocMC_eval_test);
        
        t.add("LowMCPerm_perm_test                           ", LowMCPerm_perm_test);
        t.add("LowMCPerm_inv_perm_test                       ", LowMCPerm_inv_perm_test);
        t.add("LowMCPerm_secret_shared_input_perm_test       ", LowMCPerm_secret_shared_input_perm_test);
        t.add("LowMCPerm_secret_shared_input_inv_perm_test   ", LowMCPerm_secret_shared_input_inv_perm_test);
        t.add("SharePerm_replicated_perm_test                ", SharePerm_replicated_perm_test);
        t.add("DarkMatter22Prf_plain_test                    ", DarkMatter22Prf_plain_test);
        t.add("DarkMatter32Prf_plain_test                    ", DarkMatter32Prf_plain_test);
        t.add("DarkMatter22Prf_util_test                     ", DarkMatter22Prf_util_test);
        t.add("DarkMatter22Prf_proto_test                    ", DarkMatter22Prf_proto_test);
        t.add("DarkMatter32Prf_proto_test                    ", DarkMatter32Prf_proto_test);
        
        t.add("DLpnPrf_plain_test                            ", DLpnPrf_plain_test);
        t.add("DLpnPrf_proto_test                            ", DLpnPrf_proto_test);

        t.add("ALpnPrf_plain_test                            ", ALpnPrf_plain_test);
        t.add("ALpnPrf_proto_test                            ", ALpnPrf_proto_test);
        
        t.add("OleGenerator_Basic_Test                       ", OleGenerator_Basic_Test);

    });
}
