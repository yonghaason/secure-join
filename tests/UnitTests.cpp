#include "UnitTests.h"

#include "LowMCPerm_Test.h"
#include "PaillierPerm_Test.h"
#include "ComposedPerm_Test.h"
#include "DarkMatterPrf_Test.h"
#include "OleGenerator_Test.h"
#include "GMW_Test.h"
#include "RadixSort_Test.h"

#include <functional>

#include "DlpnPerm_Test.h"
#include "PaillierPerm_Test.h"
#include "ComposedPerm_Test.h"
#include "AdditivePerm_Test.h"

#include "AggTree_Tests.h"

namespace secJoin_Tests
{
    oc::TestCollection Tests([](oc::TestCollection& t) {


        t.add("Generator_BinOle_Test                         ", Generator_BinOle_Test);
        t.add("Generator_Ot_Test                             ", Generator_Ot_Test);
        t.add("Generator_ArithTriple_Test                    ", Generator_ArithTriple_Test);

        t.add("Gmw_half_test                                 ", Gmw_half_test);
        t.add("Gmw_basic_test                                ", Gmw_basic_test);
        t.add("Gmw_inOut_test                                ", Gmw_inOut_test);
        t.add("Gmw_xor_test                                  ", Gmw_xor_test);
        t.add("Gmw_and_test                                  ", Gmw_and_test);
        t.add("Gmw_na_and_test                               ", Gmw_na_and_test);
        t.add("Gmw_or_test                                   ", Gmw_or_test);
        t.add("Gmw_xor_and_test                              ", Gmw_xor_and_test);
        t.add("Gmw_aa_na_and_test                            ", Gmw_aa_na_and_test);
        t.add("Gmw_add_test                                  ", Gmw_add_test);
        t.add("Gmw_noLevelize_test                           ", Gmw_noLevelize_test);



        t.add("PaillierPerm_basic_test                       ", PaillierPerm_basic_test);
        t.add("LocMC_eval_test                               ", LocMC_eval_test);

        t.add("LowMCPerm_perm_test                           ", LowMCPerm_perm_test);
        t.add("LowMCPerm_secret_shared_input_perm_test       ", LowMCPerm_secret_shared_input_perm_test);
        t.add("ComposedPerm_replicated_perm_test             ", ComposedPerm_replicated_perm_test);
        t.add("AdditivePerm_xor_test                         ", AdditivePerm_xor_test);
        t.add("AdditivePerm_add_test                         ", AdditivePerm_add_test);
        
        //t.add("DarkMatter22Prf_plain_test                    ", DarkMatter22Prf_plain_test);
        //t.add("DarkMatter32Prf_plain_test                    ", DarkMatter32Prf_plain_test);
        //t.add("DarkMatter22Prf_util_test                     ", DarkMatter22Prf_util_test);
        //t.add("DarkMatter22Prf_proto_test                    ", DarkMatter22Prf_proto_test);
        //t.add("DarkMatter32Prf_proto_test                    ", DarkMatter32Prf_proto_test);

        t.add("DLpnPrf_plain_test                            ", DLpnPrf_plain_test);
        t.add("DLpnPrf_proto_test                            ", DLpnPrf_proto_test); 
        t.add("Dlpn_perm_test                                ", Dlpn_perm_test);

        t.add("RadixSort_aggregateSum_test                   ", RadixSort_aggregateSum_test);
        t.add("RadixSort_oneHot_test                         ", RadixSort_oneHot_test);
        t.add("RadixSort_bitInjection_test                   ", RadixSort_bitInjection_test);
        t.add("RadixSort_genValMasks2_test                   ", RadixSort_genValMasks2_test);
        t.add("RadixSort_hadamardSum_test                    ", RadixSort_hadamardSum_test);
        t.add("RadixSort_genBitPerm_test                     ", RadixSort_genBitPerm_test);
        t.add("RadixSort_genPerm_test                        ", RadixSort_genPerm_test);

        //t.add("AggTree_levelReveal_Test                      ", AggTree_levelReveal_Test);
        //t.add("AggTree_toPackedBin_Test                      ", AggTree_toPackedBin_Test);
        //t.add("AggTree_dup_pre_setLeaves_Test                ", AggTree_dup_pre_setLeaves_Test);

        });
}
