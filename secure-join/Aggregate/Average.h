#pragma once
#include "secure-join/Sort/RadixSort.h"
#include "secure-join/Join/Table.h"
#include "secure-join/Join/OmJoin.h"

namespace secJoin
{
    using SharedTable = Table;
	using SharedColumn = Column;
    struct Average
    {
        bool mInsecurePrint = true, mInsecureMockSubroutines = false;


        static void concatColumns(ColRef groupByCol, std::vector<ColRef> average, BinMatrix& ret,
            std::vector<OmJoin::Offset>& offsets);

        // static macoro::task<> avg(ColRef groupByCol, ColRef avgCol, SharedTable& out,
        //     oc::PRNG& prng, OleGenerator& ole, coproto::Socket& sock);

    
    

    };

}