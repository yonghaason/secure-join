#include "Average.h"
// #include "secure-join/Join/OmJoin.h"

namespace secJoin{

    // concatinate all the columns in `average` that are part of the table.
    // Then append 1's the end for the count
    void Average::concatColumns(
        ColRef groupByCol,
        std::vector<ColRef> average,
        BinMatrix& ret,
        std::vector<OmJoin::Offset>& offsets)
    {
        u64 m = average.size();
        u64 n0 = groupByCol.mCol.rows();
        u64 rowSize = 0;

        std::vector<BinMatrix*> avg;

        offsets.clear();
        offsets.reserve(m+1);
        for (u64 i = 0; i < m; ++i)
        {
            if (&groupByCol.mTable == &average[i].mTable)
            {
                auto bytes = oc::divCeil(average[i].mCol.getBitCount(), 8);
                assert(average[i].mCol.rows() == n0);
                avg.emplace_back(&average[i].mCol.mData);
                offsets.emplace_back(OmJoin::Offset{ rowSize * 8, average[i].mCol.mData.bitsPerEntry(), average[i].mCol.mName });
                rowSize += bytes;
            }
            else
            {
                std::string temp("Average table is not same as groupby table\n");
                throw std::runtime_error(temp + LOCATION);
            }
            
        }

        // Adding a Columns of 1's for calculating average
        BinMatrix ones(n0, sizeof(oc::u64) * 8);
        for(oc::u64 i = 0; i < n0; i++)
            ones(i,0) = 1;
        
        
        offsets.emplace_back(OmJoin::Offset{ rowSize * 8, sizeof(oc::u64) * 8, "count*" });
        avg.emplace_back(&ones);

        ret.resize(n0, (rowSize +sizeof(oc::u64) ) * 8);
        OmJoin::concatColumns(ret, avg);

    }

    // Assumptions: 
    // 1) Both Average Col & Group by Col are not null
    // 2) Currently one group by column is supported
    // macoro::task<> Average::avg(
    //     ColRef groupByCol,
    //     std::vector<ColRef> avgCol,
    //     SharedTable& out,
    //     oc::PRNG& prng,
    //     OleGenerator& ole,
    //     coproto::Socket& sock)
    // {

    //     MC_BEGIN(macoro::task<>, groupByCol, avgCol, &out, &prng, &ole, &sock,
    //         keys = BinMatrix{},
    //         data = BinMatrix{},
    //         sPerm = AdditivePerm{},
    //         sort = RadixSort{},
    //         offsets = std::vector<OmJoin::Offset>{}
    //         );

    //     keys = groupByCol.mCol.mData;

    //     // sort.mInsecureMock = mInsecureMockSubroutines;

    //     MC_AWAIT(sort.genPerm(keys, sPerm, ole, sock));
    //     concatColumns(groupByCol, avgCol, data, offsets);



    //     MC_END();

        
    // }


}