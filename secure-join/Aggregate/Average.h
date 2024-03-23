#pragma once
#include "secure-join/Sort/RadixSort.h"
#include "secure-join/Join/Table.h"
#include "secure-join/Join/OmJoin.h"
#include "cryptoTools/Circuit/BetaLibrary.h"
#include "secure-join/Util/Util.h"
#include "libOTe/Tools/LinearCode.h"

namespace secJoin
{
    using SharedTable = Table;
    using SharedColumn = Column;
    struct Average
    {
        bool mInsecurePrint = false, mInsecureMockSubroutines = false;

        // statical security parameter.
		u64 mStatSecParam = 40;

		// the subprotocol that sorts the keys.
		RadixSort mSort;

		// the sorting permutation.
		AltModComposedPerm mPerm;

		// the subprotocol that will perform the copies.
		AggTree mAggTree;

		// the subprotocol that will compute the control bits.
		Gmw mControlBitGmw;

		// the subprotocol that will compute which output rows are active.
		Gmw mUpdateActiveFlagGmw;

		// the offset of the columns in the data matrix.
		std::vector<OmJoin::Offset> mOffsets;

		u64 mPartyIdx = -1;

		bool mRemoveDummies = false;


        void extractKeyInfo(
            BinMatrix& data,
            BinMatrix& grpByData,
            BinMatrix& actFlag,
            BinMatrix& compressKeys,
            const std::vector<OmJoin::Offset>& offsets);

        void loadKeys(
            ColRef groupByCol,
            std::vector<u8>& actFlagVec,
            BinMatrix& compressKeys);

        void init(
            ColRef groupByCol,
            std::vector<ColRef> avgCol,
            CorGenerator& ole,
            bool removeDummies,
            bool printSteps = false,
            bool mock = false);

        void concatColumns(
            ColRef groupByCol,
            std::vector<ColRef> avgCol,
            std::vector<u8>& actFlag,
            BinMatrix& compressKeys,
            BinMatrix& ret);

        void concatColumns(
            BinMatrix& data,
            BinMatrix& groupByData,
            BinMatrix& actFlag,
            BinMatrix& ret);

        macoro::task<> avg(
            ColRef groupByCol, 
            std::vector<ColRef> avgCol, 
            SharedTable& out,
            oc::PRNG& prng,
            coproto::Socket& sock,
            bool remDummies = false,
            Perm randPerm = {});

        macoro::task<> getControlBits(
            BinMatrix& keys,
            coproto::Socket& sock,
            BinMatrix& out);

        static AggTree::Operator getAddCircuit(
            std::vector<OmJoin::Offset>& offsets,
            oc::BetaLibrary::Optimized op);

        void getOutput(
                SharedTable& out,
                std::vector<ColRef> avgCol,
                ColRef groupByCol,
                BinMatrix& data,
                std::vector<OmJoin::Offset>& offsets);

        static macoro::task<> getOutput(
            SharedTable& out,
            std::vector<ColRef> avgCol,
            ColRef groupByCol,
            BinMatrix& keys,
            BinMatrix& data,
            std::vector<OmJoin::Offset>& offsets,
            std::vector<OmJoin::Offset>& keyOffsets,
            CorGenerator& ole,
            coproto::Socket& sock,
            oc::PRNG& prng,
            bool securePerm,
            Perm& randPerm);

        macoro::task<> updateActiveFlag(
            BinMatrix& actFlag,
            BinMatrix& choice,
            BinMatrix& out,
            coproto::Socket& sock);



        static void concatColumns(
            BinMatrix& dst,
            span<BinMatrix*> cols)
        {
            auto m = cols.size();
            //auto n = cols[0]->rows();
            //auto d0 = dst.data();
            auto e0 = dst.data() + dst.size();

            std::vector<u64>
                offsets(m),
                sizes(m),
                srcSteps(m);
            std::vector<u8*> srcs(m);
            u64 rem = dst.cols();
            for (u64 i = 0; i < m; ++i)
            {
                sizes[i] = oc::divCeil(cols[i]->bitsPerEntry(), 8);
                if (i)
                    offsets[i] = offsets[i - 1] + sizes[i - 1];

                srcs[i] = cols[i]->data();
                srcSteps[i] = cols[i]->mData.cols();
            }

            for (u64 j = 0; j < m; ++j)
            {
                auto n = cols[j]->rows();
                assert(n <= dst.rows());
                auto d0 = dst.data() + offsets[j];

                auto src = srcs[j];
                auto size = sizes[j];
                auto step = srcSteps[j];
                for (u64 i = 0; i < n; ++i)
                {
                    assert(d0 + size <= e0);
                    memcpy(d0, src, size);

                    src += step;
                    d0 += rem;
                }
            }
        }


    };

}