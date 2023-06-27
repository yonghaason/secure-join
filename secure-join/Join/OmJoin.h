#pragma once
#include "secure-join/Join/Table.h"
#include "cryptoTools/Circuit/BetaLibrary.h"
#include "secure-join/GMW/Gmw.h"
#include "secure-join/AggTree/AggTree.h"
#include "secure-join/Sort/RadixSort.h"

namespace secJoin
{
	using SharedTable = Table;
	using SharedColumn = Column;

	struct BgrrJoin : public oc::TimerAdapter
	{
        // OleGenerator* mOle = nullptr;

        // void init(OleGenerator& ole)
        // {
        //     mOle = &ole;
        // }

		// output a combined table that has the leftColumn
		// concatenated with the rightColumn (doubling the 
		// number of rows). THe left column will have a
		// zero appended as its LSB while the right gets
		// a one appended.
		BinMatrix loadKeys(
			ColRef leftJoinCol,
			ColRef rightJoinCol)
		{
			assert(leftJoinCol.mCol.getBitCount() == rightJoinCol.mCol.getBitCount());
			auto bits = leftJoinCol.mCol.getBitCount();
			//auto bytes = leftJoinCol.mCol.getByteCount();

			BinMatrix keys(leftJoinCol.mCol.mData.numEntries() + rightJoinCol.mCol.mData.numEntries(), bits);

			auto size0 = leftJoinCol.mCol.mData.size();
			auto size1 = rightJoinCol.mCol.mData.size();

			u8* d0 = keys.data();
			u8* d1 = keys.data() + size0;
			//u8* e0 = keys.data() + size0;
			//u8* e1 = keys.data() + size0 + size1;
			u8* s0 = leftJoinCol.mCol.mData.data();
			u8* s1 = rightJoinCol.mCol.mData.data();

			memcpy(d0, s0, size0);
			memcpy(d1, s1, size1);

			return keys;
		}

		// this circuit compares two inputs for equality with the exception that
		// the first bit is ignored.
		oc::BetaCircuit getControlBitsCircuit(u64 bitCount)
		{
			oc::BetaLibrary lib;
			return *lib.int_eq(bitCount);
		}

		macoro::task<> getControlBits(
            BinMatrix& sKeys, 
            coproto::Socket& sock, 
            BinMatrix& out, 
            OleGenerator& ole)
		{
            MC_BEGIN(macoro::task<>, this, &sKeys, &sock, &out, &ole, 
                cir = oc::BetaCircuit{},
                bin = Gmw{},
                n = u64{}, m = u64{}
            );
			cir = getControlBitsCircuit(sKeys.bitsPerEntry());
			bin.init(sKeys.numEntries(), cir, ole);

			bin.setInput(0, sKeys);

			n = sKeys.numEntries();
			m = sKeys.bytesPerEntry();

            {
                // we start on the left row and copy to the start
                auto s0 = sKeys[0].data() + sKeys[0].size() - m;
                auto s1 = sKeys[1].data() + sKeys[1].size() - m;
                for (u64 i = 0; i < n; ++i)
                {
                    memcpy(s0, s0 - m, m);
                    memcpy(s1, s1 - m, m);
                }
            }

			// everyone invert their first share, this makes sure the 
			// first control bit is zero, as required.
			sKeys.mData(0) = ~sKeys.mData(0);

			bin.setInput(1, sKeys);

			MC_AWAIT(bin.run(sock));

			out.resize(n, 1);
			bin.getOutput(0, out);

            MC_END();
		}

		void copyColumns(
			BinMatrix& dst,
			u64 rowBegin,
			span<ColRef> cols)
		{
			auto m = cols.size();
			auto n = cols[0].mCol.rows();
			auto d0 = (u8*)(dst.data() + rowBegin * dst.cols());
			auto e0 = (u8*)(dst.data() + dst.size());

			std::vector<u64> 
                sizes(m),
				srcSteps(m);
			std::vector<u8*> srcs(m);
			u64 rem = dst.cols();
			for (u64 i = 0; i < m; ++i)
			{
				sizes[i] = oc::divCeil(cols[i].mCol.getBitCount(), 8);
				srcs[i] =  cols[i].mCol.data();
				rem -= sizes[i];
				srcSteps[i] = cols[i].mCol.mData.cols();
			}

			for (u64 i = 0; i < n; ++i)
			{
				for (u64 j = 0; j < m; ++j)
				{
					assert(d0 + sizes[j] <= e0);
					memcpy(d0, srcs[j], sizes[j]);

					srcs[j][0] += srcSteps[j];
					d0 += sizes[j];
				}

				d0 += rem;
			}
		}

		BinMatrix concatColumns(
			ColRef leftJoinCol,
			span<ColRef> selects,
			u64 numDummies)
		{
			u64 m = selects.size();
			u64 n0 = leftJoinCol.mCol.rows();
			u64 leftSizeBytes = 0;

			std::vector<ColRef> left, right;

			for (u64 i = 0; i < m; ++i)
			{
				auto bytes = oc::divCeil(selects[i].mCol.getBitCount(), 8);
				if (&leftJoinCol.mTable == &selects[i].mTable)
				{
					assert(selects[i].mCol.rows() == n0);
					left.emplace_back(selects[i]);
					leftSizeBytes += bytes;
				}
                
			}
			BinMatrix ret(n0 + numDummies, leftSizeBytes * 8);
			copyColumns(ret, 0, left);
			return ret;
		}

		void getOutput(
			BinMatrix& data,
			//oc::MatrixView<i64> revealBits,
			span<ColRef> selects,
			ColRef& left,
            SharedTable& out)
		{
			throw RTE_LOC;
			//u64 m = selects.size();
			//u64 inRows = data.rows();
			//u64 outRows = data.n1;
			//u64 outSizeBytes = 0;
			//std::vector<u64> sizes(m), sSteps(m), dSteps(m);
			//std::vector<std::array<i64*, 2>> dsts(m), srcs(m);
			//assert(revealBits.size() == inRows);

			//SharedTable out;
			//out.mColumns.resize(selects.size());

			//u64 leftOffset = 0;
			//u64 rightOffset = 0;
			//for (u64 i = 0; i < m; ++i)
			//{
			//	sizes[i] = oc::divCeil(selects[i].mCol.bitCount(), 8);
			//	out[i].mCol.resize(outRows, selects[i].mCol.bitCount());
			//	dsts[i] = { out[i].mCol[0].data(), out[i].mCol[1].data() };
			//	outSizeBytes += sizes[i];
			//	dSteps[i] = out[i].mCol.i64Cols();

			//	if (&left.mTable == &selects[i].mTable)
			//	{
			//		srcs[i][0] = (i64*)(((u8*)data[0].data()) + leftOffset);
			//		srcs[i][1] = (i64*)(((u8*)data[1].data()) + leftOffset);
			//		leftOffset += sizes[i];
			//		sSteps[i] = data.mLeft[0].cols();
			//	}
			//	else
			//	{
			//		srcs[i][0] = (i64*)(((u8*)data.mRight[0].data()) + rightOffset);
			//		srcs[i][1] = (i64*)(((u8*)data.mRight[1].data()) + rightOffset);
			//		rightOffset += sizes[i];
			//	}

			//}
			//assert(oc::roundUpTo(data.mLeft.bitCount(), 8) == leftOffset);
			//assert(oc::roundUpTo(data.mRight.bitCount(), 8) == rightOffset);

			//for (u64 i = 0; i < inRows; ++i)
			//{
			//	if (revealBits(i) & 1)
			//	{
			//		for (u64 j = 0; j < m; ++j)
			//		{
			//			memcpy(dsts[j][0], srcs[j][0], sizes[j]);
			//			memcpy(dsts[j][1], srcs[j][1], sizes[j]);

			//			srcs[j][0] += sSteps[j];
			//			srcs[j][1] += sSteps[j];
			//			dsts[j][0] += dSteps[j];
			//			dsts[j][1] += dSteps[j];
			//		}
			//	}
			//}
			//for (u64 i = 0; i < m; ++i)
			//{
			//	assert(dsts[i][0] == out[i].mCol[0].data());
			//	assert(dsts[i][1] == out[i].mCol[1].data());
			//}

		}

        AggTree::Operator getDupCircuit()
        {
            return [](
                oc::BetaCircuit& c,
                const oc::BetaBundle& left,
                const oc::BetaBundle& right,
                oc::BetaBundle& out)
                {
                    for(u64 i =0; i < left.size(); ++i)
                        c.addCopy(left[i], out[i]);
                };
        }

		// leftJoinCol should be unique
		macoro::task<> join(
			ColRef leftJoinCol,
			ColRef rightJoinCol,
			std::vector<ColRef> selects,
            SharedTable& out,
            oc::PRNG& prng,
            OleGenerator& ole,
            coproto::Socket& sock)
		{
            MC_BEGIN(macoro::task<>, this, leftJoinCol, rightJoinCol, selects, &out, &prng, &ole, &sock,
                keys = BinMatrix{},
                sPerm = AdditivePerm{},
                controlBits = BinMatrix{},
                data = BinMatrix{},
                temp = BinMatrix{},
                aggTree = AggTree{},
                sort = RadixSort{}
            );
            
			setTimePoint("start");

			keys = loadKeys(leftJoinCol, rightJoinCol);
			setTimePoint("load");

            MC_AWAIT(sort.genPerm(keys, sPerm, ole, sock));
			setTimePoint("sort");

			MC_AWAIT(getControlBits(keys, sock, controlBits, ole));
			keys = {};
			setTimePoint("control");

			data = concatColumns(leftJoinCol, selects, rightJoinCol.mTable.rows());
			setTimePoint("concat");

			MC_AWAIT(sPerm.apply<u8>(data.mData, temp.mData, prng, sock, ole, true));
			std::swap(data, temp);
			setTimePoint("applyInv-sort");

			MC_AWAIT(aggTree.apply(data, controlBits, getDupCircuit(), AggTreeType::Prefix, sock, ole, temp));
			std::swap(data, temp);
			setTimePoint("duplicate");

			MC_AWAIT(sPerm.apply<u8>(data.mData, temp.mData, prng, sock, ole, false));
			std::swap(data, temp);
			setTimePoint("apply-sort");

			getOutput(data, selects, leftJoinCol, out);

            MC_END();
		}


	};

}