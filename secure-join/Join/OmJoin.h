#pragma once
//#include "aby3-DB/DBServer.h"
//#include "aby3/sh3/Sh3Converter.h"
//#include "ChikkpSort.h"
//#include "DuplicationTree.h"
//#include "BinEval.h"
//#include "cryptoTools/Common/Timer.h"
//
//namespace aby3
//{
//	using SharedTable = oc::SharedTable;
//	using SharedColumn = oc::SharedColumn;
//
//	struct BgrrJoin : public oc::TimerAdapter
//	{
//		u64 mPartyIdx = -1;
//		CommPkg mComm;
//		Sh3ShareGen* mGen = nullptr;
//
//		void init(u64 partyIdx, oc::Channel& prev, oc::Channel& next, Sh3ShareGen& gen)
//		{
//			mPartyIdx = partyIdx;
//			mComm = { prev, next };
//			mGen = &gen;
//		}
//
//		// output a combined table that has the leftColumn
//		// concatenated with the rightColumn (doubling the 
//		// number of rows). THe left column will have a
//		// zero appended as its LSB while the right gets
//		// a one appended.
//		sbMatrix loadKeys(
//			SharedTable::ColRef leftJoinCol,
//			SharedTable::ColRef rightJoinCol)
//		{
//			assert(leftJoinCol.mCol.bitCount() == rightJoinCol.mCol.bitCount());
//			auto bits = leftJoinCol.mCol.bitCount();
//			auto su64Size = leftJoinCol.mCol.i64Cols();
//
//			sbMatrix keys(leftJoinCol.mCol.rows() + rightJoinCol.mCol.rows(), bits);
//			auto ku64Size = keys.i64Cols();
//			assert(ku64Size == su64Size);
//			assert(ku64Size == leftJoinCol.mCol.i64Cols());
//
//
//			auto size0 = leftJoinCol.mCol.i64Size() * sizeof(i64);
//			auto size1 = rightJoinCol.mCol.i64Size() * sizeof(i64);
//			assert(keys[0].size() * sizeof(i64) == size0 + size1);
//			assert(keys[1].size() * sizeof(i64) == size0 + size1);
//			u8* d00 = (u8*)keys[0].data();
//			u8* d10 = (u8*)keys[1].data();
//			u8* d01 = (u8*)keys[0].data() + size0;
//			u8* d11 = (u8*)keys[1].data() + size0;
//			u8* e00 = (u8*)keys[0].data() + size0;
//			u8* e10 = (u8*)keys[1].data() + size0;
//			u8* e01 = (u8*)keys[0].data() + size0 + size1;
//			u8* e11 = (u8*)keys[1].data() + size0 + size1;
//
//			u8* s00 = (u8*)leftJoinCol.mCol[0].data();
//			u8* s10 = (u8*)leftJoinCol.mCol[1].data();
//			u8* s01 = (u8*)rightJoinCol.mCol[0].data();
//			u8* s11 = (u8*)rightJoinCol.mCol[1].data();
//
//
//			assert(e01 == (u8*)(keys[0].data() + keys[0].size()));
//			assert(e11 == (u8*)(keys[1].data() + keys[1].size()));
//
//			memcpy(d00, s00, size0);
//			memcpy(d10, s10, size0);
//			memcpy(d01, s01, size1);
//			memcpy(d11, s11, size1);
//
//			//// copy left keys and append a zero as the lsb
//			//auto k0 = keys[0].data();
//			//auto k1 = keys[1].data();
//			//auto s0 = leftJoinCol.mCol[0].data();
//			//auto s1 = leftJoinCol.mCol[1].data();
//			//for (u64 i = 0; i < leftJoinCol.mCol.rows(); ++i)
//			//{
//			//	k0[0] = s0[0] << 1;
//			//	k1[0] = s1[0] << 1;
//			//	for (u64 j = 1; j < su64Size; ++j)
//			//	{
//			//		k0[j] = (s0[j] << 1) | (u64(s0[j - 1]) >> 63);
//			//		k1[j] = (s1[j] << 1) | (u64(s1[j - 1]) >> 63);
//			//	}
//
//			//	if (su64Size != ku64Size)
//			//	{
//			//		auto j = su64Size;
//			//		k0[j] = (u64(s0[j - 1]) >> 63);
//			//		k1[j] = (u64(s1[j - 1]) >> 63);
//			//	}
//
//			//	k0 += ku64Size;
//			//	k1 += ku64Size;
//			//	s0 += su64Size;
//			//	s1 += su64Size;
//			//}
//
//			//// copy right keys and append a one as the lsb
//			//s0 = rightJoinCol.mCol[0].data();
//			//s1 = rightJoinCol.mCol[1].data();
//			//for (u64 i = 0; i < rightJoinCol.mCol.rows(); ++i)
//			//{
//			//	k0[0] = (s0[0] << 1) | 1;
//			//	k1[0] = (s1[0] << 1) | 1;
//			//	for (u64 j = 1; j < su64Size; ++j)
//			//	{
//			//		k0[j] = (s0[j] << 1) | (u64(s0[j - 1]) >> 63);
//			//		k1[j] = (s1[j] << 1) | (u64(s1[j - 1]) >> 63);
//			//	}
//
//			//	if (su64Size != ku64Size)
//			//	{
//			//		auto j = su64Size;
//			//		k0[j] = (u64(s0[j - 1]) >> 63);
//			//		k1[j] = (u64(s1[j - 1]) >> 63);
//			//	}
//
//			//	k0 += ku64Size;
//			//	k1 += ku64Size;
//			//	s0 += su64Size;
//			//	s1 += su64Size;
//			//}
//
//			return keys;
//		}
//
//		// this circuit compares two inputs for equality with the exception that
//		// the first bit is ignored.
//		oc::BetaCircuit getControlBitsCircuit(u64 bitCount)
//		{
//			oc::BetaLibrary lib;
//			return *lib.int_eq(bitCount);
//		}
//
//		sbMatrix getControlBits(sbMatrix& sKeys)
//		{
//			auto cir = getControlBitsCircuit(sKeys.bitCount());
//			BinEval bin;
//			bin.setCir(cir, sKeys.rows(), mPartyIdx, *mGen);
//
//			bin.setInput(0, sKeys);
//
//			auto n = sKeys.rows();
//			auto m = sKeys.i64Cols();
//
//			// we start on the left row and copy to the start
//			auto s0 = sKeys[0].data() + sKeys[0].size() - m;
//			auto s1 = sKeys[1].data() + sKeys[1].size() - m;
//			for (u64 i = 0; i < n; ++i)
//			{
//				memcpy(s0, s0 - m, m * sizeof(i64));
//				memcpy(s1, s1 - m, m * sizeof(i64));
//			}
//
//			// everyone invert their first share, this makes sure the 
//			// first control bit is zero, as required.
//			sKeys.mShares[0](0) = ~sKeys.mShares[0](0);
//			sKeys.mShares[1](0) = ~sKeys.mShares[1](0);
//
//			bin.setInput(1, sKeys);
//
//			bin.evaluate(mComm);
//
//			sbMatrix compareBits(n, 1);
//			bin.getOutput(0, compareBits);
//			return compareBits;
//		}
//
//		void copyColumns(
//			sbMatrix& dst,
//			u64 rowBegin,
//			span<SharedTable::ColRef> cols)
//		{
//			auto m = cols.size();
//			auto n = cols[0].mCol.rows();
//			auto d0 = (u8*)(dst[0].data() + rowBegin * dst[0].cols());
//			auto d1 = (u8*)(dst[1].data() + rowBegin * dst[1].cols());
//			auto e0 = (u8*)(dst[0].data() + dst[0].size());
//			auto e1 = (u8*)(dst[1].data() + dst[1].size());
//
//			std::vector<u64> sizes(m),
//				srcSteps64(m);
//			std::vector<std::array<i64*, 2>> srcs(m);
//			u64 rem = dst.i64Cols() * sizeof(i64);
//			for (u64 i = 0; i < m; ++i)
//			{
//				sizes[i] = oc::divCeil(cols[i].mCol.bitCount(), 8);
//				srcs[i] = { cols[i].mCol[0].data() , cols[i].mCol[1].data() };
//				rem -= sizes[i];
//				srcSteps64[i] = cols[i].mCol.i64Cols();
//			}
//
//			for (u64 i = 0; i < n; ++i)
//			{
//				for (u64 j = 0; j < m; ++j)
//				{
//					assert(d0 + sizes[j] <= e0);
//					assert(d1 + sizes[j] <= e1);
//					memcpy(d0, srcs[j][0], sizes[j]);
//					memcpy(d1, srcs[j][1], sizes[j]);
//
//
//					srcs[j][0] += srcSteps64[j];
//					srcs[j][1] += srcSteps64[j];
//					d0 += sizes[j];
//					d1 += sizes[j];
//				}
//
//				d0 += rem;
//				d1 += rem;
//			}
//		}
//
//		sbMatrix concatColumns(
//			SharedTable::ColRef leftJoinCol,
//			span<SharedTable::ColRef> selects,
//			u64 numDummies)
//		{
//			u64 m = selects.size();
//			u64 n0 = leftJoinCol.mCol.rows();
//			u64 leftSizeBytes = 0;
//
//			std::vector<SharedTable::ColRef> left, right;
//
//			for (u64 i = 0; i < m; ++i)
//			{
//				auto bytes = oc::divCeil(selects[i].mCol.bitCount(), 8);
//				if (&leftJoinCol.mTable == &selects[i].mTable)
//				{
//					assert(selects[i].mCol.rows() == n0);
//					left.emplace_back(selects[i]);
//					leftSizeBytes += bytes;
//				}
//				else
//				{
//					//assert(&leftJoinCol.mTable == &selects[i].mTable);
//					//assert(selects[i].mCol.rows() == n1);
//					//right.emplace_back(selects[i]);
//					//rightSizeBytes += bytes;
//				}
//			}
//			sbMatrix ret(n0 + numDummies, leftSizeBytes * 8);
//			copyColumns(ret, 0, left);
//			return ret;
//		}
//
//		SharedTable getOutput(
//			sbMatrix& data,
//			oc::MatrixView<i64> revealBits,
//			span<SharedTable::ColRef> selects,
//			SharedTable::ColRef& left)
//		{
//			throw RTE_LOC;
//			//u64 m = selects.size();
//			//u64 inRows = data.rows();
//			//u64 outRows = data.n1;
//			//u64 outSizeBytes = 0;
//			//std::vector<u64> sizes(m), sSteps(m), dSteps(m);
//			//std::vector<std::array<i64*, 2>> dsts(m), srcs(m);
//			//assert(revealBits.size() == inRows);
//
//			//SharedTable out;
//			//out.mColumns.resize(selects.size());
//
//			//u64 leftOffset = 0;
//			//u64 rightOffset = 0;
//			//for (u64 i = 0; i < m; ++i)
//			//{
//			//	sizes[i] = oc::divCeil(selects[i].mCol.bitCount(), 8);
//			//	out[i].mCol.resize(outRows, selects[i].mCol.bitCount());
//			//	dsts[i] = { out[i].mCol[0].data(), out[i].mCol[1].data() };
//			//	outSizeBytes += sizes[i];
//			//	dSteps[i] = out[i].mCol.i64Cols();
//
//			//	if (&left.mTable == &selects[i].mTable)
//			//	{
//			//		srcs[i][0] = (i64*)(((u8*)data[0].data()) + leftOffset);
//			//		srcs[i][1] = (i64*)(((u8*)data[1].data()) + leftOffset);
//			//		leftOffset += sizes[i];
//			//		sSteps[i] = data.mLeft[0].cols();
//			//	}
//			//	else
//			//	{
//			//		srcs[i][0] = (i64*)(((u8*)data.mRight[0].data()) + rightOffset);
//			//		srcs[i][1] = (i64*)(((u8*)data.mRight[1].data()) + rightOffset);
//			//		rightOffset += sizes[i];
//			//	}
//
//			//}
//			//assert(oc::roundUpTo(data.mLeft.bitCount(), 8) == leftOffset);
//			//assert(oc::roundUpTo(data.mRight.bitCount(), 8) == rightOffset);
//
//			//for (u64 i = 0; i < inRows; ++i)
//			//{
//			//	if (revealBits(i) & 1)
//			//	{
//			//		for (u64 j = 0; j < m; ++j)
//			//		{
//			//			memcpy(dsts[j][0], srcs[j][0], sizes[j]);
//			//			memcpy(dsts[j][1], srcs[j][1], sizes[j]);
//
//			//			srcs[j][0] += sSteps[j];
//			//			srcs[j][1] += sSteps[j];
//			//			dsts[j][0] += dSteps[j];
//			//			dsts[j][1] += dSteps[j];
//			//		}
//			//	}
//			//}
//			//for (u64 i = 0; i < m; ++i)
//			//{
//			//	assert(dsts[i][0] == out[i].mCol[0].data());
//			//	assert(dsts[i][1] == out[i].mCol[1].data());
//			//}
//
//		}
//
//		VectorPerm sortKeys(sbMatrix& keys)
//		{
//			VectorPerm sPerm;
//			ChikkpSort sort(mPartyIdx);
//			sort.genPerm(keys, sPerm, *mGen, mComm);
//
//			return sPerm;
//		}
//
//		// leftJoinCol should be unique
//		SharedTable join(
//			SharedTable::ColRef leftJoinCol,
//			SharedTable::ColRef rightJoinCol,
//			std::vector<SharedTable::ColRef> selects)
//		{
//			assert(mGen);
//			setTimePoint("start");
//
//			auto keys = loadKeys(leftJoinCol, rightJoinCol);
//			setTimePoint("load");
//
//			VectorPerm sPerm = sortKeys(keys);
//			setTimePoint("sort");
//
//			auto controlBits = getControlBits(keys);
//			keys = {};
//			setTimePoint("control");
//
//			auto data = concatColumns(leftJoinCol, selects, rightJoinCol.mTable.rows());
//			setTimePoint("concat");
//
//			sbMatrix temp;
//			sPerm.applyInv(data, temp, *mGen, mComm);
//			std::swap(data, temp);
//			setTimePoint("applyInv-sort");
//
//			DuplicationTree dt;
//			dt.apply(data, controlBits, mPartyIdx, mComm, *mGen, temp);
//			std::swap(data, temp);
//			setTimePoint("duplicate");
//
//			sPerm.apply(data, temp, *mGen, mComm);
//			std::swap(data, temp);
//			setTimePoint("apply-sort");
//
//			return {};// getOutput(data, selects, leftJoinCol);
//		}
//
//
//	};
//
//}