#pragma once

#include "SharedPerm.h"
#include "cryptoTools/Circuit/BetaLibrary.h"
#include "cryptoTools/Common/Log.h"
//#include "BinEval.h"
//#include "aby3/sh3/Sh3Converter.h"
#include "Defines.h"
#include "coproto/Socket/Socket.h"
#include "OleGenerator.h"

namespace secJoin
{
	inline void unpack(span<const u8> in, u64 bitCount, span<u32> out)
	{
		auto n = oc::divCeil(bitCount, 8);
		if (out.size() * n != in.size())
			throw RTE_LOC;

		if (n == sizeof(u32))
			memcpy(out.data(), in.data(), in.size());
		else
		{
			for (u64 j = 0; j < out.size(); ++j)
				out[j] = *(u32*)&in[j * n];
		}

	}
	inline void pack(span<const u32> in, u64 bitCount, span<u8> out)
	{
		auto n = oc::divCeil(bitCount, 8);
		if (in.size() * n != out.size())
			throw RTE_LOC;


		if (n == sizeof(u32))
			memcpy(out.data(), in.data(), out.size());
		else
		{
			auto s = in.data();
			auto iter = out.begin();
			for (u64 j = 0; j < in.size(); ++j)
			{
				std::copy((u8 const*)s, (u8 const* )s + n, iter);
				iter += n;
				++s;
			}
		}
	}

	// convert each bit of the binary secret sharing `in`
	// to integer Z_{2^outBitCount} arithmetic sharings.
	// Each row of `in` should have `inBitCount` bits.
	// out will therefore have dimension `in.rows()` rows 
	// and `inBitCount` columns.
	inline macoro::task<> bitInjection(
		u64 inBitCount,
		const oc::Matrix<u8>& in, 
		u64 outBitCount,
		oc::Matrix<u32>& out, 
		OleGenerator& gen,
		coproto::Socket& sock)
	{
		MC_BEGIN(macoro::task<>, inBitCount ,&in, outBitCount, &out, &sock, &gen,
			in2 = oc::Matrix<u8>{},
			ec = macoro::result<void>{},
			recvReq = Request<OtRecv>{},
			sendReq = Request<OtSend>{},
			recvs = std::vector<OtRecv>{},
			send = OtSend{},
			i = u64{ 0 },
			k = u64{ 0 },
			m = u64{ 0 },
			diff = oc::BitVector{},
			buff = oc::AlignedUnVector<u8>{},
			updates = oc::AlignedUnVector<u32>{},
			mask = u32{}
			);

		out.resize(in.rows(), inBitCount);
		mask = outBitCount == 32 ? -1 : ((1 << outBitCount) - 1);

		if (gen.mRole == OleGenerator::Role::Receiver)
		{
			MC_AWAIT_SET(recvReq, gen.otRecvRequest(in.rows() * inBitCount));

			while (i < out.size())
			{
				recvs.emplace_back();
				MC_AWAIT_SET(recvs.back(), recvReq.get());

				m = std::min<u64>(recvs.back().size(), out.size() - i);
				recvs.back().mChoice.resize(m);
				recvs.back().mMsg.resize(m);

				diff.reserve(m);
				for(u64 j = 0; j < m; )
				{
					auto row = i / inBitCount;
					auto off = i % inBitCount;
					auto rem = std::min<u64>(m-j, inBitCount - off);

					diff.append((u8*)&in(row, 0), rem, off);

					i += rem;
					j += rem;
				}

				diff ^= recvs.back().mChoice;
				recvs.back().mChoice ^= diff;
				MC_AWAIT(sock.send(std::move(diff)));
			}

			i = 0; k = 0;
			while (i < out.size())
			{
				m = recvs[k].size();
				buff.resize(m * oc::divCeil(outBitCount, 8));
				MC_AWAIT(sock.recv(buff));

				updates.resize(m);
				unpack(buff, outBitCount, updates);

				for (u64 j = 0; j < m; ++j, ++i)
				{
					//recvs[k].mMsg[j].set<u32>(0, 0);

					if (recvs[k].mChoice[j])
						out(i) = (recvs[k].mMsg[j].get<u32>(0) + updates[j]) & mask;
					else
						out(i) = recvs[k].mMsg[j].get<u32>(0) & mask;
				}

				++k;
			}
		}
		else
		{

			MC_AWAIT_SET(sendReq, gen.otSendRequest(in.rows() * inBitCount));

			while (i < out.size())
			{
				MC_AWAIT_SET(send, sendReq.get());

				m = std::min<u64>(send.size(), out.size() - i);
				diff.resize(m);
				MC_AWAIT(sock.recv(diff));

				updates.resize(m);
				for (u64 j = 0; j < m; ++j, ++i)
				{
					auto row = i / inBitCount;
					auto off = i % inBitCount;

					auto y = (u8)*oc::BitIterator((u8*)&in(row, 0), off);
					auto b = (u8)diff[j];
					auto m0 = send.mMsg[j][b];
					auto m1 = send.mMsg[j][b ^ 1];

					auto v0 = m0.get<u32>(0);
					auto v1 = v0 + (-2 * y + 1);
					out(i) = (-v0 + y) & mask;
					updates[j] = (v1 - m1.get<u32>(0)) & mask;
				}

				buff.resize(m * oc::divCeil(outBitCount, 8));
				pack(updates, outBitCount, buff);

				MC_AWAIT(sock.send(std::move(buff)));
			}
		}
		MC_END();
	}

	class RadixSort
	{
	public:
		u64 mPartyIdx = -1;

		using Matrix32 = oc::Matrix<u32>;
		using BinMatrix = oc::Matrix<u8>;

		RadixSort() = default;
		RadixSort(RadixSort&&) = default;

		RadixSort(u64 partyIdx) {
			init(partyIdx);
		}

		void init(u64 partyIdx)
		{
			mPartyIdx = partyIdx;
		}

		// for each i, compute the Hadamard (component-wise) product between the columns of D[i]
		// and write the result to f[i]. i.e.
		// 
		//   f[i] = D[i].col(0) * ... * D[i].col(n-1) 
		// 
		// where * is component-wise. f[i] will be a column vector.
		macoro::task<> hadamardOfColumns(
			std::vector<Matrix32>& D,
			Matrix32& f,
			OleGenerator& gen, 
			coproto::Socket& comm)
		{
			MC_BEGIN(macoro::task<>, this, &D, &f, &gen, &comm);
			//u64 numSets = D.size();
			//u64 numCols = D[0].cols();
			//u64 numRows = D[0].rows();

			//if (numCols == 1)
			//{
			//	f = std::move(D[0]);
			//	return;
			//}

			//f.resize(numSets, numRows);
			//// f = D.col(0)
			//for (u64 i = 0; i < numSets; ++i)
			//{
			//	for(u64 j = 0; j < numRows; ++j)
			//		f(j,i) = D[i](j,0);
			//}

			//// we could compute this in a binary tree to reduce depth. But probably doesn't
			//// matter since numCols = 3 is the expected number of loops.
			//for (u64 j = 1; j < numCols; ++j)
			//{
			//	// component-wise product over the columns
			//	//    f = f * D[j] 
			//	for (u64 i = 0; i < numSets; ++i)
			//	{

			//		//auto& ff0 = f.col(i);
			//		auto& dd = D[i];
			//		std::vector<i64> buff(numRows);
			//		for (u64 k = 0; k < numRows; ++k)
			//		{
			//			ff0(k)
			//				= ff0(k) * dd[0](k, j)
			//				+ ff0(k) * dd[1](k, j)
			//				+ ff1(k) * dd[0](k, j)
			//				+ gen.getShare();

			//			buff[k] = ff0(k);
			//		}

			//		//comm.mNext.asyncSend(std::move(buff));
			//	}

			//	//std::vector<i64> buff(numRows);
			//	//for (u64 i = 0; i < numSets; ++i)
			//	//{
			//	//	auto ff1 = f[1].col(i);
			//	//	comm.mPrev.recv(buff.data(), buff.size());
			//	//	for (u64 k = 0; k < numRows; ++k)
			//	//	{
			//	//		ff1(k) = buff[k];
			//	//	}
			//	//}
			//}

			MC_END();
		}

		macoro::task<> checkHadamardSum(
			Matrix32& f,
			Matrix32& s,
			Matrix32& dst,
			coproto::Socket& comm)
		{

			MC_BEGIN(macoro::task<>, this, &f, &s, &dst, &comm);
			//Sh3Encryptor enc;
			//auto ff = enc.revealAll(comm, f);
			//auto ss = enc.revealAll(comm, s);
			//auto dd = enc.revealAll(comm, dst);

			//assert(dd.cols() == 1);
			//i64Matrix exp(dd.rows(), dd.cols());
			//for (u64 i = 0; i < dd.rows(); ++i)
			//{
			//	exp(i) = 0;
			//	for (u64 j = 0; j < ff.cols(); ++j)
			//		exp(i) += ff(i, j) * ss(i, j);
			//}

			//if (exp != dd)
			//	throw RTE_LOC;
			MC_END();
		}

		// compute dst = sum_i f.col(i) * s.col(i) where * 
		// is the hadamard (component-wise) product. 
		macoro::task<> hadamardSum(
			Matrix32& f,
			Matrix32& s,
			Perm& dst,
			OleGenerator& gen,
			coproto::Socket& comm)
		{
			MC_BEGIN(macoro::task<>, this, &f, &s, &dst,&gen, &comm);
			//dst.resize(s.rows(), 1);

			//for (u64 k = 0; k < dst.size(); ++k)
			//	dst[0](k) = gen.getShare();

			//auto nc = f.cols();

			//for (u64 k = 0; k < dst.size(); ++k)
			//{
			//	for (u64 i = 0; i < nc; ++i)
			//	{

			//		dst[0](k) +=
			//			f[0](k, i) * s[0](k, i) +
			//			f[0](k, i) * s[1](k, i) +
			//			f[1](k, i) * s[0](k, i) +
			//			gen.getShare();
			//	}
			//}

			//comm.mNext.asyncSendCopy(dst[0].data(), dst[0].size());
			//comm.mPrev.recv(dst[1].data(), dst[1].size());

			MC_END();
		}

		// from each row, we generate a series of sharing flag bits
		// f.col(0) ,..., f.col(n) where f.col(i) is one if k=i.
		// Computes the same function as genValMask2 but is less efficient.
		macoro::task<> genValMasks(
			u64 keyBitCount,
			BinMatrix& kBin,
			Matrix32& f,
			OleGenerator& gen,
			coproto::Socket& comm)
		{
			assert(keyBitCount <= kBin.cols() * 8);
			MC_BEGIN(macoro::task<>, this, keyBitCount, &kBin, &f, &gen, &comm);
			//Matrix32 k(kBin.rows(), keyBitCount);

			//Sh3Converter conv;
			//conv.init(rt, gen);
			//conv.bitInjection(rt, kBin, k, true).get();

			//u64 m = k.rows();
			//u64 L = k.cols();
			//u64 L2 = 1ull << L;
			//std::vector<si64Matrix> DD(L2);// (m, L);

			//for (u64 j = 0; j < L2; ++j)
			//{
			//	std::vector<i64> B(L);
			//	for (u64 i = 0; i < L; ++i)
			//		B[i] = j & (1 << i);

			//	auto& D = DD[j];
			//	D.resize(m, L);

			//	for (u64 kk = 0; kk < L; ++kk)
			//	{
			//		if (B[kk])
			//		{
			//			// D^{kk} = k^{kk}
			//			D[0].col(kk) = k[0].col(kk);
			//			D[1].col(kk) = k[1].col(kk);
			//		}
			//		else
			//		{
			//			// D^{kk} = 1 - k^{kk}
			//			D[0].col(kk) = -k[0].col(kk);
			//			D[1].col(kk) = -k[1].col(kk);

			//			if (mPartyIdx != 2)
			//			{
			//				auto& DD0 = D[mPartyIdx];
			//				for (u64 q = 0; q < m; ++q)
			//				{
			//					DD0(q, kk) += 1;
			//				}
			//			}
			//		}
			//	}
			//}

			//// f_i = \prod_t  D_{i,t}
			//// 
			//// f_i[j] = 1 if k[j] = i
			//hadamardOfColumns(DD, f, gen, comm);

			MC_END();
		}



		macoro::task<> checkGenValMasks(
			u64 bitCount,
			const BinMatrix& k,
			BinMatrix& f,
			coproto::Socket& comm,
			bool check)
		{

			MC_BEGIN(macoro::task<>, this, &k, &f, &comm, check, 
				n = u64{},
				L = bitCount,
				kk = BinMatrix{},
				ff = BinMatrix{}
			);
			n = k.rows();
			kk.resize(k.rows(), k.cols());
			ff.resize(f.rows(), f.cols());
			MC_AWAIT(comm.send(coproto::copy(k)));
			MC_AWAIT(comm.send(coproto::copy(f)));
			MC_AWAIT(comm.recv(kk));
			MC_AWAIT(comm.recv(ff));

			for (u64 i = 0; i < kk.size(); ++i)
				kk(i) ^= k(i);
			for (u64 i = 0; i < ff.size(); ++i)
				ff(i) ^= f(i);

			if (!check)
			{
				ff.setZero();
			}

			for (u64 j = 0; j < n; ++j)
			{
				auto kj = (u64)kk(j);
				auto iter = oc::BitIterator((u8*)&(ff(j, 0)), 0);

				auto print = [&]() {
					std::lock_guard<std::mutex> ll(oc::gIoStreamMtx);
					std::cout << "exp " << j << " ~ ";
					for (u64 ii = 0; ii < (1ull << L); ++ii)
						std::cout << ((kj == ii) ? 1 : 0) << " ";

					std::cout << "\nact " << j << " ~ ";
					for (u64 ii = 0; ii < (1ull << L); ++ii)
						std::cout << *oc::BitIterator((u8*)&(ff(j, 0)), ii) << " ";
					std::cout << "\n";
				};
				print();

				for (u64 i = 0; i < (1ull << L); ++i, ++iter)
				{
					auto exp = (kj == i) ? 1 : 0;

					//auto iter = oc::BitIterator((u8*)&(ff(j, 0)), i);
					if (!check)
					{
						*iter = exp;
					}
					else
					{




						u8 fji = *iter;
						if (fji != exp)
						{
							throw RTE_LOC;
						}
					}
				}
			}

			//if (!check)
			//{
			//	Sh3Encryptor enc;
			//	enc.init(mPartyIdx, oc::block(0, mPartyIdx), oc::block(0, (mPartyIdx + 1) % 3));
			//	if (mPartyIdx == 0)
			//	{
			//		enc.localBinMatrix(comm, ff, f);
			//	}
			//	else
			//	{
			//		enc.remoteBinMatrix(comm, f);
			//	}
			//}
			MC_END();
		}

		macoro::task<> checkGenValMasks(
			const BinMatrix& k,
			Matrix32& f,
			coproto::Socket& comm)
		{
			MC_BEGIN(macoro::task<>, this, &k, &f, &comm);
			//auto n = k.rows();
			//auto L = k.bitCount();
			//Sh3Encryptor enc;
			//auto kk = enc.revealAll(comm, k);
			//auto ff = enc.revealAll(comm, f);

			//if ((u64)ff.rows() != n)
			//	throw RTE_LOC;
			//if ((u64)ff.cols() != (1ull << L))
			//	throw RTE_LOC;

			//for (u64 i = 0; i < (1ull << L); ++i)
			//{


			//	for (u64 j = 0; j < n; ++j)
			//	{
			//		auto kj = (u64)kk(j);
			//		auto fji = ff(j, i);
			//		if (kj == i)
			//		{
			//			if (fji != 1)
			//				throw RTE_LOC;
			//		}
			//		else
			//		{
			//			if (fji != 0)
			//			{

			//				throw RTE_LOC;
			//			}
			//		}
			//	}
			//}
			MC_END();
		}

		// from each row, we generate a series of sharing flag bits
		// f.col(0) ,..., f.col(n) where f.col(i) is one if k=i.
		// Computes the same function as genValMask but is more efficient
		// due to the use a binary secret sharing.
		macoro::task<> genValMasks2(
			u64 bitCount,
			const BinMatrix& k,
			Matrix32& f,
			OleGenerator& gen,
			coproto::Socket& comm)
		{
			MC_BEGIN(macoro::task<>, this, &k, &f, &gen, &comm, bitCount,
				bits = BinMatrix{},
				eval = Gmw{},
				cir = oc::BetaCircuit{}
			);
			//Sh3Runtime rt;
			//rt.init(mPartyIdx, comm);

			bits.resize(k.rows(), oc::divCeil(1ull << bitCount, 8));

			if (bitCount == 1)
			{
				for (u64 i = 0; i < k.rows(); ++i)
				{
					assert(k(i) < 2);
					if(gen.mRole ==OleGenerator::Role::Receiver)
						bits(i) = (k(i) << 1) | (~k(i) & 1);
					else
					{
						bits(i) = (k(i) << 1) | (k(i) & 1);
					}
				}
			}
			else
			{

				if (1)
				{
					cir = indexToOneHotCircuit(bitCount);


					//eval.enableDebug(mPartyIdx, -1, comm.mPrev.getSession().addChannel(), comm.mNext.getSession().addChannel());

					eval.init(k.rows(), cir, gen);

					eval.setInput(0, k);

					MC_AWAIT(eval.run(comm));

					eval.getOutput(0, bits);

					//MC_AWAIT(checkGenValMasks(bitCount, k, bits, comm, true));

				}
				else
				{
					// work around.
					//MC_AWAIT(checkGenValMasks(k, bits, comm, false));
				}
			}
			//checkGenValMasks(k, bits, comm, true);

			//Sh3Converter conv;
			//conv.init(rt, gen);
			/*conv.*/
			MC_AWAIT(bitInjection(1ull << bitCount, bits, 32, f, gen, comm));


			//checkGenValMasks(k, f, comm);
			MC_END();
		}

		// compute a running sum. replace each element f(i,j) with the sum all previous 
		// columns f(*,1),...,f(*,j-1) plus the elements of f(0,j)+....+f(i-1,j) minus one.
		static void aggregateSum(const Matrix32& f, Matrix32& s, u64 partyIdx)
		{
			//auto L2 = f.cols();
			//auto m = f.rows();

			//auto step = f.mShares[0].cols();
			//// sum = -1
			//si64 sum = std::array<i64, 2>{ 0, 0 };
			//if (partyIdx != 2)
			//	sum[partyIdx] = -1;

			//// sum over column j.
			//for (u64 j = 0; j < L2; ++j)
			//{
			//	auto f0 = f.mShares[0].data() + j;
			//	auto f1 = f.mShares[1].data() + j;
			//	auto s0 = s.mShares[0].data() + j;
			//	auto s1 = s.mShares[1].data() + j;
			//	for (u64 i = 0; i < m; ++i)
			//	{
			//		//sum.mData[0] += f.mShares[0](i, j);
			//		//sum.mData[1] += f.mShares[1](i, j);
			//		sum.mData[0] += *f0;
			//		sum.mData[1] += *f1;

			//		//s.mShares[0](i, j) = sum.mData[0];
			//		//s.mShares[1](i, j) = sum.mData[1];
			//		*s0 = sum.mData[0];
			//		*s1 = sum.mData[1];

			//		//assert(s0 == &s.mShares[0](i, j));
			//		//assert(s1 == &s.mShares[1](i, j));

			//		f0 += step;
			//		f1 += step;
			//		s0 += step;
			//		s1 += step;
			//	}
			//}
		}


		// compute a running sum. replace each element f(i,j) with the sum all previous 
		// columns f(*,1),...,f(*,j-1) plus the elements of f(0,j)+....+f(i-1,j).
		static void aggregateSum2(const Matrix32& f, Matrix32& s, u64 partyIdx)
		{

			//auto L2 = f.cols();

			//auto main = L2 / 8 * 8;
			//auto m = f.rows();

			//auto step = f.mShares[0].cols();
			//// sum = -1

			//std::array<std::vector<i64>, 2> partialSum;
			//partialSum[0].resize(L2);
			//partialSum[1].resize(L2);

			//// (L2);
			////si64 partialSum = std::array<i64, 2>{ 0, 0 };
			//if (partyIdx != 2)
			//	partialSum[partyIdx][0] = -1;

			//for (u64 i = 0; i < m; ++i)
			//{
			//	u64 j = 0;
			//	auto fi0 = (block * __restrict) & f.mShares[0](i, 0);
			//	auto fi1 = (block * __restrict) & f.mShares[1](i, 0);
			//	auto si0 = (block * __restrict) & s.mShares[0](i, 0);
			//	auto si1 = (block * __restrict) & s.mShares[1](i, 0);
			//	auto p0 = (block * __restrict) & partialSum[0][0];
			//	auto p1 = (block * __restrict) & partialSum[1][0];
			//	for (; j < main; j += 8)
			//	{

			//		p0[0] = p0[0] + fi0[0];
			//		p0[1] = p0[1] + fi0[1];
			//		p0[2] = p0[2] + fi0[2];
			//		p0[3] = p0[3] + fi0[3];
			//		//p0[4] = p0[4] + fi0[4];
			//		//p0[5] = p0[5] + fi0[5];
			//		//p0[6] = p0[6] + fi0[6];
			//		//p0[7] = p0[7] + fi0[7];

			//		p1[0] = p1[0] + fi1[0];
			//		p1[1] = p1[1] + fi1[1];
			//		p1[2] = p1[2] + fi1[2];
			//		p1[3] = p1[3] + fi1[3];
			//		//p1[4] = p1[4] + fi1[4];
			//		//p1[5] = p1[5] + fi1[5];
			//		//p1[6] = p1[6] + fi1[6];
			//		//p1[7] = p1[7] + fi1[7];

			//		si0[0] = p0[0];
			//		si0[1] = p0[1];
			//		si0[2] = p0[2];
			//		si0[3] = p0[3];
			//		//si0[4] = p0[4];
			//		//si0[5] = p0[5];
			//		//si0[6] = p0[6];
			//		//si0[7] = p0[7];

			//		si1[0] = p1[0];
			//		si1[1] = p1[1];
			//		si1[2] = p1[2];
			//		si1[3] = p1[3];
			//		//si1[4] = p1[4];
			//		//si1[5] = p1[5];
			//		//si1[6] = p1[6];
			//		//si1[7] = p1[7];

			//		p0 += 4;
			//		p1 += 4;
			//		si0 += 4;
			//		si1 += 4;
			//		fi0 += 4;
			//		fi1 += 4;
			//	}


			//	for (; j < L2; ++j)
			//	{
			//		partialSum[0][j] += f.mShares[0](i, j);
			//		partialSum[1][j] += f.mShares[1](i, j);

			//		s.mShares[0](i, j) = partialSum[0][j];
			//		s.mShares[1](i, j) = partialSum[1][j];
			//	}
			//}

			//auto prev = std::array<i64, 2>{ 0, 0 };;
			//for (u64 j = 0; j < L2; ++j)
			//{
			//	auto s0 = partialSum[0][j];
			//	auto s1 = partialSum[1][j];
			//	partialSum[0][j] = prev[0];
			//	partialSum[1][j] = prev[1];
			//	prev[0] = prev[0] + s0;
			//	prev[1] = prev[1] + s1;
			//}

			//for (u64 i = 0; i < m; ++i)
			//{
			//	auto si0 = (block * __restrict) & s.mShares[0](i, 0);
			//	auto si1 = (block * __restrict) & s.mShares[1](i, 0);
			//	auto p0 = (block * __restrict) & partialSum[0][0];
			//	auto p1 = (block * __restrict) & partialSum[1][0];
			//	u64 j = 0;
			//	for (; j < main; j += 8)
			//	{
			//		si0[0] = si0[0] + p0[0];
			//		si0[1] = si0[1] + p0[1];
			//		si0[2] = si0[2] + p0[2];
			//		si0[3] = si0[3] + p0[3];
			//		//si0[4] = si0[4] + p0[4];
			//		//si0[5] = si0[5] + p0[5];
			//		//si0[6] = si0[6] + p0[6];
			//		//si0[7] = si0[7] + p0[7];

			//		si1[0] = si1[0] + p1[0];
			//		si1[1] = si1[1] + p1[1];
			//		si1[2] = si1[2] + p1[2];
			//		si1[3] = si1[3] + p1[3];
			//		//si1[4] = si1[4] + p1[4];
			//		//si1[5] = si1[5] + p1[5];
			//		//si1[6] = si1[6] + p1[6];
			//		//si1[7] = si1[7] + p1[7];

			//		p0 += 4;
			//		p1 += 4;
			//		si0 += 4;
			//		si1 += 4;
			//	}
			//	for (; j < L2; ++j)
			//	{
			//		s.mShares[0](i, j) += partialSum[0][j];
			//		s.mShares[1](i, j) += partialSum[1][j];
			//	}
			//}

		}


		// Generate a permutation dst which will be the inverse of the
		// permutation that permutes the keys k into sorted order. 
		macoro::task<> genBitPerm(
			u64 keyBitCount,
			BinMatrix& k, 
			SharedPerm& dst, 
			OleGenerator& gen, 
			coproto::Socket& comm)
		{
			MC_BEGIN(macoro::task<>, this, keyBitCount, &k, &dst, &gen, &comm,
				m = u64{},
				L = u64{},
				L2 = u64{},
				f = Matrix32{},
				s = Matrix32{}
				);

			if (keyBitCount > k.cols() * 8)
				throw RTE_LOC;

			m = k.rows();
			L = keyBitCount;
			L2 = 1ull << L;
			dst.init(k.rows(), mPartyIdx, gen.mPrng);

			f.resize(m, L2);
			s.resize(m, L2);

		 	MC_AWAIT(genValMasks2(keyBitCount, k, f, gen, comm));

			aggregateSum2(f, s, mPartyIdx);

			MC_AWAIT(hadamardSum(f, s, dst.mPerm, gen, comm));
			//checkHadamardSum(f, s, dst.mShare, comm);
			
			MC_END();
		}


		// get 'size' columns of k starting at column index 'begin'
		// Assumes 'size <= 8'. 
		static BinMatrix extract(u64 begin, u64 size, const BinMatrix& k)
		{
			// we assume at most a byte size.
			if (size > 32)
				throw RTE_LOC;
			size = std::min<u64>(size, k.cols() * 8 - begin);


			auto byteIdx = begin / 8;
			auto shift = begin % 8;
			auto step = k.cols();
			u64 mask = (size % 64) ? (1ull << size) - 1 : ~0ull;
			BinMatrix sk(k.rows(), oc::divCeil(size, 8));

			auto n = k.rows();
			auto s0 = (u64*)(k.data() + byteIdx);

			TODO("mem bug at i=n-1, read over the end of the buffer");
			for (u64 i = 0; i < n; ++i)
			{
				sk(i) = (*s0 >> shift) & mask;
				s0 += step;
			}

			return sk;
		}


		u64 mL = 2;
		// generate the (inverse) permutation that sorts the keys k.
		macoro::task<> genPerm(
			u64 keyBitCount,
			const BinMatrix& k,
			SharedPerm& dst,
			OleGenerator& gen,
			coproto::Socket& comm)
		{

			MC_BEGIN(macoro::task<>, this, keyBitCount, &k, &dst, &gen, &comm,
				ll = u64{},
				kIdx = u64{},
				L2 = u64{},
				sk =  BinMatrix{},
				ssk = BinMatrix{},
				sigma2 = SharedPerm{},
				rho = SharedPerm{},
				i = u64{}
				
			);

			if (keyBitCount > k.cols() * 8)
				throw RTE_LOC;

			ll = oc::divCeil(keyBitCount, mL);
			kIdx = 0;
			sk = extract(kIdx, mL, k); kIdx += mL;

			// generate the sorting permutation for the
			// first L bits of the key.
			MC_AWAIT(genBitPerm(mL, sk, dst, gen, comm));
			//dst.validate(comm);

			for (i = 1; i < ll; ++i)
			{
				// get the next L bits of the key.
				sk = extract(kIdx, mL, k); kIdx += mL;

				// apply the partial sort that we have so far 
				// to the next L bits of the key.
				MC_AWAIT(dst.apply(sk, ssk, comm, gen, true));

				// generate the sorting permutation for the
				// next L bits of the key.
				MC_AWAIT(genBitPerm(mL, ssk, rho, gen, comm));

				// compose the current partial sort with
				// the permutation that sorts the next L bits
				MC_AWAIT(rho.compose(dst, sigma2, comm, gen));
				std::swap(dst, sigma2);
				//dst.validate(comm);
			}

			MC_END();
		}



		//// sort `src` based on the key `k`. The sorted values are written to `dst`
		//// and the sorting (inverse) permutation is written to `dstPerm`.
		//BinMatrix sort(
		//	u64 keyBitCount,
		//	const BinMatrix& k,
		//	const BinMatrix& src,
		//	OleGenerator& gen,
		//	coproto::Socket& comm)
		//{

		//	if (k.rows() != src.rows())
		//		throw RTE_LOC;

		//	BinMatrix dst;
		//	SharedPerm dstPerm;

		//	// generate the sorting permutation.
		//	genPerm(k, dstPerm, gen, comm);

		//	// apply the permutation.
		//	dstPerm.apply(src, dst, gen, comm, , true);

		//	return dst;
		//}

		//// sort `src` based on the key `k`. The sorted values are written to `dst`
		//// and the sorting (inverse) permutation is written to `dstPerm`.
		//void sort(
		//	const BinMatrix& k,
		//	const BinMatrix& src,
		//	BinMatrix& dst,
		//	SharedPerm& dstPerm,
		//	OleGenerator& gen,
		//	coproto::Socket& comm)
		//{
		//	if (k.rows() != src.rows())
		//		throw RTE_LOC;

		//	// generate the sorting permutation.
		//	genPerm(k, dstPerm, gen, comm);

		//	// apply the permutation.
		//	dstPerm.apply(src, dst, gen, comm, true);
		//}

		// this circuit takes as input a index i\in {0,1}^L and outputs
		// a binary vector o\in {0,1}^{2^L} where is one at index i.
		static oc::BetaCircuit indexToOneHotCircuit(u64 L)
		{
			oc::BetaCircuit indexToOneHot;
			//bool debug = false;
			//auto str = [](auto x) -> std::string {return std::to_string(x); };

			u64 numLeaves = 1ull << L;
			u64 nodesPerTree = numLeaves - 1;

			// input comparison bits, the bit is the lsb of each inputAlignment bits.
			oc::BetaBundle idx(L);

			// Flag bit for each node. The bit is set to 1 if that node is active.
			// Therefore each level of the tree is like a one-hot vector.
			oc::BetaBundle nodes(nodesPerTree);
			oc::BetaBundle leafNodes(numLeaves);

			indexToOneHot.addInputBundle(idx);

			// We output a bit for each leaf which is one iff its the active leaf.
			indexToOneHot.addOutputBundle(leafNodes);

			indexToOneHot.addTempWireBundle(nodes);

			// the root node is always active.
			indexToOneHot.addConst(nodes[0], 1);

			// the combined nodes.
			nodes.mWires.insert(nodes.mWires.end(), leafNodes.mWires.begin(), leafNodes.mWires.end());

			for (u64 i = 0; i < nodesPerTree; ++i)
			{
				// the active wire for the parent (current) node.
				auto prntWire = nodes[i];

				// child indexes.
				auto child0 = (i + 1) * 2 - 1;
				auto child1 = (i + 1) * 2;

				// Get the active wire for each child.
				auto chld0Wire = nodes[child0];
				auto chld1Wire = nodes[child1];


				// get the comparison bit for the current node. (each bit is the lsb of an inputAlignment sequence).
				auto cmpWire = idx[idx.size() - 1 - oc::log2floor(i + 1)];

				// the right child is active if the cmp bit is 1 and the parent is active.
				indexToOneHot.addGate(prntWire, cmpWire, oc::GateType::And, chld1Wire);

				// the left child is active if the cmp bit is 0 and the parent is active. This
				// can be implemented with XOR'ing the parent and the right child.
				indexToOneHot.addGate(prntWire, chld1Wire, oc::GateType::Xor, chld0Wire);
			}

			return indexToOneHot;
		}



	};

}