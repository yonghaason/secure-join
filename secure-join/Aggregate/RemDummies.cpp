#include "RemDummies.h"

namespace secJoin {

	void RemDummies::init(u64 rows, u64 bytesPerEntry, CorGenerator& ole, bool cachePerm)
	{
		mPartyIdx = ole.partyIdx();
		mCachePerm = cachePerm;
		mPerm.init(mPartyIdx, rows, bytesPerEntry, ole);
	}


	macoro::task<> RemDummies::applyRandPerm(
		BinMatrix& data,
		BinMatrix& out,
		PRNG& prng,
		coproto::Socket& sock)
	{
		auto perm = ComposedPerm{};

		mPerm.preprocess();

		// mPerm by default generates a random perm
		co_await mPerm.generate(sock, prng, data.rows(), perm);

		out.resize(data.rows(), data.bitsPerEntry());

		// Appyling the random permutation
		co_await perm.apply<u8>(mPermOp, data, out, sock);

		// Caching the Permutation
		if (mCachePerm)
			std::swap(mPermutation, perm);

	}

	// Given the full data Matrix this function extracts the act flag byte
	// & then returns the revealed Act Flag
	macoro::task<> RemDummies::revealActFlag(
		BinMatrix& data,
		u64 actFlagOffSet,
		BinMatrix& out,
		coproto::Socket& sock)
	{
		auto actFlag = BinMatrix{};

		actFlag.resize(data.numEntries(), 1);
		for (u64 i = 0; i < data.numEntries(); i++)
			actFlag(i, 0) = data(i, actFlagOffSet);

		out.resize(actFlag.numEntries(), actFlag.bitsPerEntry());
		co_await revealActFlag(actFlag, out, sock);

	}


	// Given the ActFlag, it returns the revealed Act Flag
	macoro::task<> RemDummies::revealActFlag(
		BinMatrix& actFlag,
		BinMatrix& out,
		coproto::Socket& sock
	)
	{
		// Revealing the active flag
		if (mPartyIdx == 0)
		{
			out.resize(actFlag.numEntries(), actFlag.bitsPerEntry());
			co_await sock.recv(out.mData);
			out = reveal(out, actFlag);
			co_await sock.send(coproto::copy(out.mData));
		}
		else
		{
			co_await sock.send(coproto::copy(actFlag.mData));
			out.resize(actFlag.numEntries(), actFlag.bitsPerEntry());
			co_await sock.recv(out.mData);
		}

	}


	// Average will call this remDummies method
	macoro::task<> RemDummies::remDummies(
		BinMatrix& data,
		BinMatrix& out,
		u64 actFlagOffSet,
		coproto::Socket& sock,
		PRNG& prng)
	{
		auto temp = BinMatrix{};
		auto actFlag = BinMatrix{};
		auto nOutRows = u64{};
		auto curPtr = u64{};

		// Applying the Rand Perm
		temp.resize(data.numEntries(), data.bitsPerEntry());
		co_await applyRandPerm(data, temp, prng, sock);
		std::swap(data, temp);

		// Revealing ActFlag
		co_await revealActFlag(data, actFlagOffSet, actFlag, sock);

		// Counting the total number of active rows
		nOutRows = countActiveRows(oc::MatrixView<u8>(actFlag.data(), actFlag.size(), 1));

		out.resize(nOutRows, data.bitsPerEntry());
		curPtr = 0;
		for (u64 i = 0; i < actFlag.numEntries(); i++)
		{
			if (actFlag(i, 0) == 1)
			{
				copyBytes(out[curPtr], data[i]);
				curPtr++;
			}

			if (curPtr >= nOutRows)
				break;
		}
	}


	macoro::task<> RemDummies::remDummies(
		Table& in,
		Table& out,
		coproto::Socket& sock,
		PRNG& prng)
	{

		auto data = BinMatrix{};
		auto temp = BinMatrix{};
		auto actFlag = BinMatrix{};
		auto actFlagOffSet = u64{};
		auto nOutRows = u64{};

		concatTable(in, data);

		// Applying the Rand Perm
		temp.resize(data.numEntries(), data.bitsPerEntry());
		co_await applyRandPerm(data, temp, prng, sock);
		std::swap(data, temp);

		// Calculating ActFlag Offset
		for (u64 i = 0; i < in.cols(); i++)
		{
			auto bytes = in.mColumns[i].getByteCount();
			actFlagOffSet += bytes;
		}

		// Revealing ActFlag
		co_await revealActFlag(data, actFlagOffSet, actFlag, sock);

		// Counting the total number of active rows
		nOutRows = countActiveRows(oc::MatrixView<u8>(actFlag.data(), actFlag.size(), 1));

		// Populating the out table
		out.init(nOutRows, in.getColumnInfo());

		populateOutTable(out, actFlag, data);
	}




}