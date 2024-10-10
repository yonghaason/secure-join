#include "AltModPrf.h"
#include "AltModSimd.h"


namespace secJoin
{

	auto makeAltModWPrfB() {
		std::array<block, 128> r;
		memset(&r, 0, sizeof(r));
		PRNG prng(block(2134, 5437));
		for (u64 i = 0; i < r.size(); ++i)
		{
			//*oc::BitIterator(r[i].mData[0].data(), i) = 1;
			r[i] = prng.get();
		}
		return r;
	};
	const std::array<block, 128> AltModPrf::mB = makeAltModWPrfB();

	auto makeAltModWPrfBCode()
	{

		oc::Matrix<u8> g(128, sizeof(block)), gt(128, sizeof(block));
		g.resize(128, sizeof(block));
		for (u64 i = 0; i < 128; ++i)
			memcpy(g[i], span<const block>(&AltModPrf::mB[i], 1));
		oc::transpose(g, gt);
		F2LinearCode r;
		r.init(gt);
		return r;
	}
	const F2LinearCode AltModPrf::mBCode = makeAltModWPrfBCode();

	auto makeAltModWPrfACode() {

		F3AccPermCode r;
		r.init(AltModPrf::KeySize, AltModPrf::MidSize);
		return r;
	};
	const F3AccPermCode AltModPrf::mACode = makeAltModWPrfACode();

	auto makeAltModWPrfBExpanded()
	{
		std::array<std::array<u8, 128>, 128> r;
		for (u64 i = 0; i < AltModPrf::mB.size(); ++i)
		{
			auto iter0 = oc::BitIterator((u8*)&AltModPrf::mB[i]);
			for (u64 j = 0; j < r[i].size(); ++j)
				r[i][j] = *iter0++;
		}
		return r;
	}
	const std::array<std::array<u8, 128>, 128> AltModPrf::mBExpanded = makeAltModWPrfBExpanded();


	auto makeAltModWPrfGCode()
	{
		constexpr u64 expandInput2W = (AltModPrf::KeySize - 128) / 128;
		std::array<F2LinearCode, expandInput2W> expandInput2Code;

		oc::Matrix<u8> g(128, sizeof(block));
		PRNG prng(oc::CCBlock);
		for (auto i : stdv::iota(0ull, expandInput2W))
		{
			prng.get(g.data(), g.size());
			expandInput2Code[i].init(g);
		}
		return expandInput2Code;
	}
	const std::array<F2LinearCode, 3> AltModPrf::mGCode = makeAltModWPrfGCode();

	// input v.
	// v will have m=256 rows. It will store the i'th value in
	// bit decomposed/transposed manner. That is, the j'th bit of the i'th value is
	// stored at v[j,i] where the indexing is into the bits of v.
	//
	// The result is written to y. y[i] will store the i'th output.
	// It will *not* be in transposed format
	//
	void compressB(
		u64 begin,
		u64 n,
		oc::MatrixView<block> v,
		span<block> y
	)
	{
		//auto n = y.size();
		assert(begin % 128 == 0);

		// the begin'th v value starts at block index begin128
		auto begin128 = oc::divCeil(begin, 128);

		// the number of 128 chunks
		auto n128 = oc::divCeil(n, 128);

		// the number of 128 chunks given that there are at least 8 more.
		auto n1024 = n128 / 8 * 8;


		oc::Matrix<block> yt(128, n128);

		//auto B = AltModWPrf::mB;
		assert(begin % 128 == 0);
		// assert(n % 128 == 0);
		assert(v.rows() == AltModPrf::MidSize);
		assert(v.cols() >= begin128 + n128);
		assert(y.size() >= begin + n);

		auto vStep = v.cols();
		auto ytIter = yt.data();
		auto ytstep = yt.cols();
		auto vSize = n128 * sizeof(block);

		for (u64 i = 0; i < 128; ++i)
		{
			//while (AltModWPrf::mBExpanded[i][j] == 0)
			//    ++j;

			auto vIter = v.data() + begin128 + i * vStep;
			assert(yt[i].data() == ytIter);
			assert(v[i].subspan(begin128).data() == vIter);
			memcpy(ytIter, vIter, vSize);
			//vIter += vStep;
			//++j;

			//memcpy(yt[i], v[j++].subspan(begin128, n128));
			u64 j = 128;
			vIter = v.data() + begin128 + j * vStep;
			while (j < 256)
			{
				if (AltModPrf::mBExpanded[i][j - 128])
				{
					assert(yt[i].data() == ytIter);
					assert(vIter == v[j].data() + begin128);
					block* __restrict yti = ytIter;
					block* __restrict vj = vIter;
					u64 k = 0;

					for (; k < n1024; k += 8)
					{
						yti[k + 0] = yti[k + 0] ^ vj[k + 0];
						yti[k + 1] = yti[k + 1] ^ vj[k + 1];
						yti[k + 2] = yti[k + 2] ^ vj[k + 2];
						yti[k + 3] = yti[k + 3] ^ vj[k + 3];
						yti[k + 4] = yti[k + 4] ^ vj[k + 4];
						yti[k + 5] = yti[k + 5] ^ vj[k + 5];
						yti[k + 6] = yti[k + 6] ^ vj[k + 6];
						yti[k + 7] = yti[k + 7] ^ vj[k + 7];

					}
					for (; k < n128; ++k)
						yti[k] = yti[k] ^ vj[k];
				}
				vIter += vStep;
				++j;
			}

			ytIter += ytstep;
		}

		oc::AlignedArray<block, 128> tt;
		auto step = yt.cols();
		for (u64 i = 0, ii = 0; i < n; i += 128, ++ii)
		{
			auto offset = yt.data() + ii;
			for (u64 j = 0; j < 128; ++j)
			{
				assert(&yt(j, ii) == offset);
				tt[j] = *offset;
				offset += step;
			}

			oc::transpose128(tt.data());
			auto m = std::min<u64>(n - i, 128);

			memcpy(y.data() + i + begin, tt.data(), m * sizeof(block));
			//if (m == 128)
			//{

			//    for (u64 j = 0; j < m; ++j)
			//    {
			//        y[i + j] = tt[j];
			//    }
			//}
			//else
			//{
			//    for (u64 j = 0; j < m; ++j)
			//    {
			//        y[i + j] = tt[j];
			//    }
			//}
		}
	}



	void compressB(
		oc::MatrixView<block> v,
		span<block> y
	)
	{
		if (1)
		{
			// rownd down
			auto n = y.size();

			oc::AlignedArray<block, 128> tt, yy;
			//auto v1 = v[1];
			block* v0Iter = v[0].data();
			block* v1Iter = v[128].data();
			auto vStep = v.cols();
			u64 i = 0, ii = 0;

			for (; i < n; i += 128, ++ii)
			{
				for (u64 j = 0; j < 128; ++j)
				{
					yy[j] = v0Iter[j * vStep];
				}
				++v0Iter;

				oc::transpose128(yy);

				for (u64 j = 0; j < 128; ++j)
				{
					tt[j] = v1Iter[j * vStep];
				}
				++v1Iter;

				oc::transpose128(tt.data());

				if (i + 128 < n)
				{
					auto yIter = y.data() + i;
					for (u64 j = 0; j < 128; ++j)
					{
						AltModPrf::mBCode.encode((u8*)(tt.data() + j), (u8*)(tt.data() + j));
						yIter[j] = yy[j] ^ tt[j];
					}
				}
				else
				{
					auto m = n - i;
					auto yIter = y.data() + i;
					for (u64 j = 0; j < m; ++j)
					{
						AltModPrf::mBCode.encode((u8*)(tt.data() + j), (u8*)(tt.data() + j));
						yIter[j] = yy[j] ^ tt[j];
					}
				}
			}


		}
		else
		{

			u64 batch = 1ull << 12;
			auto n = y.size();
			for (u64 i = 0; i < n; i += batch)
			{
				auto m = std::min<u64>(batch, n - i);
				compressB(i, m, v, y);
			}
		}
	}


	void compare(span<block> m1, span<block> m0, span<u16> u, bool verbose = false)
	{
		for (u64 i = 0; i < u.size(); ++i)
		{
			if (verbose && i < 10)
			{
				std::cout << i << ": " << u[i] << " ~ (" << bit(m1[0], i) << " " << bit(m0[0], i) << std::endl;
			}

			assert(u[i] < 3);
			if (*oc::BitIterator((u8*)m1.data(), i) != (u[i] >> 1))
			{
				std::cout << "msb " << i << ": " << u[i] << " -> (" << *oc::BitIterator((u8*)m1.data(), i) << " " << *oc::BitIterator((u8*)m0.data(), i) << " )" << std::endl;
				throw RTE_LOC;
			}
			if (*oc::BitIterator((u8*)m0.data(), i) != (u[i] & 1))
			{
				std::cout << "lsb " << i << ": " << u[i] << " -> (" << *oc::BitIterator((u8*)m1.data(), i) << " " << *oc::BitIterator((u8*)m0.data(), i) << " )" << std::endl;
				throw RTE_LOC;;
			}
		}
	}

	void compare(span<block> m1, span<block> m0,
		span<block> u1, span<block> u0)
	{
		assert(m1.size() == u1.size());
		assert(m0.size() == u1.size());
		assert(u0.size() == u1.size());

		for (u64 i = 0; i < u0.size(); ++i)
		{
			if (m1[i] != u1[i] || m0[i] != u0[i])
			{
				std::cout << "bad compare " << std::endl;
				for (u64 j = i * 128; j < i * 128 + 128; ++j)
				{
					std::cout << j << ": (" <<
						bit(m1[i], j % 128) << " " << bit(m0[i], j % 128) << ") vs (" <<
						bit(u1[i], j % 128) << " " << bit(u0[i], j % 128) << ")" << std::endl;
				}
				throw RTE_LOC;

			}
		}
	}



	void  AltModPrf::setKey(AltModPrf::KeyType k)
	{
		mExpandedKey = k;
	}

	//void  AltModPrf::mtxMultA(const std::array<u16, KeySize>& hj, block256m3& uj)
	//{
	//	std::array<u8, KeySize> h;
	//	for (u64 i = 0; i < KeySize; ++i)
	//		h[i] = hj[i];
	//	mACode.encode<u8>(h, uj.mData);
	//}


	void AltModPrf::expandInputAes(span<block> x, oc::MatrixView<block> xt)
	{
		auto n = x.size();
		if (xt.rows() != AltModPrf::KeySize)
			throw RTE_LOC;
		if (xt.cols() != oc::divCeil(n, 128))
			throw RTE_LOC;

		for (u64 i = 0, k = 0; i < n; ++k)
		{
			static_assert(AltModPrf::KeySize % 128 == 0);
			auto m = std::min<u64>(128, n - i);
			auto xIter = x.data() + k * 128;

			for (u64 q = 0; q < AltModPrf::KeySize / 128; ++q)
			{
				auto tweak = block(q, q);
				oc::AlignedArray<block, 128> t;
				if (q == 0)
				{
					for (u64 j = 0;j < m; ++j)
					{
						t[j] = xIter[j];
					}
				}
				else
				{
					for (u64 j = 0;j < m; ++j)
					{
						t[j] = xIter[j] ^ tweak;
					}
					oc::mAesFixedKey.hashBlocks(t, t);
				}

				oc::transpose128(t.data());

				auto xtk = &xt(q * 128, k);
				auto step = xt.cols();
				for (u64 j = 0;j < 128; ++j)
				{
					assert(xtk == &xt(q * 128 + j, k));
					*xtk = t[j];
					xtk += step;
				}
			}


			i += 128;
		}
	}

	void AltModPrf::expandInputLinear(block x, KeyType& X)
	{
		X[0] = x;
		constexpr const auto rem = KeyType{}.size() - 1;
		for (auto i = 0ull; i < rem; ++i)
			mGCode[i].encode((u8*)&x, (u8*)&X[i + 1]);
	}

	void AltModPrf::expandInputLinear(span<block> x, oc::MatrixView<block> xt)
	{
		auto n = x.size();
		if (xt.rows() != AltModPrf::KeySize)
			throw RTE_LOC;
		if (xt.cols() != oc::divCeil(n, 128))
			throw RTE_LOC;


		oc::AlignedArray<block, 128> t;
		auto step = xt.cols();
		for (u64 i = 0; i < n; i += 128)
		{
			static_assert(AltModPrf::KeySize % 128 == 0);
			auto m = std::min<u64>(128, n - i);
			auto xIter = x.data() + i;

			memcpy(t.data(), xIter, m * sizeof(block));
			if (m != 128)
				memset(t.data() + m, 0, (128 - m) * sizeof(block));

			oc::transpose128(t.data());

			auto k = i / 128;
			auto xtk = &xt(0, k);
			for (u64 j = 0; j < 128; ++j)
			{
				assert(xtk == &xt(j, k));

				//if (i == 0)
				//{
				//	std::cout << t[j] << std::endl;
				//}

				*xtk = t[j];
				xtk += step;
			}
		}
		//std::cout << std::endl;

		for (u64 q = 0; q < AltModPrf::mGCode.size(); ++q)
		{
			for (u64 i = 0; i < n; i += 128)
			{
				static_assert(AltModPrf::KeySize % 128 == 0);
				auto m = std::min<u64>(128, n - i);
				auto xIter = x.data() + i;

				if (m == 128)
				{
					for (u64 w = 0; w < 16; ++w)
						AltModPrf::mGCode[q].encodeN<8>(xIter + w * 8, t.data() + w * 8);
				}
				else
				{
					for (u64 j = 0; j < m; ++j)
						AltModPrf::mGCode[q].encode((u8*)&xIter[j], (u8*)&t[j]);
					for (u64 j = m; j < 128; ++j)
						t[j] = oc::ZeroBlock;
				}

				oc::transpose128(t.data());

				auto k = i / 128;
				auto xtk = &xt(q * 128 + 128, k);
				for (u64 j = 0;j < 128; ++j)
				{
					assert(xtk == &xt(q * 128 + 128 + j, k));
					*xtk = t[j];
					xtk += step;
				}


			}
		}
	}

	namespace
	{
		Perm expandInput3Perm;
	}

	void AltModPrf::initExpandInputPermuteLinear()
	{
		PRNG prng(oc::CCBlock);
		expandInput3Perm = Perm(4 * 128, prng);

	}

	void AltModPrf::expandInputPermuteLinear(span<block> x, oc::MatrixView<block> xt)
	{
		if (xt.rows() != 4 * 128)
			throw RTE_LOC;
		u64 batchSize = 1ull << 10;
		oc::AlignedArray<block, 128> t;
		auto step = xt.cols();
		auto n = x.size();
		for (u64 i = 0; i < n; i += batchSize)
		{
			static_assert(AltModPrf::KeySize % 128 == 0);
			auto batchSize_ = std::min<u64>(batchSize, n - i);
			auto k = i / 128;
			for (auto q = 0ull; q < batchSize_; q += 128)
			{
				auto xIter = x.data() + i + q;
				auto m = std::min<u64>(128, n - q);
				memcpy(t.data(), xIter, m);
				if (m != 128)
					memset(t.data() + m, 0, 128 - m);

				oc::transpose128(t.data());


				auto xtk = &xt(0, k);
				for (u64 j = 0;j < 128; ++j)
				{
					assert(xtk == &xt(j, k));
					*xtk = t[j];
					xtk += step;
				}
			}

			auto d = oc::divCeil(batchSize_, 128);
			auto iterations = 3ull;
			for (u64 iter = 0; iter < iterations; ++iter)
			{
				for (u64 j = 0; j < 4 * 128 - 1; ++j)
				{
					block* __restrict src = &xt(expandInput3Perm[j], k);
					block* __restrict dst = &xt(expandInput3Perm[j + 1], k);
					for (auto q = 0ull; q < d; ++q)
					{
						dst[q] = dst[q] ^ src[q];
					}
				}
			}
		}
	}


	void AltModPrf::expandInputAes(block x, KeyType& X)
	{
		X[0] = x;
		for (u64 i = 1; i < X.size(); ++i)
			X[i] = x ^ block(i, i);

		constexpr const auto rem = KeyType{}.size() - 1;
		if (rem)
			oc::mAesFixedKey.hashBlocks<rem>(X.data() + 1, X.data() + 1);
	}

	block  AltModPrf::eval(block x)
	{
		block y;
		eval({ &x,1 }, { &y,1 });
		return y;
		//std::array<u16, KeySize> h;
		//AltModPrf::KeyType X;

		//expandInput(x, X);

		//auto kIter = oc::BitIterator((u8*)mExpandedKey.data());
		//auto xIter = oc::BitIterator((u8*)X.data());
		//for (u64 i = 0; i < KeySize; ++i)
		//{
		//	h[i] = *kIter & *xIter;
		//	++kIter;
		//	++xIter;
		//}

		//block256m3 u;
		//mtxMultA(h, u);

		//block256 w;
		//for (u64 i = 0; i < u.mData.size(); ++i)
		//{
		//	*oc::BitIterator((u8*)&w, i) = u.mData[i] % 2;
		//}
		//return compress(w);
	}

	void AltModPrf::eval(span<block> x, span<block> y)
	{
		//for (u64 i = 0; i < x.size(); ++i)
		//    y[i] = eval(x[i]);
		//return;

		oc::Matrix<block> xt, xk0, xk1, u0, u1;

		// we need x in a transformed format so that we can do SIMD operations.
		xt.resize(AltModPrf::KeySize, oc::divCeil(y.size(), 128));
		AltModPrf::expandInput(x, xt);

		xk0.resize(AltModPrf::KeySize, oc::divCeil(x.size(), 128), oc::AllocType::Uninitialized);
		xk1.resize(AltModPrf::KeySize, oc::divCeil(x.size(), 128), oc::AllocType::Uninitialized);
		for (u64 i = 0; i < KeySize; ++i)
		{
			if (bit(mExpandedKey, i))
			{
				memcpy(xk0[i], xt[i]);
			}
			else
				memset(xk0[i], 0);

			memset(xk1[i], 0);
		}

		u0.resize(AltModPrf::MidSize, oc::divCeil(x.size(), 128), oc::AllocType::Uninitialized);
		u1.resize(AltModPrf::MidSize, oc::divCeil(x.size(), 128), oc::AllocType::Uninitialized);

		AltModPrf::mACode.encode(xk1, xk0, u1, u0);

		compressB(u0, y);

	}



	//block  AltModPrf::compress(block256& w)
	//{
	//	return compress(w, mB);
	//}

	//block  AltModPrf::compress(block256& w, const std::array<block, 128>& B)
	//{
	//	oc::AlignedArray<block, 128> bw;

	//	for (u64 i = 0; i < 128; ++i)
	//	{
	//		//bw[0][i] = B[i].mData[0] & w.mData[0];
	//		bw[i] = B[i] & w.mData[1];
	//	}
	//	oc::transpose128(bw.data());
	//	//oc::transpose128(bw[1].data());

	//	block r = w[0];
	//	//memset(&r, 0, sizeof(r));
	//	//for (u64 i = 0; i < 128; ++i)
	//	//    r = r ^ bw[0][i];
	//	for (u64 i = 0; i < 128; ++i)
	//		r = r ^ bw[i];

	//	return r;
	//}




}