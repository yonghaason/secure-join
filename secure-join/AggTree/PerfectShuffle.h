#pragma once
#include "secure-join/Defines.h"
#include "cryptoTools/Common/Defines.h"
#include <cassert>

namespace secJoin
{

	

	// given a shuffle on blocks of 2*Shift, shuffle
	// them together to have block size Shift.
	template<int Shift,
		u32 v = 
			(Shift == 1 ? 0x22222222 :
			(Shift == 2 ? 0x0C0C0C0C :
			(Shift == 4 ? 0x00F000F0 :
			(Shift == 8 ? 0x0000FF00 :
				0
			))))
	>
	inline u32 cPerfectShuffle_round(u32 x)
	{
		static_assert(Shift, "Shift must be 1,2,4,8. That is, we assume the x is split into chunks of size 2*Shift and we will shuffle these into chunks of size Shift");
		u32 t;
		t = (x ^ (x >> Shift)) & v; 
		x = x ^ t ^ (t << Shift);
		return x;
	}



	// Hackers Delight perfect shuffle, Sec 7.2. Interlace bits.
	// https://doc.lagout.org/security/Hackers%20Delight.pdf
	//
	// input : abcd efgh ijkl mnop ABCD EFGH IJKL MNOP,
	// output: aAbB cCdD eEfF gGhH iIjJ kKlL mMnN oOpP
	inline u32 cPerfectShuffle(u16 x0, u16 x1)
	{
		u32 x;
		((u16*)&x)[0] = x0;
		((u16*)&x)[1] = x1;
		x = cPerfectShuffle_round<8>(x);
		x = cPerfectShuffle_round<4>(x);
		x = cPerfectShuffle_round<2>(x);
		x = cPerfectShuffle_round<1>(x);
		return x;
	}

	// Hackers Delight perfect shuffle, Sec 7.2. Uninterlace bits.
	// https://doc.lagout.org/security/Hackers%20Delight.pdf
	//
	// input : aAbB cCdD eEfF gGhH iIjJ kKlL mMnN oOpP
	// output: abcd efgh ijkl mnop ABCD EFGH IJKL MNOP,
	inline std::array<u16, 2> cPerfectUnshuffle(u32 x)
	{
		x = cPerfectShuffle_round<1>(x);
		x = cPerfectShuffle_round<2>(x);
		x = cPerfectShuffle_round<4>(x);
		x = cPerfectShuffle_round<8>(x);
		return *(std::array<u16, 2>*) & x;
	}


	inline void cPerfectShuffle(span<const u8> input0, span<const u8> input1, span<u8> output)
	{
		assert(input0.size() == input1.size());
		assert(input0.size() == (output.size() + 1) / 2);

		u64 n32 = output.size() / sizeof(u32);

		auto in0 = (u16*)input0.data();
		auto in1 = (u16*)input1.data();
		auto out = (u32*)output.data();
		for (u64 i = 0; i < n32; ++i)
		{
			out[i] = cPerfectShuffle(in0[i], in1[i]);
		}


		auto n8 = n32 * sizeof(u32);
		if (output.size() != n8)
		{
			auto rem = input0.size() - n8 / 2;
			u16 x0 = 0, x1 = 0;
			memcpy(&x0, &input0[n8 / 2], rem);
			memcpy(&x1, &input1[n8 / 2], rem);
			auto t = cPerfectShuffle(x0,x1);

			memcpy(&output[n8], &t, output.size() - n8);
		}
	}

	inline void cPerfectUnshuffle(span<u8> input, span<u8> output0, span<u8> output1)
	{
		assert(output0.size() == output1.size());
		assert(output0.size() == (input.size() + 1) / 2);
		u64 n32 = input.size() / sizeof(u32);

		auto out0 = (u16*)output0.data();
		auto out1 = (u16*)output1.data();
		auto in = (u32*)input.data();
		for (u64 i = 0; i < n32; ++i)
		{
			auto t = cPerfectUnshuffle(in[i]);
			assert((u8*)&(out0[i]) < output0.data() + output0.size());
			assert((u8*)&(out1[i]) < output1.data() + output1.size());

			out0[i] = ((u16*)&t)[0];
			out1[i] = ((u16*)&t)[1];
		}

		auto n8 = n32 * sizeof(u32);
		if (input.size() != n8)
		{
			auto rem = output0.size() - n8 / 2;
			u32 t = 0;
			memcpy(&t, &input[n8], input.size() - n8);

			auto r = cPerfectUnshuffle(t);

			assert(n8 / 2 + rem == output0.size());
			assert(n8 / 2 + rem == output1.size());

			memcpy(&output0[n8 / 2], &r[0], rem);
			memcpy(&output1[n8 / 2], &r[1], rem);
		}
	}

#ifdef ENABLE_SSE

	// given a shuffle on blocks of 2*Shift, shuffle
	// them together to have block size Shift.
	template<int Shift,
		u32 v = 
			(Shift == 1 ? 0x22222222 :
			(Shift == 2 ? 0x0C0C0C0C :
			(Shift == 4 ? 0x00F000F0 :
			(Shift == 8 ? 0x0000FF00 :
				0
			))))
	>
	inline void ssePerfectShuffle_round(oc::block& x)
	{
		static_assert(Shift, "Shift must be 1,2,4,8. That is, we assume the x is split into chunks of size 2*Shift and we will shuffle these into chunks of size Shift");
		oc::block t;

		//t = (x ^ (x >> shift)) & 0x0000FF00; 
		t = _mm_srli_epi32(x, Shift);
		t = _mm_xor_si128(t, x);
		t = _mm_and_si128(t, _mm_set_epi32(v, v, v, v));

		// x = x ^ t ^ (t << shift);
		x = _mm_xor_si128(t, x);
		t = _mm_slli_epi32(t, Shift);
		x = _mm_xor_si128(t, x);
	}

	// given a shuffle on blocks of 2*Shift, shuffle
	// them together to have block size Shift.
	template<int Shift,
		u32 v = 
			(Shift == 1 ? 0x22222222 :
			(Shift == 2 ? 0x0C0C0C0C :
			(Shift == 4 ? 0x00F000F0 :
			(Shift == 8 ? 0x0000FF00 :
				0
			))))
	>
	inline void ssePerfectShuffle_round(oc::block* x)
	{
		static_assert(Shift, "Shift must be 1,2,4,8. That is, we assume the x is split into chunks of size 2*Shift and we will shuffle these into chunks of size Shift");
		oc::block t[8];
		auto V = _mm_set_epi32(v, v, v, v);

		//t = (x ^ (x >> shift)) & 0x0000FF00; 
		t[0] = _mm_srli_epi32(x[0], Shift);
		t[1] = _mm_srli_epi32(x[1], Shift);
		t[2] = _mm_srli_epi32(x[2], Shift);
		t[3] = _mm_srli_epi32(x[3], Shift);
		t[4] = _mm_srli_epi32(x[4], Shift);
		t[5] = _mm_srli_epi32(x[5], Shift);
		t[6] = _mm_srli_epi32(x[6], Shift);
		t[7] = _mm_srli_epi32(x[7], Shift);

		t[0] = _mm_xor_si128(t[0], x[0]);
		t[1] = _mm_xor_si128(t[1], x[1]);
		t[2] = _mm_xor_si128(t[2], x[2]);
		t[3] = _mm_xor_si128(t[3], x[3]);
		t[4] = _mm_xor_si128(t[4], x[4]);
		t[5] = _mm_xor_si128(t[5], x[5]);
		t[6] = _mm_xor_si128(t[6], x[6]);
		t[7] = _mm_xor_si128(t[7], x[7]);

		t[0] = _mm_and_si128(t[0], V);
		t[1] = _mm_and_si128(t[1], V);
		t[2] = _mm_and_si128(t[2], V);
		t[3] = _mm_and_si128(t[3], V);
		t[4] = _mm_and_si128(t[4], V);
		t[5] = _mm_and_si128(t[5], V);
		t[6] = _mm_and_si128(t[6], V);
		t[7] = _mm_and_si128(t[7], V);

		// x = x ^ t ^ (t << shift);
		x[0] = _mm_xor_si128(t[0], x[0]);
		x[1] = _mm_xor_si128(t[1], x[1]);
		x[2] = _mm_xor_si128(t[2], x[2]);
		x[3] = _mm_xor_si128(t[3], x[3]);
		x[4] = _mm_xor_si128(t[4], x[4]);
		x[5] = _mm_xor_si128(t[5], x[5]);
		x[6] = _mm_xor_si128(t[6], x[6]);
		x[7] = _mm_xor_si128(t[7], x[7]);
		t[0] = _mm_slli_epi32(t[0], Shift);
		t[1] = _mm_slli_epi32(t[1], Shift);
		t[2] = _mm_slli_epi32(t[2], Shift);
		t[3] = _mm_slli_epi32(t[3], Shift);
		t[4] = _mm_slli_epi32(t[4], Shift);
		t[5] = _mm_slli_epi32(t[5], Shift);
		t[6] = _mm_slli_epi32(t[6], Shift);
		t[7] = _mm_slli_epi32(t[7], Shift);
		x[0] = _mm_xor_si128(t[0], x[0]);
		x[1] = _mm_xor_si128(t[1], x[1]);
		x[2] = _mm_xor_si128(t[2], x[2]);
		x[3] = _mm_xor_si128(t[3], x[3]);
		x[4] = _mm_xor_si128(t[4], x[4]);
		x[5] = _mm_xor_si128(t[5], x[5]);
		x[6] = _mm_xor_si128(t[6], x[6]);
		x[7] = _mm_xor_si128(t[7], x[7]);
	}

	inline oc::block ssePerfectShuffle(u64 x0, u64 x1)
	{
		// perfect shuffle the bytes.
		const oc::block b = _mm_set_epi8(15, 7, 14, 6, 13, 5, 12, 4, 11, 3, 10, 2, 9, 1, 8, 0);
		oc::block y = _mm_set_epi64x(x1, x0);
		y = _mm_shuffle_epi8(y, b);

		// perfect shuffle the bits. 
		ssePerfectShuffle_round<4>(y);
		ssePerfectShuffle_round<2>(y);
		ssePerfectShuffle_round<1>(y);
		return y;
	}

	inline std::array<u64,2> ssePerfectUnshuffle(oc::block y)
	{
		// perfect shuffle the bits. 
		ssePerfectShuffle_round<1>(y);
		ssePerfectShuffle_round<2>(y);
		ssePerfectShuffle_round<4>(y);

		// perfect shuffle the bytes. 
		const oc::block b = _mm_set_epi8(15, 13, 11, 9, 7, 5, 3, 1, 14, 12, 10, 8, 6, 4, 2, 0);
		y = _mm_shuffle_epi8(y, b);

		return *(std::array<u64, 2>*)&y;
	}

	// perfect shuffle 4 blocks on x0,x1 into 8 blocks of y.
	inline void ssePerfectShuffle(const oc::block* x0, const oc::block* x1, oc::block* y)
	{
		// perfect shuffle the bytes.
		const oc::block b = _mm_set_epi8(15, 7, 14, 6, 13, 5, 12, 4, 11, 3, 10, 2, 9, 1, 8, 0);
		y[0] = _mm_set_epi64x(((u64*)x1)[0], ((u64*)x0)[0]);
		y[1] = _mm_set_epi64x(((u64*)x1)[1], ((u64*)x0)[1]);
		y[2] = _mm_set_epi64x(((u64*)x1)[2], ((u64*)x0)[2]);
		y[3] = _mm_set_epi64x(((u64*)x1)[3], ((u64*)x0)[3]);
		y[4] = _mm_set_epi64x(((u64*)x1)[4], ((u64*)x0)[4]);
		y[5] = _mm_set_epi64x(((u64*)x1)[5], ((u64*)x0)[5]);
		y[6] = _mm_set_epi64x(((u64*)x1)[6], ((u64*)x0)[6]);
		y[7] = _mm_set_epi64x(((u64*)x1)[7], ((u64*)x0)[7]);
		y[0] = _mm_shuffle_epi8(y[0], b);
		y[1] = _mm_shuffle_epi8(y[1], b);
		y[2] = _mm_shuffle_epi8(y[2], b);
		y[3] = _mm_shuffle_epi8(y[3], b);
		y[4] = _mm_shuffle_epi8(y[4], b);
		y[5] = _mm_shuffle_epi8(y[5], b);
		y[6] = _mm_shuffle_epi8(y[6], b);
		y[7] = _mm_shuffle_epi8(y[7], b);

		// perfect shuffle the bits. 
		ssePerfectShuffle_round<4>(y);
		ssePerfectShuffle_round<2>(y);
		ssePerfectShuffle_round<1>(y);
	}

	// perfect unshuffle 8 blocks of y into 4 blocks on x0,x1 into.
	inline void ssePerfectUnshuffle(const oc::block* yy, oc::block* x0, oc::block* x1)
	{
		std::array<oc::block, 8> y;
		memcpy(y.data(), yy, sizeof(y));

		// perfect shuffle the bits. 
		ssePerfectShuffle_round<1>(y.data());
		ssePerfectShuffle_round<2>(y.data());
		ssePerfectShuffle_round<4>(y.data());

		// perfect shuffle the bytes.
		const oc::block b = _mm_set_epi8(15, 13, 11, 9, 7, 5, 3, 1, 14, 12, 10, 8, 6, 4, 2, 0);
		y[0] = _mm_shuffle_epi8(y[0], b);
		y[1] = _mm_shuffle_epi8(y[1], b);
		y[2] = _mm_shuffle_epi8(y[2], b);
		y[3] = _mm_shuffle_epi8(y[3], b);
		y[4] = _mm_shuffle_epi8(y[4], b);
		y[5] = _mm_shuffle_epi8(y[5], b);
		y[6] = _mm_shuffle_epi8(y[6], b);
		y[7] = _mm_shuffle_epi8(y[7], b);

		
		u64* yyy = (u64*)y.data();
		u64* xx1 = (u64*)x1;
		u64* xx0 = (u64*)x0;
		xx0[0] = yyy[0];
		xx1[0] = yyy[1];
		xx0[1] = yyy[2];
		xx1[1] = yyy[3];
		xx0[2] = yyy[4];
		xx1[2] = yyy[5];
		xx0[3] = yyy[6];
		xx1[3] = yyy[7];

		xx0[4] = yyy[8];
		xx1[4] = yyy[9];
		xx0[5] = yyy[10];
		xx1[5] = yyy[11];
		xx0[6] = yyy[12];
		xx1[6] = yyy[13];
		xx0[7] = yyy[14];
		xx1[7] = yyy[15];
	}

	inline void ssePerfectShuffle(span<const u8> input0, span<const u8> input1, span<u8> output)
	{
		assert(input0.size() == input1.size());
		assert(input0.size() == (output.size() + 1) / 2);
		u64 n1024 = output.size() / sizeof(std::array<oc::block, 8>);

		auto in0 = (oc::block*)input0.data();
		auto in1 = (oc::block*)input1.data();
		auto out = (oc::block*)output.data();
		for (u64 i = 0; i < n1024; ++i)
		{
			ssePerfectShuffle(in0, in1, out);
			in0 += 4;
			in1 += 4;
			out += 8;
		}

		auto n64 = n1024 * 16;
		auto n8 = n64 * sizeof(u64);
		auto rem = input0.size() - n8 / 2;
		while (rem)
		{
			auto min = std::min<u64>(rem, sizeof(u64));
			u64 x0 = 0, x1 = 0;
			memcpy(&x0, &input0[n8 / 2], min);
			memcpy(&x1, &input1[n8 / 2], min);
			rem -= min;

			auto t = ssePerfectShuffle(x0, x1);

			auto min2 = std::min<u64>(output.size() - n8, sizeof(oc::block));
			memcpy(&output[n8], &t, min2);
			n8 += min2;
		}
	}


	inline void ssePerfectUnshuffle(span<const u8> input, span<u8> output0, span<u8> output1)
	{
		assert(output0.size() == output1.size());
		assert(output0.size() == (input.size() + 1) / 2);

		u64 n1024 = input.size() / sizeof(std::array<oc::block, 8>);

		auto out0 = (oc::block*)output0.data();
		auto out1 = (oc::block*)output1.data();
		auto in =   (oc::block*)input.data();
		for (u64 i = 0; i < n1024; ++i)
		{
			assert((u8*)(in + 8) <= input.data() + input.size());
			assert((u8*)(out0 + 4) <= output0.data() + output0.size());
			assert((u8*)(out1 + 4) <= output1.data() + output1.size());
			ssePerfectUnshuffle(in, out0, out1);

			in += 8;
			out0 += 4;
			out1 += 4;
		}


		auto n64 = n1024 * 16;
		u64 x0 = 0, x1 = 0;
		auto n8 = n64 * sizeof(u64);
		//auto n8 = n32 * sizeof(u32);
		while (input.size() != n8)
		{
			auto rem = input.size() - n8;
			auto min = std::min<u64>(rem, sizeof(oc::block));
			oc::block t = oc::ZeroBlock;
			memcpy(&t, &input[n8], min);

			auto r = ssePerfectUnshuffle(t);

			auto min2 = std::min<u64>(output0.size() - n8 / 2, sizeof(u64));
			memcpy(&output0[n8 / 2], &r[0], min2);
			memcpy(&output1[n8 / 2], &r[1], min2);

			n8 += min;
		}
	}
#endif

	inline void perfectShuffle(span<const u8> input0, span<const u8> input1, span<u8> output)
	{
#ifdef ENABLE_SSE
		ssePerfectShuffle(input0, input1, output);
#else
		cPerfectShuffle(input0, input1, output);
#endif
	}

	inline void perfectUnshuffle(span<const u8> input, span<u8> output0, span<u8> output1)
	{
#ifdef ENABLE_SSE
		ssePerfectUnshuffle(input, output0, output1);
#else
		cPerfectUnshuffle(input, output0, output1);
#endif
	}

	//template<typename In, typename Out>
	//inline void perfectShuffle(span<In> input0, span<In> input1, span<Out> output)
	//{
	//	static_assert(std::is_trivial<In>::value, "");
	//	static_assert(std::is_trivial<Out>::value, "");
	//	span<u8> in0((u8*)input0.data(), input0.size() * sizeof(In));
	//	span<u8> in1((u8*)input1.data(), input1.size() * sizeof(In));
	//	span<u8> out((u8*)output.data(), output.size() * sizeof(Out));
	//	perfectShuffle(in0, in1, out);
	//}

	//template<typename In, typename Out>
	//inline void perfectUnshuffle(span<In> input, span<Out> output0, span<Out> output1)
	//{
	//	static_assert(std::is_trivial<In>::value, "");
	//	static_assert(std::is_trivial<Out>::value, "");
	//	span<u8> in((u8*)input.data(), input.size() * sizeof(In));
	//	span<u8> out0((u8*)output0.data(), output0.size() * sizeof(Out));
	//	span<u8> out1((u8*)output1.data(), output1.size() * sizeof(Out));
	//	perfectShuffle(in, out0, out1);
	//}
}