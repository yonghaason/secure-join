#pragma once
#include "secure-join/CorGenerator/Request.h"
#include "secure-join/CorGenerator/TritOtBatch.h"
#include "secure-join/CorGenerator/CorGenerator.h"

namespace secJoin
{
	

	class ConvertToF3Sender
	{
	public:
		Request<TritOtSend> mRequest;

		void init(u64 n, CorGenerator& gen)
		{
			mRequest = gen.request<TritOtSend>(n);
		}

		void preprocess()
		{
			mRequest.start();
		}

		macoro::task<> convert(
			span<const block> x,
			coproto::Socket& sock,
			span<block> y1, span<block> y0);
	};



	class ConvertToF3Recver
	{
	public:
		Request<TritOtRecv> mRequest;

		void init(u64 n, CorGenerator& gen)
		{
			mRequest = gen.request<TritOtRecv>(n);
		}

		void preprocess()
		{
			mRequest.start();
		}

		macoro::task<> convert(
			span<const block> x,
			coproto::Socket& sock,
			span<block> y1, span<block> y0);

	};
}