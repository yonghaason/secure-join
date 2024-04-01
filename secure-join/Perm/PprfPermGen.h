#pragma once

#include "secure-join/Defines.h"
#include "libOTe/Tools/Pprf/RegularPprf.h"

namespace secJoin
{ 


    struct PprfPermGenSender
    {
        oc::RegularPprfSender<oc::block> mSender;
        oc::AlignedUnVector<oc::block> mVal, mOutput;

        void init(u64 n, u64 t)
        {
            mSender.configure(t, n);
            mOutput.resize(n * t);
            std::vector<std::array<block, 2>> base(mSender.baseOtCount());
            mSender.setBase(base);
        }

        auto gen(coproto::Socket& s, oc::PRNG& prng)
        {
            return mSender.expand(s, mVal, prng.get(), mOutput, oc::PprfOutputFormat::ByTreeIndex, false, 1);
        }
    };

    struct PprfPermGenReceiver
    {
        oc::RegularPprfReceiver<oc::block> mRecver;
        oc::AlignedUnVector<oc::block> mVal, mOutput;
        u64 mBaseCount = 0;

        void init(u64 n, u64 t)
        {
            mRecver.configure(t, n);
            mOutput.resize(n * t);
            std::vector<block> base(mRecver.baseOtCount());
            oc::BitVector bits(base.size());
            mBaseCount = base.size();
            mRecver.setBase(base);
            mRecver.setChoiceBits(bits);
        }

        auto gen(coproto::Socket& s)
        {
            return mRecver.expand(s, mOutput, oc::PprfOutputFormat::ByTreeIndex, false, 1);
        }
    };
}