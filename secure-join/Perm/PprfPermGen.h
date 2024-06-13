#pragma once

#include "secure-join/Defines.h"
#include "libOTe/Tools/Pprf/RegularPprf.h"
#include "libOTe/TwoChooseOne/SoftSpokenOT/SoftSpokenShOtExt.h"
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
        }

        auto gen(coproto::Socket& s, oc::PRNG& prng)
        {
            MC_BEGIN(macoro::task<>, this, &s, &prng,
                base = std::vector<std::array<block, 2>>(mSender.baseOtCount()),
                ot = oc::SoftSpokenShOtSender<>{}
            );

            MC_AWAIT(ot.send(base, prng, s));
            mSender.setBase(base);
            MC_AWAIT(mSender.expand(s, mVal, prng.get(), mOutput, oc::PprfOutputFormat::ByTreeIndex, false, 1));
            MC_END();
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
        }

        auto gen(coproto::Socket& s, PRNG& prng)
        {
            MC_BEGIN(macoro::task<>, this, &s, &prng,
                base = std::vector<block>(mRecver.baseOtCount()),
                bits = oc::BitVector(mRecver.baseOtCount()),
                ot = oc::SoftSpokenShOtReceiver<>{}
            );
            //std::vector<block> base(mRecver.baseOtCount());
            //oc::BitVector bits(base.size());
            //mBaseCount = base.size();
            //mRecver.setBase(base);

            MC_AWAIT(ot.receive(bits, base, prng, s));
            mRecver.setChoiceBits(bits);
            mRecver.setBase(base);
            MC_AWAIT(mRecver.expand(s, mOutput, oc::PprfOutputFormat::ByTreeIndex, false, 1));
            MC_END();
        }
    };
}