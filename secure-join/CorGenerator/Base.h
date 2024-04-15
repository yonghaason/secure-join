#pragma once
#include "secure-join/Defines.h"
#include "cryptoTools/Common/Aligned.h"
#include "cryptoTools/Common/BitVector.h"

#include <vector>
#include <memory>
#include <numeric>

#include "macoro/task.h"
#include "macoro/channel.h"
#include "macoro/macros.h"
#include "macoro/manual_reset_event.h"

#include "libOTe/TwoChooseOne/Silent/SilentOtExtSender.h"
#include "libOTe/TwoChooseOne/Silent/SilentOtExtReceiver.h"
#include "secure-join/CorGenerator/F4Vole/F4CoeffCtx.h"

namespace secJoin
{
    //struct SendBase
    //{
    //    std::vector<std::array<PRNG, 2>> mBase;

    //    std::vector<std::array<oc::block, 2>> get()
    //    {
    //        std::vector<std::array<oc::block, 2>> r(mBase.size());
    //        for (u64 i = 0;i < r.size();++i)
    //        {
    //            r[i][0] = mBase[i][0].get();
    //            r[i][1] = mBase[i][1].get();
    //        }
    //        return r;
    //    }


    //    void resize(u64 n)
    //    {
    //        mBase.resize(n);
    //    }

    //    SendBase fork()
    //    {
    //        SendBase s;
    //        s.resize(mBase.size());
    //        for (u64 i = 0;i < mBase.size();++i)
    //        {
    //            s.mBase[i][0].SetSeed(mBase[i][0].get<oc::block>());
    //            s.mBase[i][1].SetSeed(mBase[i][1].get<oc::block>());
    //        }

    //        return s;
    //    }
    //};

    //struct RecvBase
    //{
    //    std::vector<PRNG> mBase;
    //    oc::BitVector mChoice;

    //    std::vector<oc::block> get()
    //    {
    //        std::vector<oc::block> r(mBase.size());
    //        for (u64 i = 0;i < r.size();++i)
    //        {
    //            r[i] = mBase[i].get();
    //        }
    //        return r;
    //    }

    //    void resize(u64 n)
    //    {
    //        mBase.resize(n);
    //        mChoice.resize(n);
    //    }
    //    
    //    RecvBase fork()
    //    {
    //        RecvBase s;
    //        s.resize(mBase.size());
    //        for (u64 i = 0;i < mBase.size();++i)
    //        {
    //            s.mBase[i].SetSeed(mBase[i].get<oc::block>());
    //        }

    //        s.mChoice = mChoice;
    //        return s;
    //    }
    //};



    struct BaseRequest
    {
        // the choice bits requested for recv base OTs
        oc::BitVector mChoice;

        // the number of send OTs requested
        u64 mSendSize = 0;

        // the number of F4 voles.
        u64 mSendVoleSize = 0;

        // the base choice values for the F4 voles.
        oc::AlignedUnVector<F4> mVoleChoice;

        BaseRequest() = default;
        BaseRequest(const BaseRequest&) = default;
        BaseRequest(BaseRequest&&) = default;
        BaseRequest& operator=(BaseRequest&&) = default;
        BaseRequest(span<BaseRequest> reqs)
        {
            u64 s = 0;
            for (u64 i = 0; i < reqs.size(); ++i)
                s += reqs[i].mChoice.size();
            mChoice.reserve(s);
            for (u64 i = 0; i < reqs.size(); ++i)
                mChoice.append(reqs[i].mChoice);
            mSendSize = std::accumulate(reqs.begin(), reqs.end(), 0ull,
                [](auto c, auto& v) { return c + v.mSendSize; });



            s = 0;
            for (u64 i = 0; i < reqs.size(); ++i)
                s += reqs[i].mVoleChoice.size();
            mVoleChoice.resize(s);
            for (u64 i = 0, k = 0; i < reqs.size(); ++i)
            {
                for (u64 j = 0; j < reqs[i].mVoleChoice.size(); ++j, ++k)
                    mVoleChoice[k] = reqs[i].mVoleChoice[j];
            }
            mSendVoleSize = std::accumulate(reqs.begin(), reqs.end(), 0ull,
                [](auto c, auto& v) { return c + v.mSendVoleSize; });
        }
    };

    struct BaseCor
    {
        u64 mOtRecvIndex = 0;
        oc::BitVector mOtRecvChoice;
        oc::AlignedUnVector<block> mOtRecvMsg;

        u64 mOtSendIndex = 0;
        oc::AlignedUnVector<std::array<block, 2>> mOtSendMsg;

        u64 mVoleSendIndex = 0;
        u64 mVoleRecvIndex = 0;
        
        block mVoleDelta;

        // mVoleA = mVoleB + mVoleChoice * mVoleDelta
        oc::AlignedUnVector<F4> mVoleChoice;

        // mVoleA = mVoleB + mVoleChoice * mVoleDelta
        oc::AlignedUnVector<block> mVoleB, mVoleA;

        template<typename T>
        span<T> get(span<T> val, u64& index, u64 n)
        {
            if (index + n > val.size())
                throw RTE_LOC;

            span<T> v{ val.data() + index, n };
            index += n;

            return v;
        }

        span<std::array<block, 2>> getSendOt(u64 n)
        {
            return get<std::array<block, 2>>(mOtSendMsg, mOtSendIndex, n);
        }

        span<block> getRecvOt(u64 n)
        {
            return get<block>(mOtRecvMsg, mOtRecvIndex, n);
        }

        span<block> getRecvVole(u64 n)
        {
            return get<block>(mVoleA, mVoleRecvIndex, n);
        }

        span<block> getSendVole(u64 n)
        {
            return get<block>(mVoleB, mVoleSendIndex, n);
        }

    };
}