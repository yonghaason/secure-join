
#pragma once
#include "secure-join/config.h"
#include "secure-join/Defines.h"
#include "secure-join/CorGenerator/CorGenerator.h"

#include "macoro/optional.h"
#include "cryptoTools/Crypto/PRNG.h"
#include "AltModPrf.h"

namespace secJoin
{

    struct AltModKeyMultSender
    {
        static constexpr auto StepSize = 32;

        // base OTs, where the sender has the OT msg based on the bits of their key
        std::vector<std::array<PRNG, 2>> mKeySendOTs;

        // a share of the key. This can be disengaged if the other party 
        // knows the key in full.
        std::optional<AltModPrf::KeyType> mOptionalKeyShare;

        // The base ot request that will be used for the key
        OtSendRequest mSendKeyReq;


        bool mDebug = false;

        oc::Matrix<oc::block> mDebugXk0, mDebugXk1;

        macoro::task<> mult(
            const oc::Matrix<block>& x,
            oc::Matrix<block>& xk0,
            oc::Matrix<block>& xk1,
            coproto::Socket& sock);

        void setKeyOts(
            std::optional<AltModPrf::KeyType> keyShared,
            span<const std::array<block, 2>> ots)
        {
            if (ots.size() != AltModPrf::KeySize)
                throw RTE_LOC;

            mOptionalKeyShare = keyShared;

            mKeySendOTs.resize(AltModPrf::KeySize);
            for (u64 i = 0; i < AltModPrf::KeySize; ++i)
            {
                mKeySendOTs[i][0].SetSeed(ots[i][0]);
                mKeySendOTs[i][1].SetSeed(ots[i][1]);
            }
        }

        void clear()
        {
            mKeySendOTs.clear();
            mOptionalKeyShare = {};
            mSendKeyReq.clear();
        }

        void preprocess()
        {
            if (mSendKeyReq.size())
                mSendKeyReq.start();
        }

        void init(CorGenerator& ole,
            std::optional<AltModPrf::KeyType> keyShare,
            span<std::array<block, 2>> keyOts)
        {
            if (keyOts.size() == 0)
            {
                if (keyShare.has_value())
                    throw RTE_LOC;
                mSendKeyReq = ole.sendOtRequest(AltModPrf::KeySize);
            }
            else
            {
                setKeyOts(keyShare, keyOts);
            }
        }
    };

    struct AltModKeyMultReceiver
    {
        static constexpr auto StepSize = 32;

        // The key OTs, one for each bit of the key mKey
        std::vector<PRNG> mKeyRecvOTs;

        AltModPrf::KeyType mKey;


        // The base ot request that will be used for the key
        OtRecvRequest mRecvKeyReq;

        bool mDebug = false;


        oc::Matrix<oc::block> mDebugXk0, mDebugXk1;

        macoro::task<> mult(
            u64 n,
            oc::Matrix<block>& xk0,
            oc::Matrix<block>& xk1,
            coproto::Socket& sock);


        void setKeyOts(
            AltModPrf::KeyType k,
            span<const block> ots)
        {
            if (ots.size() != AltModPrf::KeySize)
                throw RTE_LOC;
            mKey = k;

            mKeyRecvOTs.resize(AltModPrf::KeySize);
            for (u64 i = 0; i < AltModPrf::KeySize; ++i)
            {
                mKeyRecvOTs[i].SetSeed(ots[i]);
            }

        }

        void clear()
        {
            mKeyRecvOTs.clear();
            mRecvKeyReq.clear();
            memset(&mKey, 0, sizeof(mKey));
        }


        void preprocess()
        {

            if (mRecvKeyReq.size())
                mRecvKeyReq.start();
        }


        void init(CorGenerator& ole,
            std::optional<AltModPrf::KeyType> key,
            span<block> keyOts)
        {
            if (key.has_value() ^ bool(keyOts.size()))
                throw RTE_LOC;

            if (keyOts.size() == 0)
            {
                mRecvKeyReq = ole.recvOtRequest(AltModPrf::KeySize);
            }
            else
            {
                setKeyOts(*key, keyOts);
            }
        }

    };

}