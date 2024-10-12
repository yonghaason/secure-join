#pragma once
#include "secure-join/config.h"
#include "secure-join/Defines.h"
#include "secure-join/CorGenerator/CorGenerator.h"

#include "cryptoTools/Common/BitIterator.h"
#include <bitset>
#include "libOTe/Tools/Tools.h"
#include "macoro/optional.h"
#include "F2LinearCode.h"
#include "F3LinearCode.h"

#include "AltModPrf.h"
#include "AltModKeyMult.h"
#include "ConvertToF3.h"

// TODO:
// * implement batching for large number of inputs. Will get 
//   better data locality.
// 

namespace secJoin
{


    class AltModWPrfSender : public oc::TimerAdapter
    {
    public:
        bool mDebug = false;

        // The key OTs, one for each bit of the key mPrf.mKey
        AltModKeyMultReceiver mKeyMultRecver;

        // if in fully secret shared mode, we need to multiply our input with their key.
        AltModKeyMultSender mKeyMultSender;

        // The number of input we will have.
        u64 mInputSize = 0;


        // The Ole request that will be used for the input*key operation
        BinOleRequest mKeyMultOleReq;

        // The Ole request that will be used for the mod2 operation
        BinOleRequest mMod2OleReq;

        // the 1-oo-4 OT request that will be used for the mod2 operations
        Request<F4BitOtSend> mMod2F4Req;

        bool mUseMod2F4Ot = true;

        ConvertToF3Sender mConvToF3;

        AltModPrfKeyMode mKeyMode = AltModPrfKeyMode::SenderOnly;

        AltModPrfInputMode mInputMode = AltModPrfInputMode::ReceiverOnly;

        // variables that are used for debugging.
        std::vector<block> mDebugInput;
        oc::Matrix<oc::block> 
            mDebugXk0, mDebugXk1,
            mDebugU0, mDebugU1, 
            mDebugV;

        AltModWPrfSender() = default;
        AltModWPrfSender(const AltModWPrfSender&) = default;
        AltModWPrfSender(AltModWPrfSender&&) noexcept = default;
        AltModWPrfSender& operator=(const AltModWPrfSender&) = default;
        AltModWPrfSender& operator=(AltModWPrfSender&&) noexcept = default;

        // initialize the protocol to perform inputSize prf evals.
        // set keyGen if you explicitly want to perform (or not) the 
        // key generation. default = perform if not already set.
        void init(
            u64 inputSize,
            CorGenerator& ole,
            AltModPrfKeyMode keyMode = AltModPrfKeyMode::SenderOnly,
            AltModPrfInputMode inputMode = AltModPrfInputMode::ReceiverOnly,
            macoro::optional<AltModPrf::KeyType> key = {},
            span<block> keyRecvOts = {},
            span<std::array<block, 2>> keySendOts = {})
        {
            mInputSize = inputSize;
            mKeyMode = keyMode;
            mInputMode = inputMode;

            if (key.has_value() ^ (AltModPrf::KeySize == keyRecvOts.size()))
                throw RTE_LOC;

            mKeyMultRecver.init(ole, key, keyRecvOts);
            auto n128 = oc::roundUpTo(mInputSize, 128);

            if (mKeyMode == AltModPrfKeyMode::Shared &&
                mInputMode == AltModPrfInputMode::Shared)
            {
                mKeyMultSender.init(ole, key, keySendOts);
                mKeyMultOleReq = ole.binOleRequest(n128 * AltModPrf::KeySize);
                mConvToF3.init(n128 * AltModPrf::KeySize, ole);
            }

            if (mUseMod2F4Ot)
            {
                auto num = n128 * AltModPrf::MidSize;
                mMod2F4Req = ole.request<F4BitOtSend>(num);
            }
            else
            {
                auto numOle = n128 * AltModPrf::MidSize * 2;
                mMod2OleReq = ole.binOleRequest(numOle);
            }
        }

        // clear the state. Removes any key that is set can cancels the prepro (if any).
        void clear()
        {
            mMod2F4Req.clear();
            mMod2OleReq.clear();
            mKeyMultRecver.clear();
            mKeyMultSender.clear();
            mInputSize = 0;
        }

        // perform the correlated randomness generation. 
        void preprocess()
        {

            mKeyMultRecver.preprocess();
            mKeyMultSender.preprocess();

            if (mUseMod2F4Ot)
                mMod2F4Req.start();
            else
                mMod2OleReq.start();

        }

        // explicitly set the key and key OTs.
        void setKeyOts(
            AltModPrf::KeyType k, 
            span<const oc::block> ots,
            span<const std::array<block, 2>> sendOts = {});

        // return the key that is currently set.
        AltModPrf::KeyType getKey() const
        {
            return mKeyMultRecver.mKey;
        }

        // Run the prf protocol and write the result to y. Requires that correlated 
        // randomness has already been requested using the request() function.
        // if in shared input mode, x should be a share of the input. Otherwise empty.
        coproto::task<> evaluate(
            span<oc::block> y,
            span<oc::block> x,
            coproto::Socket& sock,
            PRNG& _);


        // the mod 2 subprotocol based on OLE.
        macoro::task<> mod2Ole(
            oc::MatrixView<oc::block> u0,
            oc::MatrixView<oc::block> u1,
            oc::MatrixView<oc::block> out,
            coproto::Socket& sock);


        // the mod 2 subprotocol based on F4 OT.
        macoro::task<> mod2OtF4(
            oc::MatrixView<oc::block> u0,
            oc::MatrixView<oc::block> u1,
            oc::MatrixView<oc::block> out,
            coproto::Socket& sock);


    };



    class AltModWPrfReceiver : public oc::TimerAdapter
    {
    public:
        bool mDebug = false;

        // base OTs, where the sender has the OT msg based on the bits of their key
        AltModKeyMultSender mKeyMultSender;

        AltModKeyMultReceiver mKeyMultRecver;

        // The Ole request that will be used for the input*key operation
        BinOleRequest mKeyMultOleReq;

        // The number of input we will have.
        u64 mInputSize = 0;

        // The Ole request that will be used for the mod2 operation
        BinOleRequest mMod2OleReq;

        Request<F4BitOtRecv> mMod2F4Req;

        bool mUseMod2F4Ot = true;

        ConvertToF3Recver mConvToF3;

        AltModPrfKeyMode mKeyMode = AltModPrfKeyMode::SenderOnly;

        AltModPrfInputMode mInputMode = AltModPrfInputMode::ReceiverOnly;

        // variables that are used for debugging.
        oc::Matrix<oc::block> 
            mDebugXk0, mDebugXk1,
            mDebugU0, mDebugU1, 
            mDebugV,
            mDebugXKa0, mDebugXKa1,
            mDebugXKb0, mDebugXKb1,
            mDebugXc0, mDebugXc1;

        std::vector<block> mDebugInput;

        AltModWPrfReceiver() = default;
        AltModWPrfReceiver(const AltModWPrfReceiver&) = default;
        AltModWPrfReceiver(AltModWPrfReceiver&&) = default;
        AltModWPrfReceiver& operator=(const AltModWPrfReceiver&) = default;
        AltModWPrfReceiver& operator=(AltModWPrfReceiver&&) noexcept = default;

        // clears any internal state.
        void clear()
        {
            mMod2F4Req.clear();
            mMod2OleReq.clear();
            mKeyMultRecver.clear();
            mKeyMultSender.clear();
            mInputSize = 0;
        }

        // initialize the protocol to perform inputSize prf evals.
        // set keyGen if you explicitly want to perform (or not) the 
        // key generation. default = perform if not already set.
        // keyShare is a share of the key. If not set, then the sender
        // will hold a plaintext key. keyOts is will base OTs for the
        // sender's key (share).
        void init(u64 size,
            CorGenerator& ole,
            AltModPrfKeyMode keyMode = AltModPrfKeyMode::SenderOnly,
            AltModPrfInputMode inputMode = AltModPrfInputMode::ReceiverOnly,
            std::optional<AltModPrf::KeyType> keyShare = {},
            span<std::array<block, 2>> keyOts = {},
            span<block> keyRecvOts = {})
        {
            if (keyOts.size() != AltModPrf::KeySize && keyOts.size() != 0)
                throw RTE_LOC;
            if (!size)
                throw RTE_LOC;
            if (mInputSize)
                throw RTE_LOC;

            mInputSize = size;
            mKeyMode = keyMode;
            mInputMode = inputMode;
            auto n128 = oc::roundUpTo(mInputSize, 128);

            mKeyMultSender.init(ole, keyShare, keyOts);

            if (mKeyMode == AltModPrfKeyMode::Shared &&
                mInputMode == AltModPrfInputMode::Shared)
            {
                mKeyMultRecver.init(ole, keyShare, keyRecvOts);
                mKeyMultOleReq = ole.binOleRequest(n128 * AltModPrf::KeySize);
                mConvToF3.init(n128 * AltModPrf::KeySize, ole);
            }
            
            if (mUseMod2F4Ot)
            {
                auto numOle = n128 * AltModPrf::MidSize;
                mMod2F4Req = ole.request<F4BitOtRecv>(numOle);
            }
            else
            {
                auto numOle = n128 * AltModPrf::MidSize * 2;
                mMod2OleReq = ole.binOleRequest(numOle);
            }
        }

        // Perform the preprocessing for the correlated randomness and key gen (if requested).
        void preprocess()
        {
            if (mUseMod2F4Ot)
                mMod2F4Req.start();
            else
                mMod2OleReq.start();

            mKeyMultRecver.preprocess();
            mKeyMultRecver.preprocess();
        }

        // Run the prf protocol and write the result to y. Requires that correlated 
        // randomness has already been requested using the request() function.
        coproto::task<> evaluate(
            span<oc::block> x,
            span<oc::block> y,
            coproto::Socket& sock,
            PRNG&);

        // the mod 2 subprotocol based on ole.
        macoro::task<> mod2Ole(
            oc::MatrixView<oc::block> u0,
            oc::MatrixView<oc::block> u1,
            oc::MatrixView<oc::block> out,
            coproto::Socket& sock);

        // the mod 2 subprotocol based on ole.
        macoro::task<> mod2OtF4(
            oc::MatrixView<oc::block> u0,
            oc::MatrixView<oc::block> u1,
            oc::MatrixView<oc::block> out,
            coproto::Socket& sock);

        void setKeyOts(span<std::array<block, 2>> ots,
            std::optional<AltModPrf::KeyType> keyShare = {},
            span<block> recvOts = {});


        // return the key that is currently set.
        std::optional<AltModPrf::KeyType> getKey() const
        {
            return mKeyMultSender.mOptionalKeyShare;
        }

    };



    // on binary input x0 from the sender
    // on binary input x1 from the receiver
    // generate an F3 sharing of x0*x1. 
    // y0 will hold the lsb, and y1 will hold the msb.
    // The trit request size should be the bit length of x0,x1
    // This is the OT sender half of the protocol.
    macoro::task<> keyMultCorrectionSend(
        Request<TritOtSend>& request,
        oc::MatrixView<const oc::block> x,
        oc::Matrix<oc::block>& y0,
        oc::Matrix<oc::block>& y1,
        coproto::Socket& sock,
        bool debug);

    // on binary input x0 from the sender
    // on binary input x1 from the receiver
    // generate an F3 sharing of x0*x1. 
    // y0 will hold the lsb, and y1 will hold the msb.
    // The trit request size should be the bit length of x0,x1
    // This is the OT receiver half of the protocol.
    macoro::task<> keyMultCorrectionRecv(
        Request<TritOtRecv>& request,
        oc::MatrixView<const oc::block> x,
        oc::Matrix<oc::block>& y0,
        oc::Matrix<oc::block>& y1,
        coproto::Socket& sock,
        bool debug);
}
