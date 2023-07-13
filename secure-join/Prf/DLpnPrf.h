#pragma once
#include "secure-join/config.h"
#include "secure-join/Defines.h"
#include "secure-join/Prf/DarkMatter22Prf.h"
#include "secure-join/OleGenerator.h"

#include "cryptoTools/Common/BitIterator.h"
#include <bitset>
#include "libOTe/Tools/Tools.h"

namespace secJoin
{
    
    template<typename T>
    int bit(T& x, u64 i)
    {
        return  *oc::BitIterator((u8*)&x, i);
    }
    template<typename T>
    int bit2(T& x, u64 i)
    {
        return  *oc::BitIterator((u8*)&x, i * 2) + 2 * *oc::BitIterator((u8*)&x, i * 2 + 1);;
    }
    void mod3BitDecompostion(oc::MatrixView<u16> u, oc::MatrixView<oc::block> u0, oc::MatrixView<oc::block> u1);

    template<int keySize>
    void compressH2(
        oc::Matrix<u16>&& mH,
        oc::Matrix<u16>& mU
    );

    void compressB(
        oc::MatrixView<oc::block> v,
        span<oc::block> y
    );

    class DLpnPrf
    {
    public:
        static const std::array<block256, 128> mB, mBShuffled;
        static constexpr int KeySize = 128;

        std::array<oc::block, KeySize / 128> mKey;

        void setKey(oc::block k);

        void compressH(const std::array<u16, KeySize>& hj, block256m3& uj);

        oc::block eval(oc::block x);

        static oc::block compress(block256& w);

        static oc::block shuffledCompress(block256& w);

        static oc::block compress(block256& w, const std::array<block256, 128>& B);
    };

    class DLpnPrfSender : public oc::TimerAdapter
    {
    public:
        static constexpr auto mDebug = false;
        static constexpr auto StepSize = 32;
        static constexpr auto n = DLpnPrf::KeySize;
        static constexpr auto m = 256;
        static constexpr auto t = 128;
        static constexpr int mNumOlePer = (m * 2) / 128;

        std::vector<oc::PRNG> mKeyOTs;
        DLpnPrf mPrf;
        oc::Matrix<u16> mU;
        oc::Matrix<u16> mH;
        oc::Matrix<oc::block> mV;
        bool mIsKeyOTsSet = false;
        bool mIsKeySet = false;

        u64 mPrintI = -1;
        u64 mPrintJ = -1;


        DLpnPrfSender() = default;
        DLpnPrfSender(const DLpnPrfSender&) = default;
        DLpnPrfSender(DLpnPrfSender&&) noexcept = default;
        DLpnPrfSender& operator=(const DLpnPrfSender&) = default;
        DLpnPrfSender& operator=(DLpnPrfSender&&) noexcept = default;

        bool hasKeyOts() const {return mIsKeyOTsSet;}

        macoro::task<> genKeyOts(OleGenerator& ole);

        void setKeyOts(span<oc::block> ots);

        void setKey(oc::block k);

        coproto::task<> evaluate(
            span<oc::block> y,
            coproto::Socket& sock,
            oc::PRNG& _,
            OleGenerator& gen);

        macoro::task<> mod2Compress(
            oc::MatrixView<u16> u,
            span<oc::block> out,
            coproto::Socket& sock,
            Request<BinOle>& ole);

        macoro::task<> mod2(
            oc::MatrixView<oc::block> u0,
            oc::MatrixView<oc::block> u1,
            oc::MatrixView<oc::block> out,
            coproto::Socket& sock,
            Request<BinOle>& ole);


    };



    class DLpnPrfReceiver : public oc::TimerAdapter
    {
    public:
        static constexpr auto mDebug = DLpnPrfSender::mDebug;
        static constexpr auto StepSize = 32;
        static constexpr auto n = DLpnPrf::KeySize;
        static constexpr auto m = 256;
        static constexpr auto t = 128;
        static constexpr int mNumOlePer = (m * 2) / 128;

        std::vector<std::array<oc::PRNG, 2>> mKeyOTs;
        oc::Matrix<u16> mU;
        oc::Matrix<u16> mH;
        oc::Matrix<oc::block> mV;
        bool mIsKeyOTsSet = false;
        DLpnPrf mPrf;

        u64 mPrintI = -1;
        u64 mPrintJ = -1;

        DLpnPrfReceiver() = default;
        DLpnPrfReceiver(const DLpnPrfReceiver&) = default;
        DLpnPrfReceiver(DLpnPrfReceiver&&)  = default;
        DLpnPrfReceiver& operator=(const DLpnPrfReceiver&) = default;
        DLpnPrfReceiver& operator=(DLpnPrfReceiver&&) noexcept = default;

        bool hasKeyOts() const {return mIsKeyOTsSet;}

        macoro::task<> genKeyOts(OleGenerator& ole);

        void setKeyOts(span<std::array<oc::block, 2>> ots);

        coproto::task<> evaluate(
            span<oc::block> x,
            span<oc::block> y,
            coproto::Socket& sock,
            oc::PRNG&,
            OleGenerator& gen);


        macoro::task<> mod2Compress(
            oc::MatrixView<u16> u,
            span<oc::block> out,
            coproto::Socket& sock,
            Request<BinOle>& ole);

        macoro::task<> mod2(
            //oc::MatrixView<u16> u,
            oc::MatrixView<oc::block> u0,
            oc::MatrixView<oc::block> u1,
            oc::MatrixView<oc::block> out,
            coproto::Socket& sock,
            Request<BinOle>& ole);


    };
}
