
#pragma once
#include "secure-join/config.h"
#include "secure-join/Defines.h"
#include "secure-join/CorGenerator/CorGenerator.h"

#include "macoro/optional.h"
#include "cryptoTools/Crypto/PRNG.h"
#include "cryptoTools/Common/BitIterator.h"
#include "cryptoTools/Common/Matrix.h"
#include "cryptoTools/Common/Aligned.h"

#include "F2LinearCode.h"
#include "F3LinearCode.h"

namespace secJoin
{

    void mod3BitDecompostion(oc::MatrixView<u16> u, oc::MatrixView<oc::block> u0, oc::MatrixView<oc::block> u1);

    void compressB(
        oc::MatrixView<oc::block> v,
        span<oc::block> y
    );

    void sampleMod3(PRNG& prng, span<block> msb, span<block> lsb, oc::AlignedUnVector<u8>& b);
    void sampleMod3Lookup(PRNG& prng, span<block> msb, span<block> lsb);
    void sampleMod3Lookup3(PRNG& prng, span<block> msbVec, span<block> lsbVec);

    //
    class AltModPrf
    {
    public:
        static const std::array<oc::block, 128> mB;
        static const std::array<std::array<u8, 128>, 128> mBExpanded;

        static const F2LinearCode mBCode;
        static const F3AccPermCode mACode;
        static const std::array<F2LinearCode, 3> mGCode;

        // the bit count of the key
        static constexpr auto KeySize = 128 * 4;

        // the bit count of the middle layer
        static constexpr auto MidSize = 256;

        // the bit count of output layer
        static constexpr auto OutSize = 128;

        struct KeyType : std::array<oc::block, KeySize / 128>
        {
            KeyType operator^(const KeyType& o) const
            {
                KeyType r;
                for (u64 i = 0;i < size(); ++i)
                    r[i] = (*this)[i] ^ o[i];
                return r;
            }
        };

        KeyType mExpandedKey;

        AltModPrf() = default;
        AltModPrf(const AltModPrf&) = default;
        AltModPrf& operator=(const AltModPrf&) = default;
        AltModPrf(KeyType k)
        {
            setKey(k);
        }

        // set the key
        void setKey(KeyType k);

        KeyType getKey() const { return mExpandedKey; }

        // compute y = F(k,x)
        void eval(span<oc::block> x, span<oc::block> y);
        // compute y = F(k,x)
        oc::block eval(oc::block x);


        //static void mtxMultA(const std::array<u16, KeySize>& hj, block256m3& uj);

        //static oc::block compress(block256& w);

        //static oc::block compress(block256& w, const std::array<oc::block, 128>& B);

        static void expandInput(block x, KeyType& expanded)
        {
            expandInputLinear(x, expanded);
        }
        static void expandInput(span<block> x, oc::MatrixView<block> expanded)
        {
            expandInputLinear(x, expanded);
        }

        static void expandInputAes(block x, KeyType& expanded);
        static void expandInputAes(span<block> x, oc::MatrixView<block> expanded);
        static void expandInputLinear(block x, KeyType& expanded);
        static void expandInputLinear(span<block> x, oc::MatrixView<block> expanded);
        static void expandInputPermuteLinear(span<block> x, oc::MatrixView<block> expanded);
        static void initExpandInputPermuteLinear();
    };

    inline std::ostream& operator<< (std::ostream& o, AltModPrf::KeyType k)
    {
        o << k[3]
            << "." << k[2]
            << "." << k[1]
            << "." << k[0];
        return o;
    }
    enum class AltModPrfKeyMode
    {
        SenderOnly,
        Shared
    };

    enum class AltModPrfInputMode
    {
        ReceiverOnly,
        Shared
    };
}