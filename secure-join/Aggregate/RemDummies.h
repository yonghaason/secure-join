#pragma once

#include "secure-join/Util/Matrix.h"
#include "secure-join/CorGenerator/CorGenerator.h"
#include "secure-join/Perm/Permutation.h"
#include "secure-join/Perm/AltModComposedPerm.h"
#include "secure-join/Util/Util.h"

namespace secJoin {

    struct RemDummies
    {
        bool mCachePerm = false;

        ComposedPerm mPermutation;

        u64 mPartyIdx;
        AltModComposedPerm mPerm;
        static const PermOp mPermOp = PermOp::Inverse;

        void init(
                u64 rows,
                u64 bytesPerEntry,
                CorGenerator& ole,
                bool cachePerm = false);

        macoro::task<> applyRandPerm(
                BinMatrix &data,
                BinMatrix &out,
                PRNG &prng,
                coproto::Socket &sock);

        // Given the data Matrix and a offset
        // this function extracts the act flag byte
        // & then returns the revealed Act Flag
        macoro::task<> revealActFlag(
                BinMatrix& data,
                u64 actFlagOffSet,
                BinMatrix& out,
                coproto::Socket& sock);

        // Given the ActFlag, it returns the revealed Act Flag
        macoro::task<> revealActFlag(
                BinMatrix& actFlag,
                BinMatrix& out,
                coproto::Socket& sock);

        // Call this to remove Dummies for Average
        macoro::task<> remDummies(
                BinMatrix& data,
                BinMatrix& out,
                u64 actFlagOffSet,
                coproto::Socket& sock,
                PRNG &prng);

        // Call this to remove Dummies for Join & Where
        macoro::task<> remDummies(
                Table& in,
                Table& out,
                coproto::Socket& sock,
                PRNG &prng);
    };



}