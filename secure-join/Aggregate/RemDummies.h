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
        PermOp mPermOp = PermOp::Inverse;

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

        macoro::task<> revealActFlag(
                BinMatrix& actFlag,
                BinMatrix& out,
                coproto::Socket& sock);

        macoro::task<> remDummies(
                BinMatrix& data,
                BinMatrix& out,
                u64 actFlagOffSet,
                coproto::Socket& sock,
                PRNG &prng);

    };



}