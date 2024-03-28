#pragma once

//#include <macoro/task.h>
#include "secure-join/Util/Matrix.h"
#include "secure-join/CorGenerator/CorGenerator.h"
#include "secure-join/Perm/Permutation.h"
#include "secure-join/Perm/AltModComposedPerm.h"

namespace secJoin {

    struct RemDummies
    {
        Perm mRandPerm;

        AltModComposedPerm mPerm;

        void init(u64 rows, u64 bytesPerEntry, PRNG& prng, CorGenerator& ole, Perm& randPerm)
        {
            if(randPerm.size() > 0)
                mRandPerm = randPerm;
            else
                mRandPerm.randomize(rows, prng);

            mPerm.init(ole.partyIdx(), rows, bytesPerEntry, ole);
        }

        static macoro::task<> applyRandPerm(
                BinMatrix &data,
                BinMatrix &out,
                CorGenerator &ole,
                PRNG &prng,
                Perm &randPerm,
                coproto::Socket &sock,
                bool securePerm = true);

        static macoro::task<> revealActFlag(
                BinMatrix& actFlag,
                BinMatrix& out,
                coproto::Socket& sock,
                u64 partyIdx);

    };



}