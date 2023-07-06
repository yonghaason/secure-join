#pragma once
#include "macoro/macros.h"
#include "coproto/coproto.h"
#include "secure-join/Util/Matrix.h"
#include "secure-join/OleGenerator.h"

namespace secJoin
{

    // convert each bit of the binary secret sharing `in`
    // to integer Z_{2^outBitCount} arithmetic sharings.
    // Each row of `in` should have `inBitCount` bits.
    // out will therefore have dimension `in.rows()` rows 
    // and `inBitCount` columns.
    macoro::task<> bitInjection(
        u64 inBitCount,
        const oc::Matrix<u8>& in,
        u64 outBitCount,
        oc::Matrix<u32>& out,
        OleGenerator& gen,
        coproto::Socket& sock);

} // namespace secJoin
