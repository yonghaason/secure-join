#pragma once
#include "cryptoTools/Common/Defines.h"


#include "Paillier/Defines.h"
namespace secJoin
{
    using ::memcpy;

    template<typename D, typename S>
    OC_FORCEINLINE void memcpy(span<D> dst, span<S> src)
    {
        assert(dst.size_bytes() == src.size_bytes());
        ::memcpy(dst.data(), src.data(), dst.size_bytes());
    }

    template<typename D, typename S>
    OC_FORCEINLINE void memcpyMin(span<D> dst, span<S> src)
    {
        ::memcpy(dst.data(), src.data(), std::min(src.size_bytes(), dst.size_bytes()));
    }
    using ::memset;

    template<typename D>
    OC_FORCEINLINE void memset(span<D> dst, char v)
    {
        ::memset(dst.data(), v, dst.size_bytes());
    }

}