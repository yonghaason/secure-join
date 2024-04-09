#pragma once
#include "cryptoTools/Common/Defines.h"
#include "cryptoTools/Common/block.h"
#include "cryptoTools/Crypto/PRNG.h"
#include <iostream>
#include <sstream>
#include <iomanip>
#include "Paillier/Defines.h"
#include "macoro/result.h"

#ifndef SECJOIN_ENABLE_LOGGING
#define SECJOIN_ENABLE_LOGGING false
#endif


namespace secJoin
{
    const char CSV_COL_DELIM = ';';
    const std::string STRING_META_TYPE = "STRING";
    const std::string ROWS_META_TYPE = "Rows";
    const std::string COLS_META_TYPE = "Cols";
    const std::string TYPE_OF_FILE = "Type";
    const std::string TEXT_FILE_TYPE = "Text";
    const std::string BINARY_FILE_TYPE = "Binary";
    const u64 BATCH_READ_ENTRIES = 10000;
    using block = oc::block;
    using PRNG = oc::PRNG;

    const std::string WHBUNDLE_COL_TYPE = "Col";
    const std::string WHBUNDLE_NUM_TYPE = "Number";
    const std::string WHBUNDLE_STRING_TYPE = "String";

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

    inline std::string hex(oc::span<const u8> d)
    {
        std::stringstream ss;
        // for (u64 i = d.size() - 1; i < d.size(); --i)
        for (u64 i = 0; i < d.size(); i++)
            ss << std::hex << std::setw(2) << std::setfill('0') << int(d[i]);
        return ss.str();
    }
    inline std::string hex(u8 const* d, u64 s)
    {
        return hex(span<const u8>(d, s));
    }

    template<typename T>
    std::string whatError(macoro::result<T>& r)
    {
        try {
            std::rethrow_exception(r.error());
        }
        catch (std::exception& e)
        {
            return e.what();
        }
    }


}