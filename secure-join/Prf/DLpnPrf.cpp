

#include "DLpnPrf.h"


namespace secJoin
{
    const std::array<block256, 128> DLpnPrf::mB = oc::PRNG(oc::block(2134, 5437)).get<std::array<block256, 128>>();
    const std::array<block256, 128> DLpnPrf::mBShuffled = []() {
    
        std::array<block256, 128> shuffled;
        for (u64 i = 0; i < shuffled.size(); ++i)
        {
            auto iter0 = oc::BitIterator((u8*)&mB[i].mData[0]);
            auto iter1 = oc::BitIterator((u8*)&mB[i].mData[1]);
            auto dest = oc::BitIterator((u8*)&shuffled[i]);
            for (u64 j = 0; j < 128; ++j)
            {
                *dest++ = *iter0++;
                *dest++ = *iter1++;
            }
        }
        return shuffled;
    }();

}