#pragma once
#include "Defines.h"


#include <cryptoTools/Crypto/PRNG.h>
#include <gmp.h>



namespace secJoin
{
    namespace Paillier
    {


        class RNG 
        {
        public:
            gmp_randstate_t mState;
            oc::PRNG mPrng;
            
            RNG()
            {
                gmp_randinit_default(mState);
            }
            RNG(const RNG&) = delete;
            RNG(RNG&& o) 
                {
                gmp_randinit_default(mState);
                setSeed(o.mPrng.get());

                }


            //template<typename Seed,
            //    typename = typename std::enable_if<std::is_pod<Seed>::value>::type>
                RNG(oc::block seed)
            {
                gmp_randinit_default(mState);
                setSeed(seed);
            }


            //template<typename Seed>
            //typename std::enable_if<std::is_pod<Seed>::value>::type
            void setSeed(oc::block seed)
            {
                mPrng.SetSeed(seed);
                oc::block b = mPrng.get<oc::block>();

                mpz_t s;
                mpz_init(s);
                mpz_import(s, sizeof(oc::block), 1, 1, 0, 0, &b);
                gmp_randseed(mState, s);
                mpz_clear(s);
            }

            ~RNG()
            {
                gmp_randclear(mState);
            }
        };


    static_assert(std::is_pod<RNG>::value == false, "");
    }

}