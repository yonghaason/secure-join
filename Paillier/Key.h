#pragma once

#include <cryptoTools/Common/Defines.h>
#include "Plaintext.h"
#include "Ciphertext.h"
#include "Integer.h"
#include "RNG.h"
#include <cryptoTools/Crypto/PRNG.h>

namespace secJoin
{

    namespace Paillier
    {


        class PublicKey
        {
        public:

            PublicKey() = default;
            PublicKey(const PublicKey&) = default;
            PublicKey(PublicKey&&) = default;

            PublicKey& operator=(const PublicKey&) = default;
            PublicKey& operator=(PublicKey&&) = default;

            ~PublicKey() = default;

            Ciphertext encNoRand(const Plaintext& ptxt);
            void encNoRand(const Plaintext& ptxt, Ciphertext& ctxt);



            Ciphertext enc(const Plaintext& ptxt, RNG& rand);
            void enc(const Plaintext& ptxt, RNG& rand, Ciphertext& ctxt);

            void fromBytes(span<u8> bytes);
            void toBytes(span<u8> bytes) const;
            u64 sizeBytes() const;

            bool operator==(const PublicKey& v)const;
            bool operator!=(const PublicKey& v)const;


            u64 ciphertextByteSize();
            u64 plaintextByteSize();

            // The bit count of the primes, i.e. mBitCount = log2(p) = log2(q);
            u64 mBitCount = 0;

            // The public modulus, i.e. mN = p * q
            Integer mN;

            // The square of the public modulus. 
            Integer mNSquared;
            // The public modulus plus one.
            Integer mNPlusOne;


            void computeCache();

        };


        inline std::ostream& operator<<(std::ostream& o, const PublicKey& key)
        {
            o << key.mBitCount << std::endl;
            o << key.mN << std::endl;
            return o;
        }


        inline std::istream& operator>>(std::istream& i, PublicKey& key)
        {
            i >> key.mBitCount;
            i >> key.mN;
            key.computeCache();
            return i;
        }



        class PrivateKey
        {
        public:

            PrivateKey() = default;
            PrivateKey(const PrivateKey&) = default;
            PrivateKey(PrivateKey&&) = default;

            PrivateKey& operator=(const PrivateKey&) = default;
            PrivateKey& operator=(PrivateKey&&) = default;

            ~PrivateKey() = default;

            PrivateKey(u64 bitCount, RNG& prng);

            void keyGen(u64 bitCount, RNG& prng);


            void fromBytes(span<u8> bytes);
            void toBytes(span<u8> bytes) const;
            u64 sizeBytes() const;


            bool operator==(const PrivateKey& v)const;
            bool operator!=(const PrivateKey& v)const;


            Plaintext dec(const Ciphertext& ctxt);
            void dec(const Ciphertext& ctxt, Plaintext& ptxt);






            PublicKey mPublicKey;

            // The secret key, i.e. least common multiple of p-1, q-1
            Integer mLambda;


            Integer mX;

            void computeCache();
        };

        inline std::ostream& operator<<(std::ostream& o, const PrivateKey& key)
        {
            o << key.mPublicKey << std::endl;
            o << key.mLambda << std::endl;
            o << key.mX << std::endl;
            return o;
        }


        inline std::istream& operator>>(std::istream& i, PrivateKey& key)
        {
            i >> key.mPublicKey;
            i >> key.mLambda;
            i >> key.mX;
            return i;
        }

    }
}