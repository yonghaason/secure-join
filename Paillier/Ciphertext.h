#pragma once
#include <gmp.h>
#include <cryptoTools/Common/Defines.h>
#include <string>
#include <iostream>
#include "Integer.h"

namespace secJoin
{

    namespace Paillier
    {
        class PublicKey;
        class Plaintext;

        class Ciphertext
        {
        public:

            Ciphertext() = default;
            Ciphertext(const Ciphertext&) = default;
            Ciphertext(Ciphertext&&) = default;

            Ciphertext& operator=(const Ciphertext& s) = default;
            Ciphertext& operator=(Ciphertext&& s) = default;

            ~Ciphertext() = default;

            Ciphertext(PublicKey& pk);

            Integer mVal;
            PublicKey* mPk = nullptr;

            void add(const Ciphertext& lhs, const Ciphertext& rhs);
            void add(const Ciphertext& lhs, const Plaintext& rhs);
            void mul(const Ciphertext& lhs, const Plaintext& rhs);
            void mul(const Ciphertext& lhs, const u32& rhs);

            Ciphertext operator*(const Plaintext& rhs) const;
            Ciphertext& operator*=(const Plaintext& rhs);

            Ciphertext operator*(const u32) const;
            Ciphertext& operator*=(const u32& rhs);

            Ciphertext operator+(const Ciphertext& rhs) const;
            Ciphertext& operator+=(const Ciphertext& rhs);

            Ciphertext operator+(const Plaintext& rhs) const;
            Ciphertext& operator+=(const Plaintext& rhs);

            // IO operators

            void fromBytes(span<u8> bytes, PublicKey& pk);
            void toBytes(span<u8> bytes) const;
            u64 sizeBytes() const;

            Ciphertext& operator=(const std::string& s);
            operator std::string() const;

            bool operator==(const Ciphertext& s)const;
            bool operator!=(const Ciphertext& s)const;


            //operator const Integer&() const { return mVal; }
            //operator Integer&() { return mVal; }

        };

        inline std::ostream& operator<<(std::ostream& o, const Ciphertext&c)
        {
            return o << static_cast<std::string>(c);
        }

    }
}