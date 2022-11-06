#pragma once

#include <gmp.h>
#include <cryptoTools/Common/Defines.h>
#include <string>
#include <iostream>
#include "Integer.h"
#include "RNG.h"

namespace secJoin
{

    namespace Paillier
    {
        class Plaintext
        {
        public:
            Plaintext() = default;
            Plaintext(const Plaintext&) = default;
            Plaintext(Plaintext&&) = default;

            Plaintext& operator=(const Plaintext& val) = default;
            Plaintext& operator=(Plaintext&& val) = default;

            ~Plaintext() = default;

            Plaintext(const u32&);
            Plaintext(Integer& mod);
            Plaintext(RNG&rand, Integer& mod);
            Plaintext(const Plaintext&, Integer& mod);


            Integer mVal;
            Integer* mModulus = nullptr;

            void setValue(Integer val);
            void setModulus(Integer& mod);

            bool operator==(const Plaintext& v) const { return mVal == v.mVal; }
            bool operator!=(const Plaintext& v) const { return !(*this == v); }


            void randomize(RNG& rand);

            // IO operators

            void fromBytes(span<u8> bytes);
            void toBytes(span<u8> bytes) const;
            u64 sizeBytes() const;

            Plaintext& operator=(const std::string& v);
            operator std::string() const;

            Plaintext& operator=(u64 v);
            operator u64() const;
            operator i64() const;

            // arithmetics

            Plaintext operator*(const Plaintext& rhs) const;
            Plaintext& operator*=(const Plaintext& rhs);

            Plaintext operator+(const Plaintext& rhs) const;
            Plaintext& operator+=(const Plaintext& rhs);


            Plaintext operator-(const Plaintext& rhs) const;
            Plaintext& operator-=(const Plaintext& rhs);


            void reduce();
        };

        inline std::ostream& operator<<(std::ostream& o, const Plaintext&c)
        {
            return o << static_cast<std::string>(c);
        }
    }
}