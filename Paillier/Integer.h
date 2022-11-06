#pragma once

#include <cryptoTools/Common/Defines.h>
#include <string>
#include <iostream>
#include "Defines.h"
#include "RNG.h"

#ifdef BIO_ENABLE_RELIC
#ifdef ERROR
#undef ERROR
#endif
extern "C" {
    #include "relic.h"
    #include "relic_err.h"
}
#else
#endif
#include <gmp.h>


namespace secJoin
{

    namespace Paillier
    {



        template<typename value_type>
        class IntBase
        {
        public:

            IntBase();
            IntBase(const IntBase&);
            IntBase(IntBase&&);

            IntBase& operator=(const IntBase& val);
            IntBase& operator=(IntBase&& val);

            ~IntBase();

            IntBase(const i64&);
            IntBase(RNG& rand, const u64&bitCount);

            value_type mVal;

            void randomize(RNG& rand, u64 bitCount);
            void randomize(RNG& rand, const IntBase& mod);
            bool isPrime(u64 statisticalSecParam = 40) const;
            void randomPrime(RNG& rand, u64 bitCount, u64 statisticalSecParam = 40);

            i64 cmp(const IntBase&) const;
            i64 cmp(const i64&) const;
            bool operator==(const IntBase& v) const { return cmp(v) == 0; }
            bool operator!=(const IntBase& v) const { return cmp(v) != 0; }
            bool operator>=(const IntBase& v) const { return cmp(v) >= 0; }
            bool operator<=(const IntBase& v) const { return cmp(v) <= 0; }
            bool operator>(const IntBase& v) const { return  cmp(v) > 0; }
            bool operator<(const IntBase& v) const { return  cmp(v) < 0; }


            void fromBytes(span<u8> data);
            void toBytes(span<u8> data, bool signCheck = true) const;
            u64 sizeBytes() const;
            u8 getBit(u64 idx)const;
            u64 sizeBits()const;

            void copy(const IntBase&);
            void move(IntBase&&);

            IntBase& operator=(const std::string& v);
            operator std::string() const;

            IntBase& operator=(const i64& v);
            explicit operator i64() const;

            // arithmetics


            void mul(const IntBase& lhs, const IntBase& rhs);
            void mul(const IntBase& lhs, const u32& rhs);
            void add(const IntBase& lhs, const IntBase& rhs);
            void add(const IntBase& lhs, const u32& rhs);
            void sub(const IntBase& lhs, const IntBase& rhs);
            void sub(const IntBase& lhs, const u32& rhs);
            void pow(const IntBase& lhs, const IntBase& rhs, const IntBase& mod);
            void pow(const IntBase& lhs, const u32& rhs, const IntBase& mod);

            void mod(const IntBase& lhs, const IntBase& mod);
            void div(const IntBase& lhs, const IntBase& rhs);
            void div(const IntBase& lhs, const IntBase& rhs, IntBase& remainder);
            void inv(const IntBase& lhs, const IntBase& rhs);
            void lcm(const IntBase& lhs, const IntBase& rhs);

            IntBase operator*(const IntBase& rhs) const;
            IntBase& operator*=(const IntBase& rhs);

            IntBase operator+(const IntBase& rhs) const;
            IntBase& operator+=(const IntBase& rhs);

            IntBase operator-(const IntBase& rhs) const;
            IntBase& operator-=(const IntBase& rhs);

            IntBase operator/(const IntBase& rhs) const;
            IntBase& operator/=(const IntBase& rhs);

            IntBase operator%(const IntBase& rhs) const;
            IntBase& operator%=(const IntBase& rhs);

            template<typename T>
            bool operator==(const IntBase<T>& v) const
            {
                return 
                    static_cast<std::string>(*this) ==
                    static_cast<std::string>(v);
            }

            template<typename T>
            bool operator!=(const IntBase<T>& v) const
            {
                return 
                    static_cast<std::string>(*this) !=
                    static_cast<std::string>(v);
            }

            template<typename T>
            IntBase& operator=(const IntBase<T>& v) 
            {
                *this = static_cast<std::string>(v);
                return *this;
            }


        private:
            void init();
            operator value_type&() { return mVal; }
            operator const value_type&() const { return mVal; }

        };


        //using Integer = IntBase<bn_t>;
        using Integer = IntBase<mpz_t>;
#ifdef BIO_ENABLE_RELIC
#else
#endif


        template<typename T>
        std::ostream& operator<<(std::ostream& o, const IntBase<T>& v)
        {
            return o << static_cast<std::string>(v);
        }



        template<typename T>
        std::istream& operator>>(std::istream& i, IntBase<T>& v)
        {
            std::string buff;
            i >> buff;
            v = buff;
            return i;
        }

    }
}