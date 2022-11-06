#include "Integer.h"
#include "Key.h"
#include <cstring>
#include <algorithm> 
#include <cctype>
#include <locale>
// #include "InnerProd/util.h"

namespace secJoin
{

    namespace Paillier
    {

        namespace
        {
            // trim from end (in place)
            static inline void rtrim(std::string &s) {
                s.erase(std::find_if(s.rbegin(), s.rend(), [](int ch) {
                    return !(std::isspace(ch) || ch == 0);
                }).base(), s.end());
            }

        }

        void byteReverse(span<u8> bytes)
        {
            for (u64 i = 0, j = bytes.size() - 1; i < j; ++i, --j)
            {
                std::swap(bytes[i], bytes[j]);
            }
        }
        
        template<typename T>
        IntBase<T>::IntBase()
        {
            init();
        }

        template<typename T>
        IntBase<T>::IntBase(const IntBase &v)
        {
            init();
            copy(v);
        }

        template<typename T>
        IntBase<T>::IntBase(IntBase &&v)
        {
            init();
            move(std::move(v));
        }

        template<typename T>
        IntBase<T>::IntBase(const i64 &v)
        {
            init();
            *this = v;
        }

        template<typename T>
        IntBase<T>::IntBase(RNG & rand, const u64 &bitCount)
        {
            init();
            randomize(rand, bitCount);
        }

        template<typename T>
        IntBase<T> IntBase<T>::operator*(const IntBase & rhs) const
        {
            IntBase r;
            r.mul(*this, rhs);
            return r;
        }

        template<typename T>
        IntBase<T>& IntBase<T>::operator*=(const IntBase & rhs)
        {
            mul(*this, rhs);
            return *this;
        }

        template<typename T>
        IntBase<T> IntBase<T>::operator+(const IntBase & rhs) const
        {
            IntBase r;
            r.add(*this, rhs);
            return r;
        }

        template<typename T>
        IntBase<T>& IntBase<T>::operator+=(const IntBase & rhs)
        {
            add(*this, rhs);
            return *this;
        }

        template<typename T>
        IntBase<T> IntBase<T>::operator-(const IntBase & rhs) const
        {
            IntBase r;
            r.sub(*this, rhs);
            return r;
        }

        template<typename T>
        IntBase<T>& IntBase<T>::operator-=(const IntBase & rhs)
        {
            sub(*this, rhs);
            return *this;
        }


        template<typename T>
        IntBase<T> IntBase<T>::operator/(const IntBase & rhs) const
        {
            IntBase r;
            r.div(*this, rhs);
            return r;
        }

        template<typename T>
        IntBase<T>& IntBase<T>::operator/=(const IntBase & rhs)
        {
            div(*this, rhs);
            return *this;
        }

        template<typename T>
        IntBase<T> IntBase<T>::operator%(const IntBase & rhs) const
        {
            IntBase r;
            r.add(*this, rhs);
            return r;
        }

        template<typename T>
        IntBase<T>& IntBase<T>::operator%=(const IntBase & rhs)
        {
            add(*this, rhs);
            return *this;
        }

        template<typename T>
        IntBase<T>& IntBase<T>::operator=(const IntBase & val)
        {
            copy(val);
            return *this;
        }

        template<typename T>
        IntBase<T>& IntBase<T>::operator=(IntBase && val)
        {
            *this = 0;
            move(std::move(val));
            return *this;
        }

        template<typename T>
        IntBase<T>& IntBase<T>::operator=(const i64& v)
        {
            u64 mag;
            bool neg = false;
            if (v < 0)
            {
                neg = true;
                mag = -v;
            }
            else
                mag = v;

            auto& buff = *(std::array<u8, sizeof(u64)>*)&mag;
            byteReverse(buff);
            fromBytes(buff);

            if(neg)
                mpz_neg(mVal, mVal);

            return *this;
        }

        template<typename T>
        IntBase<T>::operator i64() const
        {
            i64 v;
            auto& buff = *(std::array<u8, sizeof(u64)>*)&v;

            toBytes(buff, false);
            byteReverse(buff);

            if (mpz_sgn(mVal) == -1)
            {
                v = -v;
            }
            return v;
        }


#ifdef BIO_ENABLE_RELIC

        template<>
        IntBase<bn_t>::~IntBase()
        {
            bn_free(mVal);
        }


        template<>
        void IntBase<bn_t>::randomize(RNG & rand, const IntBase & mod)
        {
            bn_rand_mod(*this, (bn_st*)mod.mVal);
        }

        template<>
        void IntBase<bn_t>::randomize(RNG & prng, u64 bitCount)
        {
            bn_rand(*this, BN_POS, bitCount);
            //auto size = (bitCount + 7) / 8;

            //std::array<u8, BN_SIZE * sizeof(dig_t)> buff;
            //if (size > buff.size())
            //    throw std::runtime_error("bitCount too large, " LOCATION);

            //prng.get(buff.data(), size);

            //auto off = bitCount & 7;
            //auto idx = bitCount >> 3;
            //if (off)
            //{
            //    u8 mask = (1 << off) - 1;
            //    buff[idx] &= mask;
            //    ++idx;
            //}

            //auto rem = buff.size() - idx;
            //if(rem)
            //    memset(buff.data() + idx, 0, rem);

            //fromBytes(buff);

        }

        template<>
        u64 IntBase<bn_t>::sizeBits() const
        {
            return bn_bits(*this);
        }

        template<>
        void IntBase<bn_t>::randomPrime(RNG & rand, u64 bitCount, u64 statisticalSecParam)
        {
            do bn_gen_prime_basic(*this, bitCount);
            while (sizeBits() != bitCount);
        }

        template<>
        bool IntBase<bn_t>::isPrime(u64 statisticalSecParam) const
        {
            return bn_is_prime(*this);
        }

        template<>
        u8 IntBase<bn_t>::getBit(u64 idx) const
        {
            return bn_get_bit(*this, idx);
        }

        template<>
        void IntBase<bn_t>::fromBytes(span<u8> data)
        {
            bn_read_bin(*this, data.data(), data.size());
            if (GSL_UNLIKELY(err_get_code()))
                throw std::runtime_error("Relic read error " LOCATION);
        }

        template<>
        void IntBase<bn_t>::toBytes(span<u8> data) const
        {
            bn_write_bin(data.data(), data.size(), *this);
            if (GSL_UNLIKELY(err_get_code()))
            {
                //if (sizeBytes() > data.size())
                //{
                //    std::cout << "buff too small " << data.size() << " < " << sizeBytes() << std::endl;
                //}
                throw std::runtime_error("Relic read error " LOCATION);
            }
        }

        template<>
        u64 IntBase<bn_t>::sizeBytes() const
        {
            return bn_size_bin(*this);
        }

        template<>
        IntBase<bn_t>& IntBase<bn_t>::operator=(const std::string & s)
        {
            auto radix = 16;
            auto len = s.size();
            bn_read_str(*this, s.c_str(), len, radix);
            if (GSL_UNLIKELY(err_get_code()))
                throw std::runtime_error("Relic read error " LOCATION);
            return *this;
        }

        template<>
        IntBase<bn_t>::operator std::string() const
        {
            auto radix = 16;
            auto size = bn_size_str(*this, radix);
            std::string s(size, 0);
            bn_write_str(&s[0], size, *this, radix);

            rtrim(s);
            return s;
        }

        template<>
        void IntBase<bn_t>::mul(const IntBase & lhs, const IntBase & rhs)
        {
            bn_mul(*this, lhs, rhs);
        }

        template<>
        void IntBase<bn_t>::mul(const IntBase & lhs, const u32 & rhs)
        {
            bn_mul_dig(*this, lhs, rhs);
        }

        template<>
        void IntBase<bn_t>::add(const IntBase & lhs, const IntBase & rhs)
        {
            bn_add(*this, lhs, rhs);
        }

        template<>
        void IntBase<bn_t>::add(const IntBase & lhs, const u32 & rhs)
        {
            bn_add_dig(*this, lhs, rhs);
        }

        template<>
        void IntBase<bn_t>::sub(const IntBase & lhs, const IntBase & rhs)
        {
            bn_sub(*this, lhs, rhs);
        }

        template<>
        void IntBase<bn_t>::sub(const IntBase & lhs, const u32 & rhs)
        {
            bn_sub_dig(*this, lhs, rhs);
        }

        template<>
        void IntBase<bn_t>::pow(const IntBase & lhs, const IntBase & rhs, const IntBase& mod)
        {
            //bn_mxp_slide(*this, lhs, rhs, mod);
            bn_mxp(*this, lhs, rhs, mod);
        }

        template<>
        void IntBase<bn_t>::pow(const IntBase & lhs, const u32 & rhs, const IntBase & mod)
        {
            bn_mxp_dig(*this, lhs, rhs, mod);
        }

        template<>
        void IntBase<bn_t>::mod(const IntBase & lhs, const IntBase & mod)
        {
            bn_mod(mVal, lhs, mod);
            //bn_mod_barrt(*this, lhs, mod);
        }

        template<>
        void IntBase<bn_t>::div(const IntBase & lhs, const IntBase & rhs)
        {
            bn_div(mVal, lhs, rhs);
        }

        template<>
        void IntBase<bn_t>::inv(const IntBase & lhs, const IntBase & rhs)
        {
            IntBase y, c;

            bn_gcd_ext_basic(c, *this, y, lhs, rhs);

            if (GSL_UNLIKELY(err_get_code()))
                throw std::runtime_error("Relic inverse error " LOCATION);

            mod(*this, rhs);
        }

        template<>
        void IntBase<bn_t>::lcm(const IntBase & lhs, const IntBase & rhs)
        {
            bn_lcm(*this, lhs, rhs);
        }


        template<>
        void IntBase<bn_t>::init()
        {
            if (core_get() == nullptr)
                core_init();

            bn_new(*this);
        }

        template<>
        void IntBase<bn_t>::copy(const IntBase& v)
        {
            bn_copy(*this, v);
        }

        template<>
        void IntBase<bn_t>::move(IntBase&& v)
        {
            bn_copy(*this, v);
        }


        template<>
        i64 IntBase<bn_t>::cmp(const IntBase& rhs) const
        {
            return bn_cmp(*this, rhs);
        }
        template class IntBase<bn_t>;
#endif

        template<>
        IntBase<mpz_t>::~IntBase()
        {
            mpz_clear(mVal);
        }

        template<>
        i64 IntBase<mpz_t>::cmp(const IntBase& rhs) const
        {
            return mpz_cmp(*this, rhs);
        }

        template<>
        i64 IntBase<mpz_t>::cmp(const i64& rhs) const
        {
            IntBase temp(rhs);
            return cmp(temp);
        }

        template<>
        void IntBase<mpz_t>::init()
        {
            mpz_init(*this);
        }

        template<>
        void IntBase<mpz_t>::copy(const IntBase& v)
        {
            mpz_set(*this, v);
        }

        template<>
        void IntBase<mpz_t>::move(IntBase&& v)
        {
            mpz_swap(*this, v);
        }

        template<>
        void IntBase<mpz_t>::randomize(RNG & rand, u64 bitCount)
        {
            mpz_urandomb(mVal, rand.mState, bitCount);
        }


        template<>
        void IntBase<mpz_t>::randomize(RNG & rand, const IntBase & mod)
        {
            mpz_urandomm(*this, rand.mState, mod);
        }

        template<>
        u64 IntBase<mpz_t>::sizeBits() const
        {
            return mpz_sizeinbase(*this, 2);
        }

        template<>
        u64 IntBase<mpz_t>::sizeBytes() const
        {
            return (sizeBits() + 7) / 8;
        }

        template<>
        bool IntBase<mpz_t>::isPrime(u64 statisticalSecParam) const
        {
            return !!mpz_probab_prime_p(mVal, statisticalSecParam / 2);
        }

        template<>
        void IntBase<mpz_t>::randomPrime(RNG & rand, u64 bitCount, u64 statisticalSecParam)
        {
            do randomize(rand, bitCount);
            while (sizeBits() != bitCount || isPrime(statisticalSecParam) == false);
        }

        template<>
        u8 IntBase<mpz_t>::getBit(u64 idx) const
        {
            return mpz_tstbit(mVal, idx);
        }



        template<>
        void IntBase<mpz_t>::IntBase::fromBytes(span<u8> data)
        {
            mpz_import(*this, data.size(), 1, 1, 0, 0, data.data());
        }

        template<>
        void IntBase<mpz_t>::IntBase::toBytes(span<u8> data, bool signCheck) const
        {
            if (signCheck)
            {
                bool neg = mpz_sgn(this->mVal) == -1;
                if (neg)
                    throw std::runtime_error("Can not write negative number. Handle this on your own and call toBytes(..., false); " LOCATION);
            }

            auto size = sizeBytes();
            auto size2 = mpz_size(*this);
            if (size > data.size())
                throw std::runtime_error("not enough space to write the value. " LOCATION);
            else
            {
                auto rem{ data.size() - size };

                TODO("Decide how to correctly handle the case that this is zero and export writes zero bytes...");
                if (size2 == 0)
                    ++rem;

                if (rem)
                    memset(data.data(), 0, rem);
                mpz_export(data.data() + rem, nullptr, 1, 1, 0, 0, *this);
            }
        }


        template<>
        IntBase<mpz_t>& IntBase<mpz_t>::operator=(const std::string & s)
        {
            const auto base{ 16 };
            if (mpz_set_str(*this, s.c_str(), base))
                throw std::runtime_error("IntBase::from_hex, bad string. " LOCATION);

            return *this;
        }

        template<>
        IntBase<mpz_t>::operator std::string() const
        {
            const auto base{ 16 };
            u64 size = mpz_sizeinbase(*this, base) + 2;
            std::string s(size, 0);
            mpz_get_str((char*)s.c_str(), base, *this);

            rtrim(s);
            return s;
        }



        template<>
        void IntBase<mpz_t>::IntBase::mul(const IntBase & lhs, const IntBase & rhs)
        {
            mpz_mul(*this, lhs, rhs);
        }

        template<>
        void IntBase<mpz_t>::IntBase::mul(const IntBase & lhs, const u32 & rhs)
        {
            mpz_mul_ui(mVal, lhs, rhs);
        }

        template<>
        void IntBase<mpz_t>::IntBase::add(const IntBase & lhs, const IntBase & rhs)
        {
            mpz_add(*this, lhs, rhs);
        }

        template<>
        void IntBase<mpz_t>::IntBase::add(const IntBase & lhs, const u32 & rhs)
        {
            mpz_add_ui(*this, lhs, rhs);
        }

        template<>
        void IntBase<mpz_t>::IntBase::sub(const IntBase & lhs, const IntBase & rhs)
        {
            mpz_sub(*this, lhs, rhs);
        }

        template<>
        void IntBase<mpz_t>::IntBase::sub(const IntBase & lhs, const u32 & rhs)
        {
            mpz_sub_ui(*this, lhs, rhs);
        }

        template<>
        void IntBase<mpz_t>::IntBase::pow(const IntBase & lhs, const IntBase & rhs, const IntBase& mod)
        {
            mpz_powm(*this, lhs, rhs, mod);
        }

        template<>
        void IntBase<mpz_t>::IntBase::pow(const IntBase & lhs, const u32 & rhs, const IntBase & mod)
        {
            mpz_powm_ui(*this, lhs, rhs, mod);
        }

        template<>
        void IntBase<mpz_t>::IntBase::mod(const IntBase & lhs, const IntBase & mod)
        {
            mpz_mod(mVal, lhs, mod);
        }

        template<>
        void IntBase<mpz_t>::IntBase::div(const IntBase & lhs, const IntBase & rhs)
        {
            mpz_div(mVal, lhs, rhs);
        }


        template<>
        void IntBase<mpz_t>::IntBase::div(const IntBase & lhs, const IntBase & rhs, IntBase & rem)
        {
            mpz_fdiv_qr(mVal, rem, lhs, rhs);
        }


        template<>
        void IntBase<mpz_t>::IntBase::inv(const IntBase & lhs, const IntBase & rhs)
        {
            mpz_invert(mVal, lhs, rhs);
        }

        template<>
        void IntBase<mpz_t>::IntBase::lcm(const IntBase & lhs, const IntBase & rhs)
        {
            mpz_lcm(mVal, lhs, rhs);
        }


        template class IntBase<mpz_t>;

    }
}