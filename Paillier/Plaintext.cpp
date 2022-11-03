
#include "Plaintext.h"
#include "Ciphertext.h"

namespace bio
{

    namespace Paillier
    {


        Plaintext::Plaintext(const u32 &v)
        {
            *this = v;
        }

        Plaintext::Plaintext(Integer& mod)
            : mModulus(&mod)
        {}

        Plaintext::Plaintext(RNG & rand, Integer & mod)
            : mModulus(&mod)
        {
            randomize(rand);
        }

        Plaintext::Plaintext(const Plaintext &v, Integer & mod)
            : mVal(v.mVal)
            , mModulus(&mod)
        {}

        void Plaintext::setModulus(Integer& mod)
        {
            mModulus = &mod;
            reduce();
        }

        void Plaintext::setValue(Integer val)
        {
            mVal = val;
            reduce();
        }

        void Plaintext::randomize(RNG & rand)
        {
            if (mModulus)
            {
                mVal.randomize(rand, mModulus->sizeBytes() * 8);
                reduce();
            }
            else
            {
                throw std::runtime_error(
                    "modulus must be set before randomize() is call. " LOCATION);
            }
        }

        void Plaintext::fromBytes(span<u8> data)
        {
            mVal.fromBytes(data);

            if (mModulus && mVal >= *mModulus)
            {
                throw std::runtime_error("value too large ");
            }
        }


        void Plaintext::toBytes(span<u8> data) const
        {
            mVal.toBytes(data);
        }

        u64 Plaintext::sizeBytes() const
        {
            return mVal.sizeBytes();
        }


        Plaintext& Plaintext::operator=(const std::string & s)
        {
            mVal = s;
            return *this;
        }

        Plaintext::operator std::string() const
        {
            return static_cast<std::string>(mVal);
        }

        Plaintext& Plaintext::operator=(u64 v)
        {
            mVal = v;
            return *this;
        }

        Plaintext::operator u64() const
        {
            return static_cast<i64>(mVal);
        }

        void byteReverse(span<u8> bytes);

        /*function to deal with negative numbers*/
        Plaintext::operator i64() const
        {
            
            auto temp = mVal;
            bool isNegative = false;
            if(! mModulus)
            {
                throw RTE_LOC;
            }

            if(mVal > (*mModulus)/2)
            {
                temp = *mModulus - mVal;
                isNegative = true;
            }
            auto tempsize = std::max<u64>(temp.sizeBytes(), sizeof(i64));
            std::vector<u8> buff(tempsize);
            temp.toBytes(buff, false);
            byteReverse(buff);
            i64 ret = *(i64*) buff.data();
            if(isNegative)
            {
                ret = ret * (-1);
            }
            return ret;

        }


        Plaintext Plaintext::operator*(const Plaintext & rhs) const
        {
            Plaintext r;
            r.mVal.mul(mVal, rhs.mVal);
            if (mModulus)
            {
                r.setModulus(*mModulus);
                r.reduce();
            }
            return r;
        }

        Plaintext & Plaintext::operator*=(const Plaintext & rhs)
        {
            mVal *= rhs.mVal;
            if (mModulus) reduce();
            return *this;
        }

        Plaintext Plaintext::operator+(const Plaintext & rhs) const
        {
            Plaintext r;
            r.mVal.add(mVal, rhs.mVal);
            if (mModulus)
            {
                r.setModulus(*mModulus);
                r.reduce();
            }
            return r;
        }

        Plaintext & Plaintext::operator+=(const Plaintext & rhs)
        {
            mVal.add(mVal, rhs.mVal);
            if (mModulus) reduce();
            return *this;
        }

        Plaintext Plaintext::operator-(const Plaintext & rhs) const
        {
            Plaintext r;
            r.mVal.sub(mVal, rhs.mVal);
            if (mModulus)
            {
                r.setModulus(*mModulus);
                r.reduce();
            }
            return r;
        }

        Plaintext & Plaintext::operator-=(const Plaintext & rhs)
        {
            mVal.sub(mVal, rhs.mVal);
            if (mModulus) reduce();
            return *this;
        }

        void Plaintext::reduce()
        {
            if (mModulus == nullptr)
                throw std::runtime_error(LOCATION);

            mVal.mod(mVal, *mModulus);
            //mpz_mod(mVal.mVal, mVal.mVal, mModulus->mVal);
        }

    }
}
