#include "Ciphertext.h"
#include "Key.h"
#include "Plaintext.h"
#include "Integer.h"

namespace secJoin
{

    namespace Paillier
    {
        Ciphertext::Ciphertext(PublicKey & pk)
            :mPk(&pk)
        {}

        void Ciphertext::add(const Ciphertext & lhs, const Ciphertext & rhs)
        {
            if (!mPk)
                throw std::runtime_error("ctxt is not initialized. " LOCATION);

            mVal.mul(lhs.mVal, rhs.mVal);
            mVal.mod(mVal, mPk->mNSquared);
        }

        void Ciphertext::add(const Ciphertext & lhs, const Plaintext & rhs)
        {
            if (!mPk)
                throw std::runtime_error("ctxt is not initialized. " LOCATION);

            mVal.pow(mPk->mNPlusOne, rhs.mVal, mPk->mNSquared);
            mVal.mul(mVal, lhs.mVal);
            mVal.mod(mVal, mPk->mNSquared);
        }

        void Ciphertext::mul(const Ciphertext & lhs, const Plaintext & rhs)
        {
            if (!mPk)
                throw std::runtime_error("ctxt is not initialized. " LOCATION);

            mVal.pow(lhs.mVal, rhs.mVal, mPk->mNSquared);
        }

        void Ciphertext::mul(const Ciphertext & lhs, const u32 & rhs)
        {
            if (!mPk)
                throw std::runtime_error("ctxt is not initialized. " LOCATION);

            mVal.pow(lhs.mVal, rhs, mPk->mNSquared);
        }


        Ciphertext Ciphertext::operator*(const Plaintext & rhs) const
        {
            Ciphertext r(*mPk);
            r.mul(*this, rhs);
            return r;
        }
        Ciphertext & Ciphertext::operator*=(const Plaintext & rhs)
        {
            mul(*this, rhs);
            return *this;
        }
        Ciphertext Ciphertext::operator*(const u32 rhs) const
        {
            Ciphertext r(*mPk);
            r.mul(*this, rhs);
            return r;
        }
        Ciphertext & Ciphertext::operator*=(const u32 & rhs)
        {
            mul(*this, rhs);
            return *this;
        }
        Ciphertext Ciphertext::operator+(const Ciphertext & rhs) const
        {
            Ciphertext r(*mPk);
            r.add(*this, rhs);
            return r;
        }
        Ciphertext & Ciphertext::operator+=(const Ciphertext & rhs)
        {
            add(*this, rhs);
            return *this;
        }

        Ciphertext Ciphertext::operator+(const Plaintext & rhs) const
        {
            Ciphertext r;
            r.add(*this, rhs);
            return r;
        }

        Ciphertext & Ciphertext::operator+=(const Plaintext & rhs)
        {
            add(*this, rhs);
            return *this;
        }

        void Ciphertext::fromBytes(span<u8> data, PublicKey& pk)
        {
            mVal.fromBytes(data);
            mPk = &pk;
        }

        void Ciphertext::toBytes(span<u8> bytes) const
        {
            mVal.toBytes(bytes);
        }

        u64 Ciphertext::sizeBytes() const
        {
            return mVal.sizeBytes();
        }

        Ciphertext& Ciphertext::operator=(const std::string & s)
        {
            mVal = s;
            return *this;
        }

        Ciphertext::operator std::string() const
        {
            return mVal;
        }
        bool Ciphertext::operator==(const Ciphertext & s) const
        {
            return mVal == s.mVal;
        }
        bool Ciphertext::operator!=(const Ciphertext & s) const
        {
            return !(*this == s);
        }
    }
}
