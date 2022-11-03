#include "Key.h"
#include <cstring>

namespace bio
{
    namespace Paillier
    {
        Ciphertext PublicKey::encNoRand(const Plaintext & ptxt)
        {
            Ciphertext r;
            encNoRand(ptxt, r);
            return r;
        }

        void PublicKey::encNoRand(const Plaintext & ptxt, Ciphertext & ctxt)
        {
            Integer& c = ctxt.mVal;
            c.pow(mNPlusOne, ptxt.mVal, mNSquared);
            c.mod(c, mNSquared);
            ctxt.mPk = this;
        }

        Ciphertext PublicKey::enc(const Plaintext & ptxt, RNG & rand)
        {
            Ciphertext r;
            enc(ptxt, rand, r);
            return r;
        }

        void PublicKey::enc(const Plaintext & ptxt, RNG & rand, Ciphertext & ctxt)
        {
            Integer r(rand, mBitCount), x;
            Integer& c = ctxt.mVal;

            r.randomize(rand, mN);

            c.pow(mNPlusOne, ptxt.mVal, mNSquared);
            x.pow(r, mN, mNSquared);

            c.mul(c, x);
            c.mod(c, mNSquared);

            ctxt.mPk = this;
        }


        void PublicKey::fromBytes(span<u8> bytes)
        {
            if (bytes.size() < sizeof(mBitCount))
                throw std::runtime_error(LOCATION);

            memcpy(&mBitCount, bytes.data(), sizeof(mBitCount));
            mN.fromBytes(bytes.subspan(sizeof(mBitCount), (mBitCount + 7) / 8));
            computeCache();
        }

        void PublicKey::toBytes(span<u8> bytes) const
        {
            if (bytes.size() != sizeBytes())
                throw std::runtime_error(LOCATION);

            if (mN.sizeBytes() != ((mBitCount + 7) / 8))
                throw std::runtime_error(LOCATION);

            memcpy(bytes.data(), &mBitCount, sizeof(mBitCount));
            mN.toBytes(bytes.subspan(sizeof(mBitCount)));
        }

        u64 PublicKey::sizeBytes() const
        {
            return mN.sizeBytes() + sizeof(u64);
        }

        bool PublicKey::operator==(const PublicKey & v) const
        {
            return
                mN == v.mN && // only this one really needs to be checked but the 
                              // others are also check for debugging/testing.
                mBitCount == v.mBitCount &&
                mNPlusOne == v.mNPlusOne &&
                mNSquared == v.mNSquared;
        }

        bool PublicKey::operator!=(const PublicKey & v) const
        {
            return !(*this == v);
        }

        u64 PublicKey::ciphertextByteSize()
        {
            return (2 * mBitCount + 7) / 8;
        }

        u64 PublicKey::plaintextByteSize()
        {
            return (mBitCount + 7) / 8;
        }

        void PublicKey::computeCache()
        {
            mNSquared.mul(mN, mN);
            mNPlusOne.add(mN, 1);
        }

        PrivateKey::PrivateKey(u64 bitCount, RNG & prng)
        {
            keyGen(bitCount, prng);
        }

        void PrivateKey::keyGen(u64 bitCount, RNG& rand)
        {
            Integer p, q;

            if (bitCount & 1)
                throw std::runtime_error("bitCount must be even. " LOCATION);

            do
            {
                p.randomPrime(rand, bitCount / 2);
                q.randomPrime(rand, bitCount / 2);
                mPublicKey.mN.mul(p, q);
            } while (mPublicKey.mN.sizeBits() != bitCount);

            //{
            //    std::cout << "bc " << bitCount << " " << mPublicKey.mN.sizeBits() << std::endl;
            //    std::cout << "p " << p << " " << p.sizeBits() << std::endl;
            //    std::cout << "q " << q << " " << q.sizeBits() << std::endl;
            //    std::cout << "n " << mPublicKey.mN << std::endl;
            //    throw std::runtime_error("this shouldn't happen " LOCATION);
            //}

            mPublicKey.mBitCount = bitCount;
            mPublicKey.computeCache();

            // compute the private key lambda = lcm(p-1,q-1) 
            p.sub(p, 1);
            q.sub(q, 1);
            mLambda.lcm(p, q);

            computeCache();
        }

        void PrivateKey::fromBytes(span<u8> bytes)
        {

            mPublicKey.fromBytes(bytes);
            mLambda.fromBytes(bytes.subspan(mPublicKey.sizeBytes()));
            computeCache();
        }

        void PrivateKey::toBytes(span<u8> bytes) const
        {
            if (bytes.size() != sizeBytes())
                throw std::runtime_error("Bad buffer size. " LOCATION);

            auto pkSize = mPublicKey.sizeBytes();
            mPublicKey.toBytes(bytes.subspan(0, pkSize));
            mLambda.toBytes(bytes.subspan(pkSize));
        }

        u64 PrivateKey::sizeBytes() const
        {
            return mPublicKey.sizeBytes() + mLambda.sizeBytes();
        }

        bool PrivateKey::operator==(const PrivateKey & v) const
        {
            return
                mLambda == v.mLambda &&// only this one really needs to be checked but the 
                                       // others are also check for debugging/testing.
                mX == v.mX &&
                mPublicKey == v.mPublicKey;
        }

        bool PrivateKey::operator!=(const PrivateKey & v) const
        {
            return !(*this == v);
        }

        void PrivateKey::computeCache()
        {
            mX.pow(mPublicKey.mNPlusOne, mLambda, mPublicKey.mNSquared);
            mX.sub(mX, 1);
            mX.div(mX, mPublicKey.mN);
            mX.inv(mX, mPublicKey.mN);
        }

        Plaintext PrivateKey::dec(const Ciphertext & ctxt)
        {
            Plaintext r;
            dec(ctxt, r);
            return r;
        }

        void PrivateKey::dec(const Ciphertext & ctxt, Plaintext & ptxt)
        {
            auto& p = ptxt.mVal;
            p.pow(ctxt.mVal, mLambda, mPublicKey.mNSquared);
            p.sub(p, 1);
            p.div(p, mPublicKey.mN);
            p.mul(p, mX);
            p.mod(p, mPublicKey.mN);
            ptxt.setModulus(mPublicKey.mN);
        }

    }
}