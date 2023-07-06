#pragma once

#include "secure-join/Perm/ComposedPerm.h"
#include "secure-join/Perm/AdditivePerm.h"
#include "secure-join/Defines.h"
#include "secure-join/OleGenerator.h"

#include "cryptoTools/Circuit/BetaLibrary.h"
#include "cryptoTools/Common/Log.h"
#include "coproto/Socket/Socket.h"
#include "cryptoTools/Common/Timer.h"

namespace secJoin
{

    inline bool operator>(const oc::BitVector& v0, const oc::BitVector& v1)
    {
        if (v0.size() != v1.size())
            throw RTE_LOC;
        for (u64 i = v0.size() - 1; i < v0.size(); --i)
        {
            if (v0[i] > v1[i])
                return true;
            if (v1[i] > v0[i])
                return false;
        }

        return false;
    }

    class RadixSort : public oc::TimerAdapter
    {
    public:
        // run debugging check (insecure).
        bool mDebug = false;

        // mock the sorting protocol (insecure).
        bool mMock = false;

        using Matrix32 = oc::Matrix<u32>;

        RadixSort() = default;
        RadixSort(RadixSort&&) = default;
        oc::BetaCircuit mArith2BinCir;

        // compute dst = sum_i f.col(i) * s.col(i) where * 
        // is the hadamard (component-wise) product. 
        macoro::task<> hadamardSum(
            BinMatrix& f,
            Matrix32& s,
            AdditivePerm& dst,
            OleGenerator& gen,
            coproto::Socket& comm);
        // from each row, we generate a series of sharing flag bits
        // f.col(0) ,..., f.col(n) where f.col(i) is one if k=i.
        // Computes the same function as genValMask but is more efficient
        // due to the use a binary secret sharing.
        macoro::task<> genValMasks2(
            u64 bitCount,
            const BinMatrix& k,
            Matrix32& f,
            BinMatrix& fBin,
            OleGenerator& gen,
            coproto::Socket& comm);


        // Generate a permutation dst which will be the inverse of the
        // permutation that permutes the keys k into sorted order. 
        macoro::task<> genBitPerm(
            u64 keyBitCount,
            const BinMatrix& k,
            AdditivePerm& dst,
            OleGenerator& gen,
            coproto::Socket& comm);


        // get 'size' columns of k starting at column index 'begin'
        // Assumes 'size <= 8'. 
        BinMatrix extract(u64 begin, u64 size, const BinMatrix& k);


        u64 mL = 2;
        // generate the (inverse) permutation that sorts the keys k.
        macoro::task<> genPerm(
            const BinMatrix& k,
            AdditivePerm& dst,
            OleGenerator& gen,
            coproto::Socket& comm);

        //// sort `src` based on the key `k`. The sorted values are written to `dst`
        //// and the sorting (inverse) permutation is written to `dstPerm`.
        //BinMatrix sort(
        //	u64 keyBitCount,
        //	const BinMatrix& k,
        //	const BinMatrix& src,
        //	OleGenerator& gen,
        //	coproto::Socket& comm);

        //// sort `src` based on the key `k`. The sorted values are written to `dst`
        //// and the sorting (inverse) permutation is written to `dstPerm`.
        //void sort(
        //	const BinMatrix& k,
        //	const BinMatrix& src,
        //	BinMatrix& dst,
        //	ComposedPerm& dstPerm,
        //	OleGenerator& gen,
        //	coproto::Socket& comm);

        // this circuit takes as input a index i\in {0,1}^L and outputs
        // a binary vector o\in {0,1}^{2^L} where is one at index i.
        static oc::BetaCircuit indexToOneHotCircuit(u64 L);


        // compute a running sum. replace each element f(i,j) with the sum all previous 
        // columns f(*,1),...,f(*,j-1) plus the elements of f(0,j)+....+f(i-1,j).
        static void aggregateSum(const Matrix32& f, Matrix32& s, u64 partyIdx);

        macoro::task<> mockSort(
            const BinMatrix& k,
            AdditivePerm& dst,
            OleGenerator& ole,
            coproto::Socket& comm);

        macoro::task<> checkHadamardSum(
            BinMatrix& f,
            Matrix32& s,
            span<u32> dst,
            coproto::Socket& comm,
            bool additive);

        macoro::task<> checkGenValMasks(
            u64 bitCount,
            const BinMatrix& k,
            BinMatrix& f,
            coproto::Socket& comm,
            bool check);

        macoro::task<> checkGenValMasks(
            u64 L,
            const BinMatrix& k,
            Matrix32& f,
            coproto::Socket& comm);

        macoro::task<> checkAggregateSum(
            const Matrix32& f0,
            Matrix32& s0,
            coproto::Socket& comm
        );

        macoro::task<std::vector<Perm>> debugGenPerm(
            const BinMatrix& k,
            coproto::Socket& comm);
    };


    bool lessThan(span<const u8> l, span<const u8> r);
     Perm sort(const BinMatrix& x);
     
}