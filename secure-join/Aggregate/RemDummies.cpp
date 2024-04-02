#include "RemDummies.h"

namespace secJoin {

    void RemDummies::init(u64 rows, u64 bytesPerEntry, CorGenerator& ole, bool cachePerm)
    {
        mPartyIdx = ole.partyIdx();
        mCachePerm = cachePerm;
        mPerm.init(mPartyIdx, rows, bytesPerEntry, ole);
    }


    macoro::task<> RemDummies::applyRandPerm(
            BinMatrix &data,
            BinMatrix &out,
            PRNG &prng,
            coproto::Socket &sock)
    {
        MC_BEGIN(macoro::task<>, &data, &out, &sock, &prng, this,
                 perm = ComposedPerm{}
        );

        mPerm.preprocess();

        // mPerm by default generates a random perm
        MC_AWAIT(mPerm.generate(sock, prng, data.rows(), perm));

        out.resize(data.rows(), data.bitsPerEntry());

        // Appyling the random permutation
        MC_AWAIT(perm.apply<u8>(mPermOp, data, out, sock));

        // Caching the Permutation
        if(mCachePerm)
            std::swap(mPermutation, perm);

        MC_END();
    }

    // Given the full data Matrix this function extracts the act flag byte
    // & then returns the revealed Act Flag
    macoro::task<> RemDummies::revealActFlag(
            BinMatrix& data,
            u64 actFlagOffSet,
            BinMatrix& out,
            coproto::Socket& sock
    )
    {
        MC_BEGIN(macoro::task<>, &data, &out, actFlagOffSet, this, &sock,
                 actFlag = BinMatrix{});

         actFlag.resize(data.numEntries(), 1);
         for(u64 i = 0; i < data.numEntries(); i++)
             actFlag(i, 0) = data(i, actFlagOffSet);

        out.resize(actFlag.numEntries(), actFlag.bitsPerEntry());
        MC_AWAIT(revealActFlag(actFlag, out, sock));

        MC_END();
    }


    // Given the ActFlag, it returns the revealed Act Flag
    macoro::task<> RemDummies::revealActFlag(
            BinMatrix& actFlag,
            BinMatrix& out,
            coproto::Socket& sock
    )
    {
        MC_BEGIN(macoro::task<>, &actFlag, &out, this, &sock);

         // Revealing the active flag
         if (mPartyIdx == 0)
         {
             out.resize(actFlag.numEntries(), actFlag.bitsPerEntry());
             MC_AWAIT(sock.recv(out.mData));
             out = reveal(out, actFlag);
             MC_AWAIT(sock.send(coproto::copy(out.mData)));
         }
         else
         {
             MC_AWAIT(sock.send(coproto::copy(actFlag.mData)));
             out.resize(actFlag.numEntries(), actFlag.bitsPerEntry());
             MC_AWAIT(sock.recv(out.mData));
         }

        MC_END();
    }


    // Average will call this remDummies method
    macoro::task<> RemDummies::remDummies(
                BinMatrix& data,
                BinMatrix& out,
                u64 actFlagOffSet,
                coproto::Socket& sock,
                PRNG &prng)
    {
        MC_BEGIN(macoro::task<>, &data, &out, actFlagOffSet, &sock, &prng, this,
                 temp = BinMatrix{},
                 actFlag = BinMatrix{},
                 nOutRows = u64{},
                 curPtr = u64{}
                 );

        // Applying the Rand Perm
        temp.resize(data.numEntries(), data.bitsPerEntry());
        MC_AWAIT(applyRandPerm(data, temp, prng, sock));
        std::swap(data, temp);

        // Revealing ActFlag
        MC_AWAIT(revealActFlag(data, actFlagOffSet, actFlag, sock));

        // Counting the total number of active rows
        nOutRows = countActiveRows(oc::MatrixView<u8>(actFlag.data(), actFlag.size(), 1));

        out.resize(nOutRows, data.bitsPerEntry());
        curPtr = 0;
        for(u64 i = 0; i < actFlag.numEntries(); i++)
        {
            if( actFlag(i,0) == 1)
            {
                memcpy( out.data(curPtr), data.data(i), data.bytesPerEntry());
                curPtr++;
            }

            if(curPtr >=  nOutRows)
                break;
        }

        MC_END();
    }


    macoro::task<> RemDummies::remDummies(
            Table& in,
            Table& out,
            coproto::Socket& sock,
            PRNG &prng)
    {

        MC_BEGIN(macoro::task<>, &in, &out, &sock, &prng, this,
                 data = BinMatrix{},
                 temp = BinMatrix{},
                 actFlag = BinMatrix{},
                 actFlagOffSet = u64{},
                 nOutRows = u64{}
        );

         concatTable(in, data);

         // Applying the Rand Perm
         temp.resize(data.numEntries(), data.bitsPerEntry());
         MC_AWAIT(applyRandPerm(data, temp, prng, sock));
         std::swap(data, temp);

         // Calculating ActFlag Offset
         for(u64 i = 0; i < in.cols(); i++)
         {
             auto bytes = in.mColumns[i].getByteCount();
             actFlagOffSet += bytes;
         }

         // Revealing ActFlag
         MC_AWAIT(revealActFlag(data, actFlagOffSet, actFlag, sock));

         // Counting the total number of active rows
         nOutRows = countActiveRows(oc::MatrixView<u8>(actFlag.data(), actFlag.size(), 1));

         // Populating the out table
         out.init(nOutRows, in.getColumnInfo());

         populateOutTable(out, actFlag, data);

         MC_END();

    }




}