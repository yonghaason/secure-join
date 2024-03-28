#include "RemDummies.h"

namespace secJoin {

    void init(

            )
    {

    }


    macoro::task<> RemDummies::applyRandPerm(
            BinMatrix &data,
            BinMatrix &out,
            CorGenerator &ole,
            PRNG &prng,
            Perm &randPerm,
            coproto::Socket &sock,
            bool securePerm) {
        MC_BEGIN(macoro::task<>, &data, &out, &ole, &sock, &prng, &randPerm, securePerm, this,
                 perm = ComposedPerm{},
                 kk = AltModPrf::KeyType{},
                 rk = std::vector < oc::block > {},
                 sk = std::vector < std::array < oc::block, 2 >> {}
        );

        mPerm.preprocess();

         MC_AWAIT(mPerm.generate(sock, prng, data.rows(), mPerm));

        throw RTE_LOC;// not impl
        // perm.init2(ole.partyIdx(), data.rows(), data.bytesPerEntry());
        //perm.mSender.setPermutation(randPerm);
        //perm.mIsSecure = securePerm;

        // Setuping up the OT Keys
        // kk = prng.get();
        // rk.resize(AltModPrf::KeySize);
        // sk.resize(AltModPrf::KeySize);
        // for (u64 i = 0; i < AltModPrf::KeySize; ++i)
        // {
        //     sk[i][0] = oc::block(i, 0);
        //     sk[i][1] = oc::block(i, 1);
        //     rk[i] = oc::block(i, *oc::BitIterator((u8*)&kk, i));
        // }
        // perm.setKeyOts(kk, rk, sk);

        // perm.request(ole);

        // MC_AWAIT(perm.setup(sock, prng));

        // out.resize(data.numEntries(), data.bytesPerEntry() * 8);
        // MC_AWAIT(perm.apply<u8>(PermOp::Regular, data.mData, out.mData, sock, prng));

        MC_END();
    }

    macoro::task<> revealActFlag(
            BinMatrix& actFlag,
            BinMatrix& out,
            coproto::Socket& sock,
            u64 partyIdx
    )
    {
        MC_BEGIN(macoro::task<>, &actFlag, &out, partyIdx, &sock);

         // Revealing the active flag
         if (partyIdx == 0)
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

}