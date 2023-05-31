#pragma once

#include "secure-join/Defines.h"
#include "secure-join/Prf/DLpnPrf.h"
#include "secure-join/Perm/Permutation.h"

namespace secJoin
{

    class DLpnPerm
    {
    public:


        void xorShare(oc::MatrixView<const u8> v1,
            oc::MatrixView<const oc::u8> v2,
            oc::MatrixView<oc::u8>& s)
        {

            // Checking the dimensions
            if (v1.rows() != v2.rows())
                throw RTE_LOC;
            if (v1.cols() != v2.cols())
                throw RTE_LOC;

            for (oc::u64 i = 0; i < v1.size(); ++i)
                s(i) = v1(i) ^ v2(i);
        }

        // DLpn Receiver calls this setup
        macoro::task<> setup(
            const Perm& pi,
            u64 bytesPerRow,
            oc::MatrixView<u8>& sout,
            oc::PRNG& prng,
            coproto::Socket& chl,
            OleGenerator& ole,
            DLpnPrfReceiver& recver)
        {
            MC_BEGIN(macoro::task<>, &pi, &chl, &sout, &prng, &ole, &recver, bytesPerRow,
                aesPlaintext = oc::Matrix<oc::block>(),
                aesCipher    = oc::Matrix<oc::block>(),
                dlpnCipher   = oc::Matrix<oc::block>(),
                blocksPerRow = u64(),
                tolElements  = u64()
            );

            tolElements = pi.mPerm.size();
            blocksPerRow = oc::divCeil(bytesPerRow, sizeof(oc::block));

            // Encryption starts here
            aesPlaintext.resize(tolElements, blocksPerRow);
            aesCipher.resize(tolElements, blocksPerRow);
            dlpnCipher.resize(tolElements, blocksPerRow);
            for (u64 i = 0; i < tolElements; i++)
            {
                auto row = aesPlaintext[pi[i]];
                for (u64 j = 0; j < blocksPerRow; j++)
                {
                    auto srcIdx = i * blocksPerRow + j;
                    row[j] = oc::block(0, srcIdx);
                }
            }

            oc::mAesFixedKey.ecbEncBlocks(aesPlaintext, aesCipher);

            MC_AWAIT(recver.evaluate(aesCipher, dlpnCipher, chl, prng, ole));

            for (u64 i = 0; i < tolElements; i++)
                memcpyMin(sout[i], dlpnCipher[i]);

            MC_END();
        }


        // DLpn Sender calls this setup
        macoro::task<> setup(
            std::vector<oc::MatrixView<u8>>& sout,
            oc::PRNG& prng,
            coproto::Socket& chl,
            OleGenerator& ole,
            u64 totElements,
            u64 bytesPerRow,
            DLpnPrfSender& sender)
        {

            MC_BEGIN(macoro::task<>, &chl, &sout, &prng, &ole, &sender, totElements, bytesPerRow,
                aesPlaintext = oc::Matrix<oc::block>(),
                aesCipher    = oc::Matrix<oc::block>(),
                dlpnCipher   = oc::Matrix<oc::block>(),
                blocksPerRow = u64()
            );

            blocksPerRow = oc::divCeil(bytesPerRow, sizeof(oc::block));

            // // Calculating a from the ppt
            aesPlaintext.resize(totElements, blocksPerRow);
            aesCipher.resize(totElements, blocksPerRow);
            dlpnCipher.resize(totElements, blocksPerRow);


            for (u64 i = 0; i < aesPlaintext.size(); i++)
                aesPlaintext(i) = oc::block(0, i);

            oc::mAesFixedKey.ecbEncBlocks(aesPlaintext, aesCipher);

            // Placing a in sout[0]
            for (u64 i = 0; i < totElements; i++)
                memcpyMin(sout[0][i], aesCipher[i]);

            MC_AWAIT(sender.evaluate(dlpnCipher, chl, prng, ole));

            // Placing [y] in sout[1]
            for (u64 i = 0; i < totElements; i++)
                memcpyMin(sout[1][i], dlpnCipher[i]);

            MC_END();
        }


        // DLpn Receiver calls this apply
        macoro::task<> apply(
            const Perm& pi,
            oc::MatrixView<const u8> sin,
            oc::MatrixView<u8> sout,
            u64 bytesPerRow,
            coproto::Socket& chl)
        {
            MC_BEGIN(macoro::task<>, &pi, &chl, &sin, &sout, bytesPerRow, this,
                xEncrypted = oc::Matrix<u8>(),
                xPermuted = oc::Matrix<u8>(),
                totElements = u64()
            );

            totElements = pi.mPerm.size();
            xPermuted.resize(totElements, bytesPerRow);
            xEncrypted.resize(totElements, bytesPerRow);

            MC_AWAIT(chl.recv(xEncrypted));

            for (u64 i = 0; i < totElements; ++i)
                memcpy(xPermuted[pi[i]], xEncrypted[i]);

            xorShare(sin, xPermuted, sout);

            MC_END();
        }


        // DLpn Sender calls this apply
        macoro::task<> apply(
            oc::MatrixView<u8> input,
            oc::MatrixView<u8> sin,
            coproto::Socket& chl)
        {

            MC_BEGIN(macoro::task<>, &chl, &input, &sin, this,
                xEncrypted = oc::Matrix<u8>()
            );
            // Both dlpnCipher & input x would be Matrix<u8>

            xEncrypted.resize(sin.rows(), sin.cols());

            xorShare(sin, input, xEncrypted);

            MC_AWAIT(chl.send(std::move(xEncrypted)));

            MC_END();
        }


    };

}