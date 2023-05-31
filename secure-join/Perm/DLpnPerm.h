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
            oc::Matrix<u8>& sout,
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
                totElements  = u64()
            );

            totElements = pi.mPerm.size();
            blocksPerRow = oc::divCeil(bytesPerRow, sizeof(oc::block));

            // Encryption starts here
            aesPlaintext.resize(totElements, blocksPerRow);
            aesCipher.resize(totElements, blocksPerRow);
            dlpnCipher.resize(totElements, blocksPerRow);
            for (u64 i = 0; i < totElements; i++)
            {
                auto row = aesPlaintext[pi[i]];
                for (u64 j = 0; j < blocksPerRow; j++)
                {
                    auto srcIdx = i * blocksPerRow + j;
                    row[j] = oc::block(0, srcIdx);
                }
            }

            oc::mAesFixedKey.ecbEncBlocks(aesPlaintext, aesCipher);

            // std::cout << "Printing permuted AES PlainText" << std::endl;
            // for(int i = 0; i < aesPlaintext.rows() ; i++)
            // {
            //     std::cout << "i = " << i << " plain= "<< aesPlaintext(i,0) << " cipher = " << aesCipher(i,0) << std::endl;   
            // }

            MC_AWAIT(recver.evaluate(aesCipher, dlpnCipher, chl, prng, ole));

            // std::cout << "Printing dlpnCipher 1" << std::endl;
            // for(int i = 0; i < dlpnCipher.size() ; i++)
            // {
            //     std::cout << dlpnCipher(i,0) << std::endl;   
            // }

            sout.resize(totElements, bytesPerRow );
            for (u64 i = 0; i < totElements; i++)
                memcpyMin(sout[i], dlpnCipher[i]);

            // std::cout << "dlpnCipher 1 is added in sout" << std::endl;
            // for(int i = 0; i < totElements ; i++)
            // {
            //     std::cout << hex(sout[i]) << std::endl;   
            // }

            MC_END();
        }


        // DLpn Sender calls this setup
        macoro::task<> setup(
            oc::Matrix<u8>& a,
            oc::Matrix<u8>& b,
            oc::PRNG& prng,
            coproto::Socket& chl,
            OleGenerator& ole,
            u64 totElements,
            u64 bytesPerRow,
            DLpnPrfSender& sender,
            DLpnPrf& dm)
        {

            MC_BEGIN(macoro::task<>, &chl, &a, &b, &prng, &ole, &sender, totElements, bytesPerRow, &dm,
                aesPlaintext = oc::Matrix<oc::block>(),
                aesCipher    = oc::Matrix<oc::block>(),
                preProsdlpnCipher   = oc::Matrix<oc::block>(),
                dlpnCipher   = oc::Matrix<oc::block>(),
                blocksPerRow = u64()
            );

            blocksPerRow = oc::divCeil(bytesPerRow, sizeof(oc::block));

            // // Calculating a from the ppt
            aesPlaintext.resize(totElements, blocksPerRow);
            aesCipher.resize(totElements, blocksPerRow);
            dlpnCipher.resize(totElements, blocksPerRow);
            preProsdlpnCipher.resize(totElements, blocksPerRow);

            for (u64 i = 0; i < aesPlaintext.size(); i++)
                aesPlaintext(i) = oc::block(0, i);

            oc::mAesFixedKey.ecbEncBlocks(aesPlaintext, aesCipher);

            // std::cout << "Printing AES sender setup" << std::endl;
            // for(int i = 0; i < aesPlaintext.rows() ; i++)
            // {
            //     std::cout << "i = " << i
            //              << " plain= " << aesPlaintext(i,0)
            //              << " cipher = " << aesCipher(i,0)
            //              << std::endl;   
            // }

        
            for(int i = 0; i < aesCipher.rows() ; i++)
            {
                for(int j=0; j < aesCipher.cols(); j++)
                {
                    preProsdlpnCipher(i,j) = dm.eval(aesCipher(i,j));
                }
                
            }
            // dm.eval(aesCipher);

            // Placing a in sout[0]
            a.resize(totElements, bytesPerRow);
            for (u64 i = 0; i < totElements; i++)
                memcpyMin(a[i], preProsdlpnCipher[i]);

            MC_AWAIT(sender.evaluate(dlpnCipher, chl, prng, ole));

            // Placing [y] in sout[1]
            b.resize(totElements, bytesPerRow);

            // std::cout<< "Size of one row in b " << b[1].size_bytes() << std::endl;
            // std::cout<< "Size of one row in dlpnCipher " << dlpnCipher[1].size_bytes() << std::endl;
            for (u64 i = 0; i < totElements; i++)
                memcpyMin(b[i], dlpnCipher[i]);

            // std::cout << "dlpnCipher 2 is added in b" << std::endl;
            // for(int i = 0; i < totElements ; i++)
            // {
            //     std::cout << hex(b[i]) << std::endl;   
            // }

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
            xEncrypted.resize(sin.rows(), sin.cols());

            xorShare(sin, input, xEncrypted);

            MC_AWAIT(chl.send(std::move(xEncrypted)));

            MC_END();
        }


    };

}