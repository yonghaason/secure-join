#pragma once

#include "secure-join/Defines.h"
#include "secure-join/Prf/DLpnPrf.h"
#include "secure-join/Perm/Permutation.h"

namespace secJoin
{

    class DLpnPerm
    {
    public:


        void xorShare(oc::MatrixView<u8>& v1,
                oc::MatrixView<oc::u8>& v2,
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
            oc::block& aesKey,
            DLpnPrfReceiver& recver)
        {
            MC_BEGIN(macoro::task<>, &pi, &chl, &sout, &prng, &ole, &recver, bytesPerRow,
                // dm = DLpnPrf{},
                aes = oc::AES(aesKey),
                aesPlaintext = std::vector<oc::block>(),
                aesCipher = std::vector<oc::block>(),
                dlpnCipher = std::vector<oc::block>(),
                blocksPerRow = u64(),
                tolElements = u64()
            );
            
            tolElements = pi.mPerm.size();
            blocksPerRow = oc::divCeil(bytesPerRow, sizeof(oc::block));

            // Encryption starts here
            aesPlaintext.resize( tolElements * blocksPerRow );
            aesCipher.resize( tolElements * blocksPerRow );
            dlpnCipher.resize( tolElements * blocksPerRow );
            for(u64 i =0; i < tolElements; i++)
            {

                for(u64 j=0; j<blocksPerRow; j++)
                {
                    auto srcIdx = i * blocksPerRow + j;
                    auto dstIdx = pi[i] * blocksPerRow + j;
                    // std::memcpy( &aesPlaintext[dstIdx], &srcIdx , sizeof(int));
                    aesPlaintext[dstIdx] = oc::block(0, srcIdx);
                }

            }

            aes.ecbEncBlocks(aesPlaintext, aesCipher);

            MC_AWAIT( recver.evaluate(aesCipher, dlpnCipher, chl, prng, ole) );

            // look into std::copy to replace memcpy
            for (u64 i = 0; i < tolElements; i++)
            {
                if( (i * blocksPerRow) + blocksPerRow > dlpnCipher.size())
                    throw RTE_LOC;

                // auto src = dlpnCipher.begin() + (i * blocksPerRow);
                std::memcpy(sout.data(i), &dlpnCipher[i * blocksPerRow], bytesPerRow);
            }
            
            MC_END();
        }


        // DLpn Sender calls this setup
        macoro::task<> setup(
            std::vector<oc::MatrixView<u8>>& sout,
            oc::PRNG& prng,
            coproto::Socket& chl,
            OleGenerator& ole,
            oc::block& aesKey,
            u64 totElements,
            u64 bytesPerRow,
            DLpnPrfSender& sender)
        {

            MC_BEGIN(macoro::task<>, &chl, &sout, &prng, &ole, &sender, totElements, bytesPerRow,
                aesPlaintext = std::vector<oc::block>(),
                aesCipher = std::vector<oc::block>(),
                dlpnCipher = std::vector<oc::block>(),
                aes = oc::AES(aesKey),
                blocksPerRow = u64()
            );

            blocksPerRow = oc::divCeil(bytesPerRow, sizeof(oc::block));

            // // Calculating a from the ppt
            aesPlaintext.resize( totElements * blocksPerRow );
            aesCipher.resize( totElements * blocksPerRow );
            dlpnCipher.resize( totElements * blocksPerRow  );
            
            
            // std::for_each(aesPlaintext.begin(), aesPlaintext.end(), [i =0](auto &x){ x = oc::block(0,i++);} );
            for(u64 i =0; i < aesPlaintext.size(); i++)
            {
                aesPlaintext[i] = oc::block(0,i);
            }

            aes.ecbEncBlocks(aesPlaintext, aesCipher);
            
            // Placing a in sout[0]
            for (u64 i = 0; i < totElements; i++)
            {
                if( (i * blocksPerRow) + blocksPerRow > dlpnCipher.size())
                    throw RTE_LOC;
                
                // auto src = aesCipher.begin() + (i * blocksPerRow);
                std::memcpy(sout[0].data(i), &aesCipher[i * blocksPerRow], bytesPerRow);

            }

            MC_AWAIT( sender.evaluate(dlpnCipher, chl, prng, ole) );

            // Placing [y] in sout[1]
            for (u64 i = 0; i < totElements; i++)
            {
                if( (i * blocksPerRow) + blocksPerRow > dlpnCipher.size())
                    throw RTE_LOC;


                // auto src = dlpnCipher.begin() + (i * blocksPerRow);
                std::memcpy(sout[1].data(i), &dlpnCipher[i * blocksPerRow], bytesPerRow);
            }
            
            MC_END();
        }


        // DLpn Receiver calls this apply
        macoro::task<> apply(
            const Perm& pi,
            oc::MatrixView<u8>& sin,
            oc::MatrixView<u8>& sout,
            u64 bytesPerRow,
            coproto::Socket& chl)
        {
            MC_BEGIN(macoro::task<>, &pi, &chl, &sin, &sout, bytesPerRow, this,
                xEncrypted = oc::MatrixView<u8>(),
                xPermuted = oc::MatrixView<u8>(),
                totElements = u64()
            );
            
            totElements = pi.mPerm.size();
            // xEncrypted.resize(totElements * bytesPerRow);       
            // xPermuted.resize(totElements * bytesPerRow);

            MC_AWAIT(chl.recv(xEncrypted));

            
            xPermuted.reshape(totElements , bytesPerRow);
            xEncrypted.reshape(totElements , bytesPerRow);

            
            for (u64 i = 0; i < totElements; ++i)
            {
                // Do I need a check over here?
                std::memcpy( xPermuted.data(pi[i]) , xEncrypted.data(i), bytesPerRow );
            }

            xorShare(sin,xPermuted,sout);

            

            MC_END();
        }


        // DLpn Sender calls this apply
        macoro::task<> apply(
            oc::MatrixView<u8>& input,
            oc::MatrixView<u8>& sin,
            coproto::Socket& chl)
        {

            MC_BEGIN(macoro::task<>, &chl, &input, &sin, this,
                xEncrypted = oc::MatrixView<u8>()
            );
            // Both dlpnCipher & input x would be Matrix<u8>
            
            xEncrypted.reshape(sin.rows(), sin.cols());
            
            xorShare(sin,input,xEncrypted);

            
            MC_AWAIT(chl.send(std::move( xEncrypted )));


            MC_END();
        }


    };

}