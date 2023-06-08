#pragma once

#include "secure-join/Defines.h"
#include "secure-join/Prf/DLpnPrf.h"
#include "secure-join/Perm/Permutation.h"

namespace secJoin
{

    class DLpnPerm
    {

    public: 

        bool isDlpnSetupDone = false;
        DLpnPrfReceiver mRecver;
        DLpnPrfSender mSender;
        oc::Matrix<u8> a, delta, b;

        void setupDlpnSender(oc::block& key, std::vector<oc::block>& rk)
        {
            mSender.setKey(key);
            mSender.setKeyOts(rk);
            isDlpnSetupDone = true;
        }

        void setupDlpnReceiver(std::vector<std::array<oc::block, 2>>& sk)
        {
            mRecver.setKeyOts(sk);
            isDlpnSetupDone = true;
        }

        inline macoro::task<> setupDlpnSender(OleGenerator& ole)
        {

            MC_BEGIN(macoro::task<>, this, &ole);
            MC_AWAIT(mSender.genKeyOTs(ole));

            isDlpnSetupDone = true;
            MC_END();
        }

        inline macoro::task<> setupDlpnReceiver(OleGenerator& ole)
        {

            MC_BEGIN(macoro::task<>, this, &ole);
            MC_AWAIT(mRecver.genKeyOTs(ole));

            isDlpnSetupDone = true;
            MC_END();
        }

        inline void xorShare(oc::MatrixView<const u8> v1,
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
            oc::PRNG& prng,
            coproto::Socket& chl,
            OleGenerator& ole,
            bool invPerm)
        {
            MC_BEGIN(macoro::task<>, &pi, &chl, &prng, &ole, bytesPerRow, this, invPerm,
                aesPlaintext = oc::Matrix<oc::block>(),
                aesCipher    = oc::Matrix<oc::block>(),
                dlpnCipher   = oc::Matrix<oc::block>(),
                blocksPerRow = u64(),
                totElements  = u64()
            );

            if(!isDlpnSetupDone)
            {
                std::cerr << "DLPN Receiver is not setupped" << std::endl;
                throw RTE_LOC;
            }
                

            totElements = pi.mPerm.size();
            blocksPerRow = oc::divCeil(bytesPerRow, sizeof(oc::block));

            // Encryption starts here
            aesPlaintext.resize(totElements, blocksPerRow);
            aesCipher.resize(totElements, blocksPerRow);
            dlpnCipher.resize(totElements, blocksPerRow);
            for (u64 i = 0; i < totElements; i++)
            {
                for (u64 j = 0; j < blocksPerRow; j++)
                {
                    if(!invPerm)
                    {
                        auto srcIdx = pi[i] * blocksPerRow + j;
                        aesPlaintext(i,j) = oc::block(0, srcIdx);
                    }
                    else
                    {
                        auto srcIdx = i * blocksPerRow + j;
                        aesPlaintext(pi[i],j) = oc::block(0, srcIdx);
                    }


                }
            }
            oc::mAesFixedKey.ecbEncBlocks(aesPlaintext, aesCipher);

            // std::cout << "Printing permuted AES PlainText" << std::endl;
            // for(int i = 0; i < aesPlaintext.rows() ; i++)
            // {
            //     std::cout << "i = " << i << " plain= "<< aesPlaintext(i,0) << " cipher = " << aesCipher(i,0) << std::endl;   
            // }

            if(!mRecver.isKeyOTsSet)
            {
                std::cerr << "Receiver KeyOTS are not set" << std::endl;
            }

            MC_AWAIT(mRecver.evaluate(aesCipher, dlpnCipher, chl, prng, ole));

            // std::cout << "Printing dlpnCipher 1" << std::endl;
            // for(int i = 0; i < dlpnCipher.size() ; i++)
            // {
            //     std::cout << dlpnCipher(i,0) << std::endl;   
            // }

            delta.resize(totElements, bytesPerRow );
            for (u64 i = 0; i < totElements; i++)
                memcpyMin(delta[i], dlpnCipher[i]);

            // std::cout << "dlpnCipher 1 is added in sout" << std::endl;
            // for(int i = 0; i < totElements ; i++)
            // {
            //     std::cout << hex(sout[i]) << std::endl;   
            // }


            MC_END();
        }


        // DLpn Sender calls this setup
        macoro::task<> setup(
            oc::PRNG& prng,
            coproto::Socket& chl,
            OleGenerator& ole,
            u64 totElements,
            u64 bytesPerRow)
        {

            MC_BEGIN(macoro::task<>, &chl, &prng, &ole, totElements, bytesPerRow, this,
                aesPlaintext = oc::Matrix<oc::block>(),
                aesCipher    = oc::Matrix<oc::block>(),
                preProsdlpnCipher   = oc::Matrix<oc::block>(),
                dlpnCipher   = oc::Matrix<oc::block>(),
                blocksPerRow = u64()
            );

            if(!isDlpnSetupDone)
            {
                std::cerr << "DLPN Sender is not setupped" << std::endl;
                throw RTE_LOC;
            }
                

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
                    preProsdlpnCipher(i,j) = mSender.mPrf.eval(aesCipher(i,j));
                }
                
            }

            // Placing a in sout[0]
            a.resize(totElements, bytesPerRow);
            for (u64 i = 0; i < totElements; i++)
                memcpyMin(a[i], preProsdlpnCipher[i]);

            if(!mSender.isKeyOTsSet || !mSender.isKeySet)
            {
                std::cerr << "Receiver Key or KeyOTS are not set" << std::endl;
            }

            MC_AWAIT(mSender.evaluate(dlpnCipher, chl, prng, ole));

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
            oc::MatrixView<u8> sout,
            u64 bytesPerRow,
            coproto::Socket& chl,
            bool invPerm)
        {
            MC_BEGIN(macoro::task<>, &pi, &chl, sout, bytesPerRow, this, invPerm, 
                xEncrypted = oc::Matrix<u8>(),
                xPermuted = oc::Matrix<u8>(),
                totElements = u64()
            );

            totElements = pi.mPerm.size();
            xPermuted.resize(totElements, bytesPerRow);
            xEncrypted.resize(totElements, bytesPerRow);

            MC_AWAIT(chl.recv(xEncrypted));

            for (u64 i = 0; i < totElements; ++i)
            {
                if(!invPerm){
                    memcpy(xPermuted[i], xEncrypted[pi[i]]);
                }
                else{
                    memcpy(xPermuted[pi[i]], xEncrypted[i]);
                }
                
            }
            
            xorShare(delta, xPermuted, sout);

            MC_END();
        }


        // DLpn Sender calls this apply
        macoro::task<> apply(
            oc::MatrixView<const u8> input,
            oc::MatrixView<u8> sout,
            coproto::Socket& chl)
        {

            MC_BEGIN(macoro::task<>, &chl, input, sout, this,
                xEncrypted = oc::Matrix<u8>(),
                totElements = u64()
            );
            totElements = input.rows();
            xEncrypted.resize(input.rows(), input.cols());

            xorShare(a, input, xEncrypted);

            MC_AWAIT(chl.send(std::move(xEncrypted)));
            
            for (u64 i = 0; i < totElements; ++i)
                memcpy(sout[i], b[i]);


            MC_END();
        }

        template<typename T>
        macoro::task<> apply(
            const Perm& pi,
            u64 bytesPerRow,
            oc::PRNG& prng,
            coproto::Socket& chl,
            OleGenerator& ole,
            oc::MatrixView<T> sout,
            bool invPerm
        )
        {
            oc::MatrixView<u8> oo((u8*)sout.data(), sout.rows(), sout.cols() * sizeof(T));
            return apply<u8>(pi, bytesPerRow, prng, chl, ole, sout, invPerm);
        }



        // If DLPN receiver only wants to call apply
        // this will internally call setup for it
        template<>
        macoro::task<> apply<u8>(
            const Perm& pi,
            u64 bytesPerRow,
            oc::PRNG& prng,
            coproto::Socket& chl,
            OleGenerator& ole,
            oc::MatrixView<u8> sout,
            bool invPerm
        )
        {
            MC_BEGIN(macoro::task<>, &pi, &chl, &prng, &ole, bytesPerRow, this, sout, invPerm);
        
            MC_AWAIT( setup(pi, bytesPerRow, prng, chl, ole, invPerm) );
            MC_AWAIT( apply(pi , sout, bytesPerRow, chl, invPerm) );

            MC_END();

        }


        // Generic version of below method
        template<typename T>
        macoro::task<> apply(
            const Perm& pi,
            oc::PRNG& prng,
            coproto::Socket& chl,
            OleGenerator& ole,
            oc::MatrixView<const T> in,
            oc::MatrixView<T> sout,
            bool invPerm
        )
        {
            oc::MatrixView<const u8> xx((u8*)in.data(), in.rows(), in.cols() * sizeof(T));
            oc::MatrixView<u8> oo((u8*)sout.data(), sout.rows(), sout.cols() * sizeof(T));
            return apply<u8>(pi, prng, chl, ole, xx, oo, invPerm);
        }

        // If DLPN receiver only wants to call apply
        // when it also has inputs
        // this will internally call setup for it
        template<>
        macoro::task<> apply<u8>(
            const Perm& pi,
            oc::PRNG& prng,
            coproto::Socket& chl,
            OleGenerator& ole,
            oc::MatrixView<const u8> in,
            oc::MatrixView<u8> sout,
            bool invPerm
        )
        {
            MC_BEGIN(macoro::task<>, &pi, &chl, &prng, &ole, this, sout, invPerm, in,
                xPermuted = oc::Matrix<u8>(),
                soutPerm  = oc::Matrix<u8>(),
                bytesPerRow = u64()
            );

            bytesPerRow = in.cols();

            xPermuted.resize(in.rows(), in.cols());
            soutPerm.resize( sout.rows(), sout.cols());
            MC_AWAIT( setup(pi, bytesPerRow, prng, chl, ole, invPerm) );
            MC_AWAIT( apply(pi , soutPerm, bytesPerRow, chl, invPerm) );

            pi.apply<u8>(in, xPermuted, invPerm);
            xorShare(xPermuted, soutPerm , sout);

            MC_END();

        }


        // Generic version of below method
        template<typename T>
        macoro::task<> apply(
            oc::PRNG& prng,
            coproto::Socket& chl,
            OleGenerator& ole,
            oc::MatrixView<const T> in,
            oc::MatrixView<T> sout
        )
        {
            oc::MatrixView<const u8> xx((u8*)in.data(), in.rows(), in.cols() * sizeof(T));
            oc::MatrixView<u8> oo((u8*)sout.data(), sout.rows(), sout.cols() * sizeof(T));
            return apply<u8>(prng, chl, ole, xx, oo);
        }

    

        // If DLPN sender only wants to call apply
        // this will internally call setup for it
        template<>
        macoro::task<> apply<u8>(
            oc::PRNG& prng,
            coproto::Socket& chl,
            OleGenerator& ole,
            oc::MatrixView<const u8> input,
            oc::MatrixView<u8> sout
        )
        {
            MC_BEGIN(macoro::task<>, &chl, &prng, &ole, this, input, sout,
                totElements = u64(),
                bytesPerRow = u64() );


            totElements = input.rows();
            bytesPerRow = input.cols();

            MC_AWAIT( setup(prng, chl, ole, totElements, bytesPerRow) );
            MC_AWAIT( apply(input, sout, chl));

            MC_END();


        }



    };

}