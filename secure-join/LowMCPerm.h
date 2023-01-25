#include "LowMC.h"
#include "Permutation.h"
#include "secure-join/GMW/Gmw.h"
#include "coproto/Socket/LocalAsyncSock.h"
#include <bitset>
#include "tests/Common.h"
#include "cryptoTools/Common/Matrix.h"
#include "coproto/coproto.h"

// using coproto::LocalAsyncSocket;

namespace secJoin
{
    
    class LowMCPerm
    {
        public:

        macoro::task<> applyVec(
            Matrix<u8>& x,
            oc::PRNG& prng, 
            u64 n, 
            u64 bytesPerRow, 
            Gmw &gmw0, 
            coproto::Socket& chl, 
            Matrix<u8>& sout)
        {
          
            LowMC2<>::keyblock key;
            prng.get((u8*) &key, sizeof(key));
        
            MC_BEGIN(macoro::task<>, &x, &chl, n, bytesPerRow, &gmw0, &sout, &prng,
            lowMc = LowMC2<>(false, key),
            roundkeys = std::vector<LowMC2<>::block>{},
            cir = oc::BetaCircuit(),
            xEncrypted = oc::Matrix<u8>{},
            roundkeysMatrix = std::vector<Matrix<u8>>{},
            counterMode = u64(),
            blocksPerRow = u64()
            // xEncrypted = oc::MatrixView<LowMC2<>::block>()
            );

            

            roundkeys = lowMc.roundkeys;
        
            // xEncrypted.reshape(n,bytesPerRow);
            blocksPerRow = oc::divCeil(bytesPerRow, sizeof(LowMC2<>::block) );
            xEncrypted.resize(blocksPerRow * n,sizeof(LowMC2<>::block)); 
            // something = MatrixView<LowMC2<>::block>(  (LowMC2<>::block*) xEncrypted.data() , n, bytesPerRow);

            // Encrypting the vector x
            counterMode = 0;
            for(u64 i =0; i < n; ++i)
            {
                
                for(u64 j =0; j < blocksPerRow; ++j)
                {
                    LowMC2<>::block temp;

                    // Minimum between block and remaining size
                    auto minSize = std::min<u64>( sizeof(LowMC2<>::block) ,(x.cols() - (j*sizeof(LowMC2<>::block) )) );
                    memcpy(&temp, &x(i,j*sizeof(LowMC2<>::block)) , minSize);

                    temp = lowMc.encrypt(counterMode) ^ temp;

                    memcpy(xEncrypted[counterMode].data(), &temp , sizeof(LowMC2<>::block));

                
                    // auto& i0s0 = *(LowMC2<>::block*)xEncrypted[counterMode].data();
                    // std::cout << "xEncrypted at " << counterMode << " value is " << i0s0 << std::endl;
                    
                    counterMode++;
                }


            }

            
            MC_AWAIT(chl.send(std::move(xEncrypted)));


            lowMc.to_enc_circuit(cir, true);

            // To enable debugging in the circuit
            // gmw0.mO.mDebug = true;
            // gmw0.mDebugPrintIdx = 1;
            

            gmw0.init(n * blocksPerRow, cir, 1, 0, prng.get());

            // Indexes are set by other party because they have the permutation pi
            gmw0.setZeroInput(0);

            // Encrypted x is set by other party because they have permuted the encrypted x
            gmw0.setZeroInput(1);


            // Setting up the lowmc round keys
            roundkeysMatrix.resize(roundkeys.size());
            for(u64 i=0; i<roundkeysMatrix.size(); i++)
            {
                roundkeysMatrix[i].resize( (n * blocksPerRow), sizeof(roundkeys[i]));

                for(u64 j=0; j< (n * blocksPerRow) ; j++)
                {
                    if(sizeof(roundkeys[i]) != roundkeysMatrix[i][j].size())
                        throw RTE_LOC;
                    memcpy(roundkeysMatrix[i][j].data(), &roundkeys[i] , sizeof(roundkeys[i]));
                }


                // Adding the round keys to the evaluation circuit
                gmw0.setInput(2+i, roundkeysMatrix[i]);
            }

            MC_AWAIT(gmw0.run(chl));

            if(bytesPerRow % sizeof(LowMC2<>::block) == 0)
            {
                sout.reshape(n * blocksPerRow, sizeof(LowMC2<>::block));
                gmw0.getOutput(0, sout);
                sout.reshape(n, bytesPerRow);
            }
            else
            {
                Matrix<u8> temp(n * blocksPerRow, sizeof(LowMC2<>::block), oc::AllocType::Uninitialized);
                gmw0.getOutput(0, temp);

                sout.resize(n,bytesPerRow, oc::AllocType::Uninitialized);
                for(u64 i = 0; i < n;++i)
                {
                    memcpy(sout.data(i), temp.data(i), bytesPerRow);
                }
            }



            MC_END();



        }



        macoro::task<> applyPerm(
            std::vector<u64>& pi, 
            oc::PRNG& prng, 
            u64 n, 
            u64 bytesPerRow, 
            Gmw &gmw1, 
            coproto::Socket& chl, 
            Matrix<u8>& sout)
        {

            LowMC2<>::keyblock key;
            prng.get((u8*) &key, sizeof(key));


            MC_BEGIN(macoro::task<>, &pi, &chl, n, bytesPerRow, &gmw1, &sout, &prng,
            xEncrypted = oc::Matrix<u8>{},
            xPermuted = oc::Matrix<u8>{},
            indexMatrix = oc::Matrix<u8>{},
            lowMc = secJoin::LowMC2<>(false,key),
            cir = oc::BetaCircuit(),
            counterMode = u64(),
            blocksPerRow = u64()
            );
            
            blocksPerRow = oc::divCeil(bytesPerRow, sizeof(LowMC2<>::block) );
            xEncrypted.resize(n * blocksPerRow, sizeof(LowMC2<>::block));
            // xPermuted.reshape(n*bytesPerRow, 1);
            // xEncrypted.reshape(n,bytesPerRow);
            
            
            MC_AWAIT(chl.recv(xEncrypted));
            indexMatrix.resize(n * blocksPerRow,sizeof(LowMC2<>::block));
            // indexMatrix.reshape(n*bytesPerRow, 1);

            xPermuted.resize(n * blocksPerRow,sizeof(LowMC2<>::block));

            // xPermuted = MatrixView<LowMC2<>::block>{ (LowMC2<>::block*) xEncrypted.data() ,n * bytesPerRow , 1 };
            // xPermuted = MatrixView<LowMC2<>::block>{ (LowMC2<>::block*) something.data() ,n * bytesPerRow , 1 };
            
            // indexMatrix = MatrixView<LowMC2<>::block>{ (LowMC2<>::block*) xEncrypted.data() ,n * bytesPerRow , 1 };
            counterMode = 0;
            for(u64 i =0; i < n; ++i)
            {

                for(u64 j=0; j<blocksPerRow; ++j)
                {

                    memcpy(xPermuted[counterMode].data(), xEncrypted[pi[i] * blocksPerRow + j].data() , sizeof(LowMC2<>::block));
                    // xPermuted[counterMode][0] = someMatrix[pi[i]*bytesPerRow + j][0];

                    LowMC2<>::block temp = pi[i] * blocksPerRow + j;
                    memcpy(indexMatrix[counterMode].data(), &temp , sizeof(temp));
                    


                    // std::cout << "xEncrypted at " << counterMode << " value is " << *(LowMC2<>::block*)xEncrypted[counterMode].data() << std::endl;
                    // std::cout << "xPermuted at " << counterMode << " value is " << *(LowMC2<>::block*)xPermuted[counterMode].data() << std::endl;
                    // std::cout << "indexMatrix at " << counterMode << " value is " << *(LowMC2<>::block*)indexMatrix[counterMode].data() << std::endl;


                    counterMode++;
                }


            }
    
            lowMc.to_enc_circuit(cir, true);

            // gmw1.mO.mDebug = true;
            // gmw1.mDebugPrintIdx = 1;


            gmw1.init(n * blocksPerRow, cir, 1, 1, prng.get());

            // Setting the permutated indexes (since we are using the counter mode)
            gmw1.setInput(0, indexMatrix);

            // Setting the permuatated vector
            gmw1.setInput(1,xPermuted);


            for(u8 i=0; i<lowMc.roundkeys.size(); i++)
            {
                gmw1.setZeroInput(2+i);   
            }

            MC_AWAIT(gmw1.run(chl));


            if(bytesPerRow % sizeof(LowMC2<>::block) == 0)
            {
                sout.reshape(n * blocksPerRow, sizeof(LowMC2<>::block));
                gmw1.getOutput(0, sout);
                sout.reshape(n, bytesPerRow);
            }
            else
            {
                Matrix<u8> temp(n * blocksPerRow, sizeof(LowMC2<>::block), oc::AllocType::Uninitialized);
                gmw1.getOutput(0, temp);

                sout.resize(n,bytesPerRow, oc::AllocType::Uninitialized);
                for(u64 i = 0; i < n;++i)
                {
                    memcpy(sout.data(i), temp.data(i), bytesPerRow);
                }
            }
            

            MC_END();


        }




        /*

        template <typename T>
        std::vector<T> reconstruct(std::array<Matrix<u8>, 2> shares)
        {
            std::cout << "The size of T is " << sizeof(T) << std::endl;
            if (shares[0].cols() != sizeof(T))
                throw RTE_LOC;
            if (shares[1].cols() != sizeof(T))
                throw RTE_LOC;
            if (shares[0].rows() != shares[1].rows())
                throw RTE_LOC;

            std::vector<T> ret(shares[0].rows());
            oc::MatrixView<u8> v((u8*)ret.data(), ret.size(), sizeof(T));

            for (u64 i = 0; i < v.size(); ++i)
                v(i) = shares[0](i) ^ shares[1](i);

            return ret;
        }

        Single piece of code to test the whole lowmc stuff

        void dosomething()
        {
            u64 n = 5;

            std::vector<u64> pi(n), z(n);

            oc::PRNG prng(oc::block(0,0));


            std::vector<LowMC2<>::block> x(n),y(n), xEncrypted(n), xPermuted(n);

            for(u64 i =0; i < n; ++i)
            {
                // x[i] = prng0.get<u64>() % n;
                x[i] = i;
                y[i] = prng.get<u64>() % n;
                pi[i] = i;

                // std::cout << "The " << i << "th index value is " << x[i] << std::endl;
            }
                

            const size_t keysize = 80;
            const size_t blocksize = 256;
            // size_t  rounds = 12;
            using keyblock = std::bitset<keysize>;
            using block = std::bitset<blocksize>;

            // Generating the key
            // auto num = prng.get<u64>();
            // std::cout << "The random number is " << num << std::endl;

            // std::cout << "The rounded random number is " << std::fixed << fmod ( num ,  pow(2.0,static_cast<double>(keysize)) ) << std::endl;

            // Setting the maximum keysize to be 2^keysize
            // keyblock key = fmod ( num ,  pow(2.0,static_cast<double>(keysize)) );
            keyblock key = prng.get<u64>();

            // std::cout << "The key is " << key << std::endl;

            LowMC2<> lowMc(false, key); 

            // Initializing the keys
            std::vector<block> keys = lowMc.roundkeys;
            // std::cout << "The keysize is total " << keys.size() << std::endl;

            // algo.encrypt(x[0]);

            // std::vector<LowMC2<>::block> xEncrypted(n);
            for(u64 i =0; i < x.size(); ++i)
            {
                xEncrypted[i] = lowMc.encrypt(x[i]);
                // block bi = ...;
                // xEncrypted[i] = lowMc.encrypt(bi) ^ x[i];
            }


            // Second Party will now permute the data
            for(u64 i =0; i < x.size(); ++i)
            {
                xPermuted[i] = xEncrypted[pi[i]];
            }


            oc::BetaCircuit cir;
            lowMc.to_enc_circuit(cir, false);
            // lowMc.to_prg_circuit(cir);

            // Vector of Matric 13 inputs Matrix(n* blocksize/8)

            // // Creating first person's input (the key)
            std::vector<Matrix<u8>> s0(keys.size());

            for(int i=0; i<s0.size(); i++)
            {
                s0[i].resize(n, sizeof(keys[i]));

                for(int j=0; j<n ; j++)
                {
                    if(sizeof(keys[i]) != s0[i][j].size())
                        throw RTE_LOC;
                    memcpy(s0[i][j].data(), &keys[i] , sizeof(keys[i]));
                }
            }



            // Creating second person's input ( the permuated x vector)
            Matrix<u8> xMatrix(n, sizeof(x[0]));  
            Matrix<u8> indexMatrix(n, sizeof(x[0]));

            for (u64 i = 0; i < n; ++i)
            {
                if(sizeof(x[i]) != xMatrix[i].size())
                    throw RTE_LOC;
                memcpy(xMatrix[i].data(), &x[i] , sizeof(x[i]));
                block temp = i;
                memcpy(indexMatrix[i].data(), &temp , sizeof(temp));

                // memcpy(s1[i].data(), &xPermuted[i] , lowMc.getBlockSize()/8); --> commenting for testing

                // auto& i0s0 = *(LowMC2<>::block*)s0[i].data();
                // std::cout << "The matrix value is " << i0s0 << std::endl;
            }  

            Gmw gmw0, gmw1;
            gmw0.mO.mDebug = true;
            gmw1.mO.mDebug = true;
            gmw0.mDebugPrintIdx = 1;
            gmw1.mDebugPrintIdx = 1;
            

            gmw0.init(n, cir, 1, 0, oc::ZeroBlock);
            gmw1.init(n, cir, 1, 1, oc::OneBlock);

            // gmw0.setInput(0, indexMatrix);
            // gmw1.setZeroInput(0);

            gmw0.setInput(0,xMatrix);
            gmw1.setZeroInput(0);

            for(int i=0; i<s0.size(); i++)
            {
                gmw0.setZeroInput(1+i);
                gmw1.setInput(1+i, s0[i]);
            }


            auto sockets = coproto::LocalAsyncSocket::makePair();

            auto p0 = gmw0.run(sockets[0]);
            auto p1 = gmw1.run(sockets[1]);
            eval(p0, p1);

            std::array<Matrix<u8>, 2> sout;
            sout[0].resize(n, blocksize/8);
            sout[1].resize(n, blocksize/8);


            gmw0.getOutput(0, sout[0]);
            gmw1.getOutput(0, sout[1]);

            auto out = reconstruct<block>(sout);

            for (u64 i = 0; i < n; ++i)
            {
                block temp = i;
                std::cout << "out[i] is " << out[i] << std::endl;
                std::cout << "lowMc.encrypt(temp) is " << lowMc.encrypt(temp) << std::endl;
                std::cout << "final is " << (lowMc.encrypt(temp) ^ x[i]) << std::endl;
 
                

                // if (out[i] != (lowMc.encrypt(temp) ^ x[i]))
                // {
                //     throw RTE_LOC;
                // }
                if (out[i] != lowMc.encrypt(x[i]))
                {
                    throw RTE_LOC;
                }
            }
            
        }
        */



        
    };
}