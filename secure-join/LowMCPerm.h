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

        macoro::task<> applyVec(std::vector<LowMC2<>::block>& x, oc::PRNG& prng, u64 n, Gmw &gmw0,coproto::Socket& chl)
        {
          
            LowMC2<>::keyblock key;
            prng.get((u8*) &key, sizeof(key));
        
            MC_BEGIN(macoro::task<>, &x, &chl, n, &gmw0,
            lowMc = LowMC2<>(false, key),
            roundkeys = std::vector<LowMC2<>::block>{},
            cir = oc::BetaCircuit(),
            // xMatrix =  oc::Matrix<u8>{},
            xEncrypted = oc::Matrix<u8>{},
            roundkeysMatrix = std::vector<Matrix<u8>>{}
            );

            roundkeys = lowMc.roundkeys;
        

            xEncrypted.resize(x.size(),sizeof(LowMC2<>::block)); 

            // Encrypting the vector x
            for(u64 i =0; i < x.size(); ++i)
            {
                LowMC2<>::block temp = lowMc.encrypt(i) ^ x[i] ;
                memcpy(xEncrypted[i].data(), &temp , sizeof(LowMC2<>::block));

                // auto& i0s0 = *(LowMC2<>::block*)xEncrypted[i].data();
                // std::cout << "The encrypted value is " << i0s0 << std::endl;
                
            }

            MC_AWAIT(chl.send(std::move(xEncrypted)));


            lowMc.to_enc_circuit(cir, true);

            // To enable debugging in the circuit
            // gmw0.mO.mDebug = true;
            // gmw0.mDebugPrintIdx = 1;
            

            gmw0.init(n, cir, 1, 0, oc::ZeroBlock);

            // Indexes are set by other party because they have the permutation pi
            gmw0.setZeroInput(0);

            // Encrypted x is set by other party because they have permuted the encrypted x
            gmw0.setZeroInput(1);

            roundkeysMatrix.resize(roundkeys.size());

            // Setting up the lowmc round keys
            for(u64 i=0; i<roundkeysMatrix.size(); i++)
            {
                roundkeysMatrix[i].resize(n, sizeof(roundkeys[i]));

                for(u64 j=0; j<n ; j++)
                {
                    if(sizeof(roundkeys[i]) != roundkeysMatrix[i][j].size())
                        throw RTE_LOC;
                    memcpy(roundkeysMatrix[i][j].data(), &roundkeys[i] , sizeof(roundkeys[i]));
                }


                // Adding the round keys to the evaluation circuit
                gmw0.setInput(2+i, roundkeysMatrix[i]);
            }

            MC_END();



        }



        macoro::task<> applyPerm(
            std::vector<u64>& pi,
            oc::PRNG& prng,          
            u64 n,
            Gmw &gmw1,
            coproto::Socket& chl)
        {

            LowMC2<>::keyblock key;
            prng.get((u8*) &key, sizeof(key));



            MC_BEGIN(macoro::task<>, &pi, &chl,n,&gmw1,
            xEncrypted = oc::Matrix<u8>{},
            xPermuted = oc::Matrix<u8>{},
            indexMatrix = oc::Matrix<u8>{},
            lowMc = secJoin::LowMC2<>(false,key),
            totalNumberOfRounds = size_t(),
            cir = oc::BetaCircuit()
            );
            totalNumberOfRounds = lowMc.roundkeys.size();

            xEncrypted.resize(pi.size(),sizeof(LowMC2<>::block));
            xPermuted.resize(pi.size(),sizeof(LowMC2<>::block));
            MC_AWAIT(chl.recv(xEncrypted));

            // xEncrypted.resize(pi.size()); // --> Why do we need to do this? // Why is this not working


            indexMatrix.resize(n, sizeof(LowMC2<>::block));

            for(u64 i =0; i < pi.size(); ++i)
            {
                memcpy(xPermuted[i].data(), xEncrypted[pi[i]].data() , sizeof(LowMC2<>::block));

                LowMC2<>::block temp = pi[i];
                memcpy(indexMatrix[i].data(), &temp , sizeof(temp));

                // auto& i0s0 = *(LowMC2<>::block*)indexMatrix[i].data();
                // std::cout << "The encrypted value is " << i0s0 << std::endl;
            }
    
            lowMc.to_enc_circuit(cir, true);

            // gmw1.mO.mDebug = true;
            // gmw1.mDebugPrintIdx = 1;

            gmw1.init(n, cir, 1, 1, oc::OneBlock);

            // Setting the permutated indexes (since we are using the counter mode)
            gmw1.setInput(0, indexMatrix);

            // Setting the permuatated vector
            gmw1.setInput(1,xPermuted);


            for(u8 i=0; i<totalNumberOfRounds; i++)
            {
                gmw1.setZeroInput(2+i);   
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