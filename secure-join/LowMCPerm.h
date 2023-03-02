#pragma once

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
        static const LowMC2<> mLowMc;

        static const oc::BetaCircuit mLowMcCir;

        static macoro::task<> applyVec(
            oc::Matrix<u8>& x1,
            oc::PRNG& prng,
            Gmw& gmw0,
            coproto::Socket& chl,
            oc::Matrix<u8>& sout)
        {


            MC_BEGIN(macoro::task<>, &x1, &chl, &gmw0, &sout, &prng,
                n = u64(x1.rows()),
                bytesPerRow = u64(x1.cols()),
                roundkeys = std::vector<LowMC2<>::block>{},
                xEncrypted = oc::Matrix<u8>{},
                roundkeysMatrix = std::vector<oc::Matrix<u8>>{},
                counterMode = u64(),
                blocksPerRow = u64(),
                lowMc = mLowMc
            );

            {
                LowMC2<>::keyblock key;
                prng.get((u8*)&key, sizeof(key));
                lowMc.set_key(key);
            }

            roundkeys = lowMc.roundkeys;

            // xEncrypted.reshape(n,bytesPerRow);
            blocksPerRow = oc::divCeil(bytesPerRow, sizeof(LowMC2<>::block));
            xEncrypted.resize(blocksPerRow * n, sizeof(LowMC2<>::block));
            // something = MatrixView<LowMC2<>::block>(  (LowMC2<>::block*) xEncrypted.data() , n, bytesPerRow);

            // Encrypting the vector x
            counterMode = 0;
            for (u64 i = 0; i < n; ++i)
            {

                for (u64 j = 0; j < blocksPerRow; ++j)
                {
                    LowMC2<>::block temp;

                    // Minimum between block and remaining size
                    auto minSize = std::min<u64>(sizeof(LowMC2<>::block), (x1.cols() - (j * sizeof(LowMC2<>::block))));
                    memcpy(&temp, &x1(i, j * sizeof(LowMC2<>::block)), minSize);

                    temp = lowMc.encrypt(counterMode) ^ temp;

                    memcpy(xEncrypted[counterMode].data(), &temp, sizeof(LowMC2<>::block));


                    // auto& i0s0 = *(LowMC2<>::block*)xEncrypted[counterMode].data();
                    // std::cout << "xEncrypted at " << counterMode << " value is " << i0s0 << std::endl;

                    counterMode++;
                }


            }


            MC_AWAIT(chl.send(std::move(xEncrypted)));


            // To enable debugging in the circuit
            // gmw0.mO.mDebug = true;
            // gmw0.mDebugPrintIdx = 1;


            gmw0.init(n * blocksPerRow, mLowMcCir, 1, 0, prng.get());

            // Indexes are set by other party because they have the permutation pi
            gmw0.setZeroInput(0);

            // Encrypted x is set by other party because they have permuted the encrypted x
            gmw0.setZeroInput(1);


            // Setting up the lowmc round keys
            roundkeysMatrix.resize(roundkeys.size());
            for (u64 i = 0; i < roundkeysMatrix.size(); i++)
            {
                // std::cout << "Setting up round key " << i << std::endl;
                roundkeysMatrix[i].resize((n * blocksPerRow), sizeof(roundkeys[i]));

                for (u64 j = 0; j < (n * blocksPerRow); j++)
                {
                    if (sizeof(roundkeys[i]) != roundkeysMatrix[i][j].size())
                        throw RTE_LOC;
                    memcpy(roundkeysMatrix[i][j].data(), &roundkeys[i], sizeof(roundkeys[i]));
                }


                // Adding the round keys to the evaluation circuit
                gmw0.setInput(2 + i, roundkeysMatrix[i]);
            }

            MC_AWAIT(gmw0.run(chl));

            if (bytesPerRow % sizeof(LowMC2<>::block) == 0)
            {
                sout.reshape(n * blocksPerRow, sizeof(LowMC2<>::block));
                gmw0.getOutput(0, sout);
                sout.reshape(n, bytesPerRow);
            }
            else
            {
                oc::Matrix<u8> temp(n * blocksPerRow, sizeof(LowMC2<>::block), oc::AllocType::Uninitialized);
                gmw0.getOutput(0, temp);

                // std::cout << "applyVec GMW got the output" << std::endl;

                sout.resize(n, bytesPerRow, oc::AllocType::Uninitialized);
                for (u64 i = 0; i < n; ++i)
                {
                    memcpy(sout.data(i), temp.data(i), bytesPerRow);
                }
            }



            MC_END();
        }



        static macoro::task<> applyVecPerm(
            oc::Matrix<u8>& x2,
            std::vector<u64>& pi,
            oc::PRNG& prng,
            Gmw& gmw1,
            coproto::Socket& chl,
            oc::Matrix<u8>& sout,
            bool invPerm)
        {

            MC_BEGIN(macoro::task<>, &x2, &pi, &chl, &gmw1, &sout, &prng, invPerm,
                n = u64(x2.rows()),
                bytesPerRow = u64(x2.cols()),
                x2Perm = oc::Matrix<u8>{}
            );


            MC_AWAIT(LowMCPerm::applyPerm(pi, prng, n, bytesPerRow, gmw1, chl, sout, invPerm));

            x2Perm.resize(x2.rows(), x2.cols());

            // Permuting the secret shares x2
            for (u64 i = 0; i < n; ++i)
            {

                if (invPerm)
                    memcpy(x2Perm.data(i), x2.data(pi[i]), bytesPerRow);
                else
                    memcpy(x2Perm.data(pi[i]), x2.data(i), bytesPerRow);
            }

            for (u64 i = 0; i < sout.rows(); ++i)
            {

                for (u64 j = 0; j < sout.cols(); j++)
                {
                    // sout combined with x Permuted
                    sout(i, j) = sout(i, j) ^ x2Perm(i, j);
                }
            }

            MC_END();


        }


        static macoro::task<> applyPerm(
            std::vector<u64>& pi,
            oc::PRNG& prng,
            u64 n,
            u64 bytesPerRow,
            Gmw& gmw1,
            coproto::Socket& chl,
            oc::Matrix<u8>& sout,
            bool invPerm)
        {

            LowMC2<>::keyblock key;
            prng.get((u8*)&key, sizeof(key));


            MC_BEGIN(macoro::task<>, &pi, &chl, n, bytesPerRow, &gmw1, &sout, &prng, invPerm,
                xEncrypted = oc::Matrix<u8>{},
                xPermuted = oc::Matrix<u8>{},
                indexMatrix = oc::Matrix<u8>{},
                counterMode = u64(),
                blocksPerRow = u64()
            );

            blocksPerRow = oc::divCeil(bytesPerRow, sizeof(LowMC2<>::block));
            xEncrypted.resize(n * blocksPerRow, sizeof(LowMC2<>::block));
            // xPermuted.reshape(n*bytesPerRow, 1);
            // xEncrypted.reshape(n,bytesPerRow);


            MC_AWAIT(chl.recv(xEncrypted));

            if ((pi.size() != n) || (blocksPerRow * n != xEncrypted.rows()))
                throw RTE_LOC;

            indexMatrix.resize(n * blocksPerRow, sizeof(LowMC2<>::block));
            // indexMatrix.reshape(n*bytesPerRow, 1);

            xPermuted.resize(n * blocksPerRow, sizeof(LowMC2<>::block));

            // xPermuted = MatrixView<LowMC2<>::block>{ (LowMC2<>::block*) xEncrypted.data() ,n * bytesPerRow , 1 };
            // xPermuted = MatrixView<LowMC2<>::block>{ (LowMC2<>::block*) something.data() ,n * bytesPerRow , 1 };

            // indexMatrix = MatrixView<LowMC2<>::block>{ (LowMC2<>::block*) xEncrypted.data() ,n * bytesPerRow , 1 };
            counterMode = 0;
            for (u64 i = 0; i < n; ++i)
            {

                for (u64 j = 0; j < blocksPerRow; ++j)
                {

                    if (invPerm)
                    {
                        auto dst = counterMode;
                        auto src = pi[i] * blocksPerRow + j;


                        memcpy(xPermuted[counterMode].data(),
                            xEncrypted[pi[i] * blocksPerRow + j].data(),
                            sizeof(LowMC2<>::block));
                        // xPermuted[counterMode][0] = someMatrix[pi[i]*bytesPerRow + j][0];

                        LowMC2<>::block temp = pi[i] * blocksPerRow + j;
                        memcpy(indexMatrix[counterMode].data(), &temp, sizeof(temp));
                    }
                    else
                    {
                        auto src = counterMode;
                        auto dst = pi[i] * blocksPerRow + j;

                        assert(src + sizeof(LowMC2<>::block) < xEncrypted.size());
                        assert(dst + sizeof(LowMC2<>::block) < xPermuted.size());


                        memcpy(xPermuted[pi[i] * blocksPerRow + j].data(),
                            xEncrypted[counterMode].data(),
                            sizeof(LowMC2<>::block));

                        LowMC2<>::block temp = i * blocksPerRow + j;
                        memcpy(indexMatrix[pi[i] * blocksPerRow + j].data(), &temp, sizeof(temp));
                    }

                    counterMode++;
                }

            }

            // gmw1.mO.mDebug = true;
            // gmw1.mDebugPrintIdx = 1;


            gmw1.init(n * blocksPerRow, mLowMcCir, 1, 1, prng.get());

            // Setting the permutated indexes (since we are using the counter mode)
            gmw1.setInput(0, indexMatrix);

            // Setting the permuatated vector
            gmw1.setInput(1, xPermuted);


            for (u8 i = 0; i < mLowMc.roundkeys.size(); i++)
            {
                gmw1.setZeroInput(2 + i);
            }

            MC_AWAIT(gmw1.run(chl));

            if (bytesPerRow % sizeof(LowMC2<>::block) == 0)
            {
                sout.reshape(n * blocksPerRow, sizeof(LowMC2<>::block));
                gmw1.getOutput(0, sout);
                sout.reshape(n, bytesPerRow);
            }
            else
            {
                oc::Matrix<u8> temp(n * blocksPerRow, sizeof(LowMC2<>::block), oc::AllocType::Uninitialized);
                gmw1.getOutput(0, temp);

                sout.resize(n, bytesPerRow, oc::AllocType::Uninitialized);
                for (u64 i = 0; i < n; ++i)
                {
                    memcpy(sout.data(i), temp.data(i), bytesPerRow);
                }
            }


            MC_END();


        }

    };
}