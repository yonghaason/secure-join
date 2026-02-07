// #include "AltModPID.h"
#include <iostream>
#include "secure-join/PID/AltModPID.h"
#include "secure-join/Kunlun/mpc/oprf/ddh_oprf.hpp"
#include "secure-join/Kunlun/crypto/prg.hpp"
#include "secure-join/Kunlun/crypto/setup.hpp"
#include "cryptoTools/Crypto/AES.h"


using namespace std;

namespace secJoin
{
    u64 log_batch2 = 22;

    oc::Timer timer;

    Proto AltModPidSender::evalOPRF(span<block> Y, u64 XSize, PRNG& prng, Socket& chl)
        {

            SenderSetSize = Y.size();

            // run two OPRF

            // OPRF 1
            CorGenerator ole1;
            ole1.init(chl.fork(), prng, 1, 1, 1 << log_batch2, 0);
            oc::SilentOtExtSender keyOtSender;
            std::vector<std::array<oc::block, 2>> sk(AltModPrf::KeySize);
            keyOtSender.configure(AltModPrf::KeySize);
            co_await keyOtSender.send(sk, prng, chl);

            AltModWPrfReceiver recver;
            recver.init(Y.size(), ole1, AltModPrfKeyMode::SenderOnly, AltModPrfInputMode::ReceiverOnly, {}, sk);
            recver.mUseMod2F4Ot = true;

            vector<block> SenderOPRFValue(Y.size());
            vector<block> SenderOPRFValue2(Y.size());

            co_await macoro::when_all_ready(
                ole1.start(),
                recver.evaluate(Y, SenderOPRFValue, chl, prng)
            );

            SenderOPRFValue2.resize(Y.size());
            co_await(chl.recv(SenderOPRFValue2));

            // OPRF 2

            AltModPrf temp(prng.get());
            if (flag == 0){
                dm = temp;
                flag = 1;
            }
            vector<block> myPRF(Y.size());

            dm.eval(Y, myPRF);

            CorGenerator ole0;
            ole0.init(chl.fork(), prng, 0, 1, 1 << log_batch2, 0);
            oc::SilentOtExtReceiver keyOtReceiver;
            std::vector<oc::block> rk(AltModPrf::KeySize);
            keyOtReceiver.configure(AltModPrf::KeySize);
            oc::BitVector kk_bv;
            kk_bv.append((u8*)dm.getKey().data(), AltModPrf::KeySize);

            co_await keyOtReceiver.receive(kk_bv, rk, prng, chl);

            AltModWPrfSender sender;
            sender.init(XSize, ole0, AltModPrfKeyMode::SenderOnly, AltModPrfInputMode::ReceiverOnly, dm.getKey(), rk); // Should be Y size

            sender.mUseMod2F4Ot = true;

            vector<block> ReceiverOPRFValue(XSize);

            co_await macoro::when_all_ready(
                ole0.start(),
                sender.evaluate({}, ReceiverOPRFValue, chl, prng)
            );

            co_await(chl.send(ReceiverOPRFValue));

            OPRFSum.resize((Y.size()));

            for (int i = 0; i < OPRFSum.size(); i++)
                OPRFSum[i] = SenderOPRFValue2[i] ^ SenderOPRFValue[i] ^ myPRF[i];

        }


    Proto AltModPidReceiver::evalOPRF(span<block> X, u64 YSize,PRNG& prng, Socket& chl)
        {
            ReceiverSetSize = X.size();

            // run two OPRF
            
            timer.setTimePoint("OPRF1 start");
            // OPRF 1
            AltModPrf temp(prng.get());
            std::cout << "flag is " << flag;
            if (flag == 0){
                dm = temp;
                flag = 1;
            }

            std::cout << ", key is " << dm.getKey() << '\n';
            
            vector<block> myPRF(X.size());

            dm.eval(X, myPRF);

            CorGenerator ole0;
            ole0.init(chl.fork(), prng, 0, 1, 1 << log_batch2, 0);
            oc::SilentOtExtReceiver keyOtReceiver;
            std::vector<oc::block> rk(AltModPrf::KeySize);
            keyOtReceiver.configure(AltModPrf::KeySize);
            oc::BitVector kk_bv;
            kk_bv.append((u8*)dm.getKey().data(), AltModPrf::KeySize);

            co_await keyOtReceiver.receive(kk_bv, rk, prng, chl);

            AltModWPrfSender sender;
            sender.init(YSize, ole0, AltModPrfKeyMode::SenderOnly, AltModPrfInputMode::ReceiverOnly, dm.getKey(), rk); // Should be Y size

            sender.mUseMod2F4Ot = true;

            vector<block> SenderOPRFValue(YSize);

            co_await macoro::when_all_ready(
                ole0.start(),
                sender.evaluate({}, SenderOPRFValue, chl, prng)
            );

            co_await(chl.send(SenderOPRFValue));

            timer.setTimePoint("OPRF1 End");

            //OPRF2

            CorGenerator ole1;
            ole1.init(chl.fork(), prng, 1, 1, 1 << log_batch2, 0);
            oc::SilentOtExtSender keyOtSender;
            std::vector<std::array<oc::block, 2>> sk(AltModPrf::KeySize);
            keyOtSender.configure(AltModPrf::KeySize);
            co_await keyOtSender.send(sk, prng, chl);

            AltModWPrfReceiver recver;
            recver.init(X.size(), ole1, AltModPrfKeyMode::SenderOnly, AltModPrfInputMode::ReceiverOnly, {}, sk);
            recver.mUseMod2F4Ot = true;

            vector<block> ReceiverOPRFValue(X.size());
            vector<block> ReceiverOPRFValue2(X.size());

            co_await macoro::when_all_ready(
                ole1.start(),
                recver.evaluate(X, ReceiverOPRFValue, chl, prng)
            );

            ReceiverOPRFValue2.resize(X.size());
            co_await(chl.recv(ReceiverOPRFValue2));

            timer.setTimePoint("OPRF2 End");

            OPRFSum.resize((X.size()));
            
            for (int i = 0; i < OPRFSum.size(); i++)
                OPRFSum[i] = ReceiverOPRFValue2[i] ^ ReceiverOPRFValue[i] ^ myPRF[i];

            timer.setTimePoint("End OPRF eval");

    }

    template <typename T>
	struct Buffer : public span<T>
	{
		std::unique_ptr<T[]> mPtr;

		void resize(u64 s)
		{
			mPtr.reset(new T[s]);
			static_cast<span<T>&>(*this) = span<T>(mPtr.get(), s);
		}
	};


    Proto AltModPidSender::evalRR22(span<block> Y, u64 XSize, PRNG& prng, Socket& chl)
        {
            // std::cout << "point1";

            // run two OPRF, init
                  
            // Hash0, Hash1
            AES H0(oc::AllOneBlock), H1(oc::OneBlock);

            // if OPRFkey is Zero, set OPRFkey

            if (OPRFkey.size() == 0){
                OPRFkey.resize(XSize);
                // prng.get<block>(OPRFkey);
                myKeySize = Y.size();
                initSetSize = Y.size();
                mPaxos.init(OPRFkey.size(), mBinSize, 3, mSsp, PaxosParam::GF128, oc::ZeroBlock);
                OPRFkey.resize(mPaxos.size());
                prng.get<block>(OPRFkey);
                delta = prng.get<block>();
                Paxos.init(initSetSize, mBinSize, 3, mSsp, PaxosParam::GF128, oc::ZeroBlock);
            }

            // Paxos.init(initSetSize, mBinSize, 3, mSsp, PaxosParam::GF128, oc::ZeroBlock);
            // mPaxos.init(XSize, mBinSize, 3, mSsp, PaxosParam::GF128, oc::ZeroBlock);

            int mySetSize = Y.size();
            myKeySize = Paxos.size();
            int OtherPartySetSize = mPaxos.size();
            
            Baxos PaxosTemp;
            PaxosTemp.init(XSize, mBinSize, 3, mSsp, PaxosParam::GF128, oc::ZeroBlock);

            // Baxos Paxos2;
            // Paxos2.init(initSetSize, mBinSize, 3, mSsp, PaxosParam::GF128, oc::ZeroBlock);

            // OtherPartySetSize = PaxosTemp.size();

            // std::cout << "\nY.size is " << Y.size() << " myKeySize is " << myKeySize << "\n\n";

            std::vector<block> myOPRFValue(mySetSize), PRFValue(mySetSize);

            // vole, c = a + delta * b
            std::vector<block> VecA(myKeySize), VecB(myKeySize), VecC(OtherPartySetSize);
            prng.get<block>(VecA);
            prng.get<block>(VecB);

            // random vole variant
            std::vector<block> rVecA(myKeySize), rVecB(myKeySize), rVecC(OtherPartySetSize);
            block rDelta = prng.get<block>();

            std::vector<block> tVecA(myKeySize), tVecB(myKeySize);
            block tDelta;

            // Baxos PaxosTemp;
            // PaxosTemp.init(XSize, mBinSize, 3, mSsp, PaxosParam::GF128, oc::ZeroBlock);
            std::vector<block> tVecArecv(OtherPartySetSize), tVecBrecv(OtherPartySetSize);

            std::vector<block> VecQ(myKeySize), VecP(OtherPartySetSize);

            // OPRF1

            //invoke random vole

            // std::cout << "\nPaxos.size() is " << Paxos.size() << " mPaxos.size() is " << mPaxos.size() << "\n\n";

            co_await(mVoleRecver.silentReceiveInplace(Paxos.size(), prng, chl));

            // make VecA and compute VecB
            rVecA.assign(mVoleRecver.mA.begin(), mVoleRecver.mA.end());
            rVecB.assign(mVoleRecver.mC.begin(), mVoleRecver.mC.end());
            
            // fill out Y by dumy data

            std::vector<block> FillY(initSetSize);
            prng.get<block>(FillY);

            for (int i = 0; i < Y.size(); i++)
                FillY[i] = Y[i];

            std::vector<block> H1Value(FillY);
            H1.ecbEncBlocks(FillY.data(), FillY.size(), H1Value.data());
            
            prng.get<block>(VecA);

            // make mB = B - B' and mA = A - A' + delta' * B, and send it

            co_await(chl.recv(tDelta));
            co_await(chl.flush());

            VecB.resize(Paxos.size());

            // std::cout << "Sender: Y size is " << Y.size() << " H1Value size is " << H1Value.size() << " VecB size is " << VecB.size() << " Paxos size is " << Paxos.size() << '\n';

            Paxos.solve<block>(FillY, H1Value, VecB, nullptr, numThreads);

            // mA = A - A' + delta' * B
            for (int i = 0; i < VecA.size(); i++){
                tVecA[i] = VecA[i] ^ rVecA[i] ^ tDelta.gf128Mul(VecB[i]);
            }

            // mB = B - B'
            for(int i = 0; i < myKeySize; i++ ){
                tVecB[i] = VecB[i] ^ rVecB[i];
            }

            // std::cout << "Sender: tVecA size is " << tVecA.size() << " tVecB size is " << tVecB.size() << " VecP size is " << VecP.size() << '\n';
        
            co_await(chl.send(tVecA));
            co_await(chl.send(tVecB));

            co_await(chl.flush());

            // std::cout << "Sender: Protocol end\n";
            // if (Y.size() == 1024)
            //     exit(1);

            co_await(chl.recv(VecQ));

            // Q = P - A = R + delta * B
            for(int i = 0; i < myKeySize; i++ ){
                VecQ[i] = VecQ[i] ^ VecA[i];
            }

            std::vector<block> OKVSDecodeValue2(mySetSize);

            // compute Decode(Q, x)
            // Decode(Q, x) = Decode(R + delta * B, y)
            //              = Decode(R, y) + Decode(delta * B, y)
            //              = Decode(R, y) + delta * Decode(B, y)
            //              = Decode(R, y) + delta * H1(y), B = Encode(y, H1(y))
            Paxos.decode<block>(Y, OKVSDecodeValue2, VecQ, numThreads);

            // std::cout << "VecQ is " << VecQ[0] << '\n';
            // std::cout << "Sender OPRF2[1] is " << OKVSDecodeValue2[1] << '\n';

            // compute H0 (Decode(Q, x))
            H0.ecbEncBlocks(OKVSDecodeValue2.data(), OKVSDecodeValue2.size(), myOPRFValue.data());

            // std::cout << "Sender H0(OPRF2[1]) is " << myOPRFValue[1] << '\n';

            // OPRF2 - Vole from Random Vole

            // random vole
            co_await(mVoleSender.silentSendInplace(rDelta, mPaxos.size(), prng, chl));
            // std::cout << "point4";
            // rVecC = mVoleSender.mB;
            rVecC.assign(mVoleSender.mB.begin(), mVoleSender.mB.end());
            tDelta = delta ^ rDelta;

            co_await(chl.send(tDelta));

            co_await(chl.recv(tVecArecv));
            co_await(chl.recv(tVecBrecv));

            for (int i = 0; i < OtherPartySetSize;i++){
                VecC[i] = rVecC[i] ^ tVecArecv[i] ^ rDelta.gf128Mul(tVecBrecv[i]);
            }
            // std::cout << "Sender: Point 1 " << "\n";

            // OPRF2 - make key fixed OPRF

            for(int i = 0; i < OtherPartySetSize; i++ ){
                VecP[i] = OPRFkey[i] ^ VecC[i];
            }
            
            co_await(chl.send(VecP));

            // compute my OPRF2 value using key

            std::vector<block> tValue(mySetSize);
            std::vector<block> OKVSDecodeValue(mySetSize);
            H1Value.resize(mySetSize);

            mPaxos.decode<block>(Y, OKVSDecodeValue, OPRFkey, numThreads);
        
            // std::cout << "OPRFkey is " << OPRFkey[0] << '\n';
            // std::cout << "Sender OPRF1[1] is " << OKVSDecodeValue[1] << '\n';

            // compute H1(x)
            H1.ecbEncBlocks(Y.data(), mySetSize, H1Value.data());
            // std::cout << "point5";
            for (int i = 0; i < mySetSize; i++){
                H1Value[i] = delta.gf128Mul(H1Value[i]);
            }
            // std::cout << "\nSender delta * H1(y) is " << H1Value[1] << '\n';
            
            for(int i = 0; i < mySetSize; i++ ){
                tValue[i] = OKVSDecodeValue[i] ^ H1Value[i];
            }

            // compute H0(Decode(OPRFkey), x) + delta * H1(x))

            // std::cout << "\nSender OPRF1[1] ^ delta * H1(y) is " << tValue[1] << '\n';
            H0.ecbEncBlocks(tValue.data(), tValue.size(), PRFValue.data());

            // std::cout << "\nSender H1(OPRF1[1] ^ delta * H1(y)) is " << PRFValue[1] << '\n';

            // make/update OPRFTable
            int tempValue;
            if (OPRFTable.size() == 0){
                OPRFTable.resize(mySetSize);
                for(int i = 0; i < OPRFTable.size(); i++){
                    OPRFTable[i] = myOPRFValue[i] ^ PRFValue[i];
                }
            }
            else{
                tempValue = OPRFTable.size();
                // std::cout << "tempValue is " << tempValue << " update size is " << (tempValue + mySetSize) << " updated data[1] is " << (myOPRFValue[1] ^ PRFValue[1]) << " 1-th origianl data is " << Y[1] << '\n';
                OPRFTable.resize(tempValue + mySetSize);
                // std::cout << "tempValue is " << tempValue << " OPRFTable size is " << OPRFTable.size() << '\n';
                for(int i = tempValue; i < OPRFTable.size(); i++){
                    
                    OPRFTable[i] = myOPRFValue[i - tempValue] ^ PRFValue[i - tempValue];

                }

            }

            // std::cout << ("End OPRF eval\n");
        }


    Proto AltModPidReceiver::evalRR22(span<block> X, u64 YSize,PRNG& prng, Socket& chl)
        {
      
            // Hash0, Hash1
            AES H0(oc::AllOneBlock), H1(oc::OneBlock);

            // if OPRFkey is Zero, set OPRFkey
            oc::Timer timer;

            // timer.setTimePoint("RR22 start");

            if (OPRFkey.size() == 0){
                // std::cout << "Enter this if cause\n";
                OPRFkey.resize(YSize);
                // prng.get<block>(OPRFkey);
                myKeySize = X.size();
                initSetSize = X.size();
                mPaxos.init(OPRFkey.size(), mBinSize, 3, mSsp, PaxosParam::GF128, oc::ZeroBlock);
                OPRFkey.resize(mPaxos.size());
                prng.get<block>(OPRFkey);
                delta = prng.get<block>();
                Paxos.init(initSetSize, mBinSize, 3, mSsp, PaxosParam::GF128, oc::ZeroBlock);
            }

            // Paxos.init(initSetSize, mBinSize, 3, mSsp, PaxosParam::GF128, oc::ZeroBlock);

            int mySetSize = X.size();
            myKeySize = Paxos.size();
            int OtherPartySetSize = mPaxos.size();

            std::vector<block> myOPRFValue(mySetSize), PRFValue(mySetSize);
            
            Baxos PaxosTemp;
            PaxosTemp.init(YSize, mBinSize, 3, mSsp, PaxosParam::GF128, oc::ZeroBlock);

            // vole, c = a + delta * b
            std::vector<block> VecA(myKeySize), VecB(myKeySize), VecC(OtherPartySetSize);
            prng.get<block>(VecA);
            prng.get<block>(VecB);

            // random vole variant
            std::vector<block> rVecA(myKeySize), rVecB(myKeySize), rVecC(OtherPartySetSize);
            block rDelta = prng.get<block>();

            std::vector<block> tVecA(myKeySize), tVecB(myKeySize);
            block tDelta;
            // Baxos PaxosTemp;
            // PaxosTemp.init(YSize, mBinSize, 3, mSsp, PaxosParam::GF128, oc::ZeroBlock);
            std::vector<block> tVecArecv(OtherPartySetSize), tVecBrecv(OtherPartySetSize);

            std::vector<block> VecQ(myKeySize), VecP(OtherPartySetSize);

            // timer.setTimePoint("RR22 init (define)");

            // OPRF1 - Vole from Random Vole

            // random vole

            // std::cout << "rVOLE Paxos.size is " << Paxos.size() << "\n";

            co_await(mVoleSender.silentSendInplace(rDelta, Paxos.size(), prng, chl));

            // timer.setTimePoint("RR22 1 rVOLE");

            // rVecC = mVoleSender.mB;
            rVecC.assign(mVoleSender.mB.begin(), mVoleSender.mB.end());
            tDelta = delta ^ rDelta;

            co_await(chl.send(tDelta));
            co_await(chl.flush());

            co_await(chl.recv(tVecArecv));
            co_await(chl.recv(tVecBrecv));

            // timer.setTimePoint("RR22 1 VOLE form rVOLE");

            // std::cout << "Receiver: Protocol end\n";
            // if (X.size() == 1024)
            //     exit(1);

            for (int i = 0; i < OtherPartySetSize;i++){
                // random vole C' = A' + delta' * B'에서 곱하기 연산이 XOR로 되는가?
                VecC[i] = rVecC[i] ^ tVecArecv[i] ^ rDelta.gf128Mul(tVecBrecv[i]);
            }

            // OPRF1 - make key fixed OPRF

            for(int i = 0; i < OtherPartySetSize; i++ ){
                VecP[i] = OPRFkey[i] ^ VecC[i];
            }

            // timer.setTimePoint("RR22 1 compute fixed key");

            co_await(chl.send(VecP));

            co_await(chl.flush());

            // timer.setTimePoint("RR22 1 send P");

            // compute my OPRF1 value using key

            std::vector<block> tValue(mySetSize);
            std::vector<block> OKVSDecodeValue(mySetSize);
            std::vector<block> H1Value(mySetSize);
            mPaxos.decode<block>(X, OKVSDecodeValue, OPRFkey, numThreads);

            // compute H1(x)
            H1.ecbEncBlocks(X.data(), mySetSize, H1Value.data());

            // timer.setTimePoint("RR22 1 compute H1(x)");

            for (int i = 0; i < mySetSize; i++){
                H1Value[i] = delta.gf128Mul(H1Value[i]);
            }
            
            for(int i = 0; i < mySetSize; i++ ){
                tValue[i] = OKVSDecodeValue[i] ^ H1Value[i];
            }

            // timer.setTimePoint("RR22 1 compute Decode(OPRFkey), x) + delta * H1(x)");

            // compute H0(Decode(OPRFkey), x) + delta * H1(x))

            H0.ecbEncBlocks(tValue.data(), tValue.size(), PRFValue.data());

            // timer.setTimePoint("RR22 1 compute H0(Decode(OPRFkey), x) + delta * H1(x))");

            // OPRF2

            // std::cout << "Receiver: Start OPRF2" << "\n";
            //invoke random vole

            co_await(mVoleRecver.silentReceiveInplace(mPaxos.size(), prng, chl));
            // std::cout << "Receiver: End Random Vole" << "\n";

            // make VecA and compute VecB
            rVecA.assign(mVoleRecver.mA.begin(), mVoleRecver.mA.end());
            rVecB.assign(mVoleRecver.mC.begin(), mVoleRecver.mC.end());

            // fill out Y by dumy data

            std::vector<block> FillX(initSetSize);
            prng.get<block>(FillX);

            for (int i = 0; i < X.size(); i++)
                FillX[i] = X[i];

            H1Value.clear();
            H1Value.resize(FillX.size());
            H1.ecbEncBlocks(FillX.data(), FillX.size(), H1Value.data());
            
            prng.get<block>(VecA);

            VecB.resize(Paxos.size());
            Paxos.solve<block>(FillX, H1Value, VecB, nullptr, numThreads);

            // make mB = B - B' and mA = A - A' + delta' * B, and send it

            co_await(chl.recv(tDelta));

            // mA = A - A' + delta' * B
            for (int i = 0; i < VecA.size(); i++){
                tVecA[i] = VecA[i] ^ rVecA[i] ^ tDelta.gf128Mul(VecB[i]);
            }

            // mB = B - B'
            for(int i = 0; i < myKeySize; i++ ){
                tVecB[i] = VecB[i] ^ rVecB[i];
            }



            co_await(chl.send(tVecA));
            co_await(chl.send(tVecB));

            co_await(chl.recv(VecQ));

            for(int i = 0; i < myKeySize; i++ ){
                VecQ[i] = VecQ[i] ^ VecA[i];
            }

            std::vector<block> OKVSDecodeValue2(mySetSize);

            // compute Decode(Q, x)
            Paxos.decode<block>(X, OKVSDecodeValue2, VecQ, numThreads);

            // compute H0 (Decode(Q, x))
            H0.ecbEncBlocks(OKVSDecodeValue2.data(), OKVSDecodeValue2.size(), myOPRFValue.data());

            // timer.setTimePoint("RR22 2 end");

            // make/update OPRFTable
            int tempValue;
            if (OPRFTable.size() == 0){

                // std::cout << "Receiver: tValue size is " << tValue.size() << " myOPRFValue size is " << myOPRFValue.size() << " PRFValue size is " << PRFValue.size() << "\n";

                OPRFTable.resize(mySetSize);
                for(int i = 0; i < OPRFTable.size(); i++){
                    OPRFTable[i] = myOPRFValue[i] ^ PRFValue[i];
                }
            }
            else{
                tempValue = OPRFTable.size();
                OPRFTable.resize(tempValue + mySetSize);
                for(int i = tempValue; i < OPRFTable.size(); i++){                    
                    OPRFTable[i] = myOPRFValue[i - tempValue] ^ PRFValue[i - tempValue];
                }

            }

            // timer.setTimePoint("RR22 compute UID");

            // std::cout << timer << "\n";
    }

    void AltModPidSender::evalDDH(span<block> Y, u64 XSize, PRNG& prng)
        {
            // std::cout << "Sender Start suspend" << std::endl;
            // co_await std::suspend_always{}; 
            std::cout << "Entry AltModPidSender::evalDDH" << std::endl;

            NetIO client_io("client", "127.0.0.1", 8080 - (2 * invokeNumber));

            DDHOPRF::PP pp;
            pp = DDHOPRF::Setup();
            
            std::vector<uint64_t> permutation_map_X; // Sender permutation

            permutation_map_X.resize(XSize); 
            for(auto i = 0; i < XSize; i++){
                permutation_map_X[i] = i; 
            }
            std::vector<__m128i> Yvec(Y.begin(), Y.end());

            std::cout << "Yvec size is " << Yvec.size() << std::endl;

            // OPRF 1
            std::vector<std::vector<uint8_t>> SenderOPRF = DDHOPRF::Client(client_io, pp, Yvec, Yvec.size());

            // OPRF 2
            NetIO server_io("server", "", 8081 - (2 * invokeNumber));

            key = DDHOPRF::Server(server_io, pp, permutation_map_X, XSize);
            std::vector<std::vector<uint8_t>> myPRF = DDHOPRF::Evaluate(pp, key, Yvec, Yvec.size());

            std::cout << "Sender OPRF2 End" << std::endl;

            OPRFSum.resize((Y.size()));
            block temp1;
            block temp2;
            std::cout << "Start Compute OPRFSum By Sender" << std::endl;
            for (int i = 0; i < myPRF.size(); i++){
                
                std::memcpy(&temp1, myPRF[i].data(), 16);
                std::memcpy(&temp2 , SenderOPRF[i].data(), 16);
                OPRFSum[i] = temp1 ^ temp2;
            }
            std::cout << "Sender End" << '\n';
            std::cout << "Init OPRF End\n\n\n\n\n\n\n\n\n\n";

        }


    void AltModPidReceiver::evalDDH(span<block> X, u64 YSize, PRNG& prng)
        {
            // std::cout << "Receiver Start suspend" << std::endl;
            // co_await std::suspend_always{}; 
            std::cout << "Entry AltModPidReceiver::evalDDH" << std::endl;

            NetIO server_io("server", "", 8080 - (2 * invokeNumber));

            DDHOPRF::PP pp;
            pp = DDHOPRF::Setup();

            std::vector<uint64_t> permutation_map_Y; // Receiver permutation

            permutation_map_Y.resize(YSize); 
            for(auto i = 0; i < YSize; i++){
                permutation_map_Y[i] = i; 
            }
            std::vector<__m128i> Xvec(X.begin(), X.end());

            // OPRF 1
            std::cout << "Start OPRF 1" << std::endl;
            key = DDHOPRF::Server(server_io, pp, permutation_map_Y, YSize);
            std::vector<std::vector<uint8_t>> myPRF = DDHOPRF::Evaluate(pp, key, Xvec, Xvec.size());
            std::cout << "End OPRF 1" << std::endl;

            // OPRF 2
            NetIO client_io("client", "127.0.0.1", 8081 - (2 * invokeNumber));

            std::cout << "Start OPRF 2" << std::endl;
            std::vector<std::vector<uint8_t>> ReceiverOPRF = DDHOPRF::Client(client_io, pp, Xvec, Xvec.size());
            std::cout << "End OPRF 2" << std::endl;

            OPRFSum.resize((X.size()));
            block temp1;
            block temp2;
            // std::cout << "Start Compute OPRFSum" << std::endl;
            // std::cout << "Xvec Size is " << Xvec.size() << " myPRF size is " << myPRF.size() << '\n';
            for (int i = 0; i < myPRF.size(); i++){                
                
                std::memcpy(&temp1, myPRF[i].data(), 16);
                std::memcpy(&temp2 , ReceiverOPRF[i].data(), 16);
                OPRFSum[i] = temp1 ^ temp2;
            }

            // std::cout << "Receiver End" << '\n';

    }



    void runPID(AltModPidSender& Sender, AltModPidReceiver& Receiver, int OPRFflag, span<block> X, span<block> Y, PRNG& prng, Socket& chl1, Socket& chl2, int PartyFlag)
        {
            // std::cout << "start OPRFflag is " << OPRFflag << '\n';

            u64 nt = 1;

            macoro::thread_pool pool0;
            auto e0 = pool0.make_work();
            pool0.create_threads(nt);
            macoro::thread_pool pool1;
            auto e1 = pool1.make_work();
            pool1.create_threads(nt);

            // ss-PRF
            if (OPRFflag == 1){

                auto p0 = Sender.evalOPRF(Y, X.size(), prng, chl1);
                auto p1 = Receiver.evalOPRF(X, Y.size(), prng, chl2);

                auto r = macoro::sync_wait(
                    macoro::when_all_ready(std::move(p0) | macoro::start_on(pool0),
                                        std::move(p1) | macoro::start_on(pool1)));
                std::get<0>(r).result();
                std::get<1>(r).result();

            }
            // RR22 OPRF
            else if (OPRFflag == 2){
                
                auto p0 = Sender.evalRR22(Y, X.size(), prng, chl1);
                auto p1 = Receiver.evalRR22(X, Y.size(), prng, chl2);

                auto r = macoro::sync_wait(
                    macoro::when_all_ready(std::move(p0) | macoro::start_on(pool0),
                                        std::move(p1) | macoro::start_on(pool1)));
                std::get<0>(r).result();
                std::get<1>(r).result();

            }
            // DDH OPRF
            else if (OPRFflag == 3) {

                CRYPTO_Initialize();

                if (PartyFlag == 0){
                    std::cout << "[OPRF-DDH] Role = Receiver (server)\n";
                    Receiver.evalDDH(X, Y.size(), prng);
                    // macoro::sync_wait(Receiver.evalDDH(X, Y.size(), prng));

                    NetIO server_io("server", "", 8083);
                    server_io.SendInteger(Receiver.OPRFSum.size());
                    server_io.SendBytes(Receiver.OPRFSum.data(), Receiver.OPRFSum.size() * sizeof(osuCrypto::block));

                    return;
                }
                else if (PartyFlag == 1){
                    std::cout << "[OPRF-DDH] Role = Sender (client)\n";
                    Sender.evalDDH(Y, X.size(), prng);

                    NetIO client_io("client", "127.0.0.1", 8083);
                    size_t n = 0;
                    client_io.ReceiveInteger(n);
                    Receiver.OPRFSum.resize(n);
                    std::cout << '\n' << "n is " << n << '\n';
                    std::cout << "Sender Size is " << Sender.OPRFSum.size() << " Receiver Size is " << Receiver.OPRFSum.size() << '\n';
                    client_io.ReceiveBytes(Receiver.OPRFSum.data(), n * sizeof(osuCrypto::block));
                    // macoro::sync_wait(Sender.evalDDH(Y, X.size(), prng));
                }
                std::cout << "Init OPRF End\n\n\n\n\n\n\n\n\n\n";

            }
            // PID protocol: RR22 + ePSU
            // RR22
            else if (OPRFflag == 4){

                // std::cout << "point1" << '\n';

                // std::cout << "Set size is (" << X.size() << ", " << Y.size() << ") OPRFTable Size is (" <<  Sender.OPRFTable.size() << ", " << Receiver.OPRFTable.size() << ") \n";
                
                auto p0 = Sender.evalRR22(Y, X.size(), prng, chl1);
                auto p1 = Receiver.evalRR22(X, Y.size(), prng, chl2);

                auto r = macoro::sync_wait(
                    macoro::when_all_ready(std::move(p0) | macoro::start_on(pool0),
                                        std::move(p1) | macoro::start_on(pool1)));
                std::get<0>(r).result();
                std::get<1>(r).result();

            }
            // std::cout << "point2" << '\n';

            // ePSU

            if (OPRFflag == 4)
            {
                // PSU 1
                {

                    u64 nt = 1;

                    macoro::thread_pool pool0;
                    auto e0 = pool0.make_work();
                    pool0.create_threads(nt);
                    macoro::thread_pool pool1;
                    auto e1 = pool1.make_work();
                    pool1.create_threads(nt);

                    oc::Timer timer_s;
                    oc::Timer timer_r;

                    AltModPsuSender send;
                    AltModPsuReceiver recv;

                    // send.setTimer(timer_s);
                    // recv.setTimer(timer_r);
                    timer_s.setTimePoint("start");

                    std::vector<block> diffSet;

                    {
                        auto p0 = send.run(Sender.OPRFTable, prng, chl1);
                        auto p1 = recv.run(Receiver.OPRFTable, diffSet, prng, chl2);

                        auto r = macoro::sync_wait(
                            macoro::when_all_ready(std::move(p0) | macoro::start_on(pool0),
                                                std::move(p1) | macoro::start_on(pool1)));
                        std::get<0>(r).result();
                        std::get<1>(r).result();
                    }

                    if (0) {
        
                        std::cout << timer_s << std::endl;

                        // std::cout << timer_r << std::endl;

                        std::cout << "comm " << double(chl1.bytesSent())/ 1024 / 1024 << " + "
                                << double(chl2.bytesSent())/ 1024 / 1024 << " = "
                                << double(chl1.bytesSent() + chl2.bytesSent()) / 1024 / 1024
                                << "MB" << std::endl;
                    }
                }
                // PSU 2
                {

                    u64 nt = 1;

                    macoro::thread_pool pool0;
                    auto e0 = pool0.make_work();
                    pool0.create_threads(nt);
                    macoro::thread_pool pool1;
                    auto e1 = pool1.make_work();
                    pool1.create_threads(nt);

                    oc::Timer timer_s;
                    oc::Timer timer_r;

                    AltModPsuSender send;
                    AltModPsuReceiver recv;

                    // send.setTimer(timer_s);
                    // recv.setTimer(timer_r);
                    timer_s.setTimePoint("start");

                    std::vector<block> diffSet;

                    {
                        auto p0 = send.run(Receiver.OPRFTable, prng, chl1);
                        auto p1 = recv.run(Sender.OPRFTable, diffSet, prng, chl2);

                        auto r = macoro::sync_wait(
                            macoro::when_all_ready(std::move(p0) | macoro::start_on(pool0),
                                                std::move(p1) | macoro::start_on(pool1)));
                        std::get<0>(r).result();
                        std::get<1>(r).result();
                    }

                    if (0) {
        
                        std::cout << timer_s << std::endl;

                        // std::cout << timer_r << std::endl;

                        std::cout << "comm " << double(chl1.bytesSent())/ 1024 / 1024 << " + "
                                << double(chl2.bytesSent())/ 1024 / 1024 << " = "
                                << double(chl1.bytesSent() + chl2.bytesSent()) / 1024 / 1024
                                << "MB" << std::endl;
                    }
                }
            }
            

            std::cout << "Protocol End" << '\n';

            if (OPRFflag == 2){
                // std::cout << "Sender.OPRFTable size is " << Sender.OPRFTable.size() << '\n';
                std::cout << "init OPRFSum is" << Sender.OPRFTable[1] << " original value is " << X[1] <<"\n\n";

                // std::cout << "init OPRFSum is" << Sender.OPRFTable[(1 << 16) + 1] << " Update Value is " << Sender.OPRFTable[(1 << 16) + 1] << "\n\n";
            }


        }

        struct BlockLess {
            bool operator()(const block& a, const block& b) const noexcept {
                std::uint64_t ax[2], bx[2];
                std::memcpy(ax, &a, sizeof ax);
                std::memcpy(bx, &b, sizeof bx);
                return (ax[0] < bx[0]) || (ax[0] == bx[0] && ax[1] < bx[1]);
            }
        };


    void runUpdate(AltModPidSender& Sender, AltModPidReceiver& Receiver, int OPRFflag, int updateNumber, PRNG& prng, Socket& chl1, Socket& chl2, int PartyFlag)
        {
            // std::cout << "\n\nstart Update OPRFflag is " << OPRFflag << '\n';
            
            std::vector<block> recvSet(updateNumber), sendSet(updateNumber);
            Sender.invokeNumber++;
            Receiver.invokeNumber++;
            // Sender.OPRFSum = std::vector<block>();
            // Receiver.OPRFSum = std::vector<block>();
            Sender.OPRFSum.clear();
            Receiver.OPRFSum.clear();

            prng.get<block>(recvSet);
            sendSet = recvSet;
            
            u64 itx = 105;
            u64 n = 1024;
            // for (u64 i = 0; i < itx; i++) {
            //     sendSet[(i*5) % n] = prng.get();
            // }

            // prng.get<block>(sendSet);
            for (u64 i = 1; i < sendSet.size() / 2; i++) {
                sendSet[i] = block(i,i);
            }

            for (u64 i = 1; i < recvSet.size(); i++) {
                recvSet[(i)] = block(i,i);
            }

            u64 nt = 1;

            macoro::thread_pool pool0;
            auto e0 = pool0.make_work();
            pool0.create_threads(nt);
            macoro::thread_pool pool1;
            auto e1 = pool1.make_work();
            pool1.create_threads(nt);

            std::vector<block> SenderdiffSet;
            std::vector<block> ReceiverdiffSet;

            // std::cout << "updatePID OPRF start" << '\n';
            // ss-PRF

            if (OPRFflag == 1){

                auto p0 = Sender.evalOPRF(sendSet, updateNumber, prng, chl1);
                auto p1 = Receiver.evalOPRF(recvSet, updateNumber, prng, chl2);

                auto r = macoro::sync_wait(
                    macoro::when_all_ready(std::move(p0) | macoro::start_on(pool0),
                                        std::move(p1) | macoro::start_on(pool1)));
                std::get<0>(r).result();
                std::get<1>(r).result();

            }
            // RR22 OPRF
            else if (OPRFflag == 2){
                // recvSet.resize(1ull << 20);
                // sendSet.resize(1ull << 20);

                // prng.get<block>(recvSet);
                // sendSet = recvSet;
                
                {
                auto p0 = Sender.evalRR22(sendSet, updateNumber, prng, chl1);
                auto p1 = Receiver.evalRR22(recvSet, updateNumber, prng, chl2);

                auto r = macoro::sync_wait(
                    macoro::when_all_ready(std::move(p0) | macoro::start_on(pool0),
                                        std::move(p1) | macoro::start_on(pool1)));
                std::get<0>(r).result();
                std::get<1>(r).result();
                }
                // recvSet.resize(updateNumber);
                // sendSet.resize(updateNumber);

            }

            // DDH OPRF
            else if (OPRFflag == 3) {

                CRYPTO_Initialize();

                if (PartyFlag == 0){
                    std::cout << "[OPRF-DDH] Role = Receiver (server)\n";
                    Receiver.evalDDH(sendSet, updateNumber, prng);
                    // macoro::sync_wait(Receiver.evalDDH(X, Y.size(), prng));

                    NetIO server_io("server", "", 8083 + Sender.invokeNumber);
                    server_io.SendInteger(Receiver.OPRFSum.size());
                    server_io.SendBytes(Receiver.OPRFSum.data(), Receiver.OPRFSum.size() * sizeof(osuCrypto::block));

                    return;
                }
                else if (PartyFlag == 1){
                    std::cout << "[OPRF-DDH] Role = Sender (client)\n";
                    Sender.evalDDH(recvSet, updateNumber, prng);

                    NetIO client_io("client", "127.0.0.1", 8083 + Sender.invokeNumber);
                    size_t n = 0;
                    client_io.ReceiveInteger(n);
                    Receiver.OPRFSum.resize(n);
                    std::cout << '\n' << "n is " << n << '\n';
                    std::cout << "Sender Size is " << Sender.OPRFSum.size() << " Receiver Size is " << Receiver.OPRFSum.size() << '\n';
                    client_io.ReceiveBytes(Receiver.OPRFSum.data(), n * sizeof(osuCrypto::block));
                    // macoro::sync_wait(Sender.evalDDH(Y, X.size(), prng));
                }

            }

            if (OPRFflag == 2){
                std::cout << "Sender.OPRFTable size is " << Sender.OPRFTable.size() << '\n';
                std::cout << "\nSender:\n";
                std::cout << "init OPRFSum is " << Sender.OPRFTable[1] << " Update Value is " << Sender.OPRFTable[Sender.initSetSize + 1] << "\n\n";

                std::cout << "\nReceiver:\n";
                std::cout << "init OPRFSum is " << Receiver.OPRFTable[1] << " Update Value is " << Receiver.OPRFTable[Receiver.initSetSize + 1] << "\n\n";
                
            }
            
        }
}