// #include "AltModPID.h"
#include <iostream>
#include "secure-join/PID/AltModPID.h"
#include "secure-join/Kunlun/mpc/oprf/ddh_oprf.hpp"
#include "secure-join/Kunlun/crypto/prg.hpp"
#include "secure-join/Kunlun/crypto/setup.hpp"



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

            SenderSetSize = Y.size();

            // run two OPRF, init

            RsOprfSender mSender;
            RsOprfReceiver mRecver;
            bool mMalicious = false;
            u64 mSsp = 40;
            bool mUseReducedRounds = false;
            bool mDebug = false;
            u64 mNumThreads = 1;
            auto hashes = Buffer<block>{};
            // vector<block> hashes;
            oc::MultType type;

            type = osuCrypto::MultType::ExConv21x24;
            // #ifdef ENABLE_INSECURE_SILVER
            //     type = cmd.isSet("useSilver") ? oc::MultType::slv5 : type;
            // #endif
            // #ifdef ENABLE_BITPOLYMUL
            //     type = cmd.isSet("useQC") ? oc::MultType::QuasiCyclic : type;
            // #endif

            mSender.setMultType(type);
            mRecver.setMultType(type);

            // OPRF 1
            // std::cout << "OPRF1 start\n";

            auto data = std::unique_ptr<u8[]>{};
            auto myHashes = span<block>{};
            data = std::unique_ptr<u8[]>(new u8[
                    Y.size() * sizeof(block)]);

            myHashes = span<block>((block*)data.get(), Y.size());

            setTimePoint("RsPsiReceiver::run-alloc");

            if (mTimer)
                mRecver.setTimer(getTimer());

            mRecver.mMalicious = mMalicious;
            mRecver.mSsp = mSsp;
            mRecver.mDebug = mDebug;

            co_await(mRecver.receive(Y, myHashes, prng, chl, mNumThreads, mUseReducedRounds));
            
            // std::cout << "OPRF1 End\n";
            // OPRF 2

            mSender.mMalicious = mMalicious;
            mSender.mSsp = mSsp;
            mSender.mDebug = mDebug;

            co_await mSender.send(XSize, prng, chl, mNumThreads, mUseReducedRounds);
            // std::cout << ("OPRF2 End\n");

            setTimePoint("RsPsiSender::run-opprf");

            hashes.resize(Y.size() * sizeof(block));
            mSender.eval(Y, span<block>((block*)hashes.data(), Y.size()), mNumThreads);

            OPRFSum.resize((Y.size()));

            for (int i = 0; i < OPRFSum.size(); i++)
                OPRFSum[i] = myHashes[i] ^ ((block*)hashes.data())[i];
            // std::cout << ("End OPRF eval\n");
        }


    Proto AltModPidReceiver::evalRR22(span<block> X, u64 YSize,PRNG& prng, Socket& chl)
        {
            ReceiverSetSize = X.size();

            // run two OPRF, init

            RsOprfSender mSender;
            RsOprfReceiver mRecver;
            bool mMalicious = false;
            u64 mSsp = 40;
            bool mUseReducedRounds = false;
            bool mDebug = false;
            u64 mNumThreads = 1;
            auto hashes = Buffer<u8>{};
            // vector<block> hashes;
            oc::MultType type;

            type = osuCrypto::MultType::ExConv21x24;
            // #ifdef ENABLE_INSECURE_SILVER
            //     type = cmd.isSet("useSilver") ? oc::MultType::slv5 : type;
            // #endif
            // #ifdef ENABLE_BITPOLYMUL
            //     type = cmd.isSet("useQC") ? oc::MultType::QuasiCyclic : type;
            // #endif

            mSender.setMultType(type);
            mRecver.setMultType(type);

            // OPRF 1

            mSender.mMalicious = mMalicious;
            mSender.mSsp = mSsp;
            mSender.mDebug = mDebug;

            co_await mSender.send(YSize, prng, chl, mNumThreads, mUseReducedRounds);

            setTimePoint("RsPsiSender::run-opprf");

            hashes.resize(X.size() * sizeof(block));
            mSender.eval(X, span<block>((block*)hashes.data(), X.size()), mNumThreads);

            // OPRF 2

            auto data = std::unique_ptr<u8[]>{};
            auto myHashes = span<block>{};
            data = std::unique_ptr<u8[]>(new u8[
                    X.size() * sizeof(block)]);

            myHashes = span<block>((block*)data.get(), X.size());

            setTimePoint("RsPsiReceiver::run-alloc");

            if (mTimer)
                mRecver.setTimer(getTimer());

            mRecver.mMalicious = mMalicious;
            mRecver.mSsp = mSsp;
            mRecver.mDebug = mDebug;

            co_await(mRecver.receive(X, myHashes, prng, chl, mNumThreads, mUseReducedRounds));            

            OPRFSum.resize((X.size()));
            
            for (int i = 0; i < OPRFSum.size(); i++)
                OPRFSum[i] = myHashes[i] ^ ((block*)hashes.data())[i];

    }

    void AltModPidSender::evalDDH(span<block> Y, u64 XSize, PRNG& prng)
        {
            // std::cout << "Sender Start suspend" << std::endl;
            // co_await std::suspend_always{}; 
            std::cout << "Entry AltModPidSender::evalDDH" << std::endl;

            NetIO client_io("client", "127.0.0.1", 8080);

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
            NetIO server_io("server", "", 8081);

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

        }


    void AltModPidReceiver::evalDDH(span<block> X, u64 YSize, PRNG& prng)
        {
            // std::cout << "Receiver Start suspend" << std::endl;
            // co_await std::suspend_always{}; 
            std::cout << "Entry AltModPidReceiver::evalDDH" << std::endl;

            NetIO server_io("server", "", 8080);

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
            NetIO client_io("client", "127.0.0.1", 8081);

            std::cout << "Start OPRF 2" << std::endl;
            std::vector<std::vector<uint8_t>> ReceiverOPRF = DDHOPRF::Client(client_io, pp, Xvec, Xvec.size());
            std::cout << "End OPRF 2" << std::endl;

            OPRFSum.resize((X.size()));
            block temp1;
            block temp2;
            std::cout << "Start Compute OPRFSum" << std::endl;
            std::cout << "Xvec Size is " << Xvec.size() << " myPRF size is " << myPRF.size() << '\n';
            for (int i = 0; i < myPRF.size(); i++){                
                
                std::memcpy(&temp1, myPRF[i].data(), 16);
                std::memcpy(&temp2 , ReceiverOPRF[i].data(), 16);
                OPRFSum[i] = temp1 ^ temp2;
            }

            std::cout << "Receiver End" << '\n';

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

                // std::exception_ptr ep0, ep1;

                // std::thread tS([&]{
                //     try { macoro::sync_wait(Sender.evalDDH(Y, X.size(), prng)); }
                //     catch (...) { ep0 = std::current_exception(); }
                // });
                // std::thread tR([&]{
                //     try { macoro::sync_wait(Receiver.evalDDH(X, Y.size(), prng)); }
                //     catch (...) { ep1 = std::current_exception(); }
                // });

                // tS.join();
                // tR.join();

                // if (ep0) std::rethrow_exception(ep0);
                // if (ep1) std::rethrow_exception(ep1);
            }

            std::cout << "Protocol End" << '\n';

            AltModPsuSender send;
            AltModPsuReceiver recv;

            std::vector<block> SenderdiffSet;
            std::vector<block> ReceiverdiffSet;

            std::cout << "Start Psu1 Sender.OPRFSum.size() is " << Sender.OPRFSum.size() << " Receiver.OPRFSum.size() is " << Receiver.OPRFSum.size() << '\n';
            {
                auto p0 = send.run(Sender.OPRFSum, prng, chl1);
                auto p1 = recv.run(Receiver.OPRFSum, ReceiverdiffSet, prng, chl2);

                auto r = macoro::sync_wait(
                    macoro::when_all_ready(std::move(p0) | macoro::start_on(pool0),
                                        std::move(p1) | macoro::start_on(pool1)));
                std::get<0>(r).result();
                std::get<1>(r).result();
            }
            std::cout << ("End Psu1 and start Psu2\n");

            {
                auto p0 = send.run(Receiver.OPRFSum, prng, chl1);
                auto p1 = recv.run(Sender.OPRFSum, SenderdiffSet, prng, chl2);

                auto r = macoro::sync_wait(
                    macoro::when_all_ready(std::move(p0) | macoro::start_on(pool0),
                                        std::move(p1) | macoro::start_on(pool1)));
                std::get<0>(r).result();
                std::get<1>(r).result();
            }
            std::cout << ("End Psu2\n");

            int j = Receiver.OPRFSum.size();
            Receiver.UID.resize(Receiver.OPRFSum.size() + ReceiverdiffSet.size());
            for (int i = 0; i < Receiver.UID.size(); i ++){
                if (i < j)
                    Receiver.UID[i] = Receiver.OPRFSum[i];
                else
                    Receiver.UID[i] = ReceiverdiffSet[i - j];
            }

            j = Sender.OPRFSum.size();
            Sender.UID.resize(Sender.OPRFSum.size() + SenderdiffSet.size());
            for (int i = 0; i < Sender.UID.size(); i ++){
                if (i < j)
                    Sender.UID[i] = Sender.OPRFSum[i];
                else
                    Sender.UID[i] = SenderdiffSet[i - j];
            }

            // Receiver.UID.insert(Receiver.UID.end(),
            //                     ReceiverdiffSet.begin(), ReceiverdiffSet.end());

            // Sender.UID.insert(Sender.UID.end(),
            //                 SenderdiffSet.begin(), SenderdiffSet.end());
            
            std::cout << "\nSenderdiffSet.size() is " << SenderdiffSet.size() << " ReceiverdiffSet.size() is " << ReceiverdiffSet.size() << '\n';
            std::cout << "Sender.UID.size() is " << Sender.UID.size() << " Receiver.UID.size() is " << Receiver.UID.size() << "\n\n";

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
            for (u64 i = 1; i < itx + 1; i++) {
                sendSet[(i)] = block(i,i);
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

                    NetIO server_io("server", "", 8083);
                    server_io.SendInteger(Receiver.OPRFSum.size());
                    server_io.SendBytes(Receiver.OPRFSum.data(), Receiver.OPRFSum.size() * sizeof(osuCrypto::block));

                    return;
                }
                else if (PartyFlag == 1){
                    std::cout << "[OPRF-DDH] Role = Sender (client)\n";
                    Sender.evalDDH(recvSet, updateNumber, prng);

                    NetIO client_io("client", "127.0.0.1", 8083);
                    size_t n = 0;
                    client_io.ReceiveInteger(n);
                    Receiver.OPRFSum.resize(n);
                    std::cout << '\n' << "n is " << n << '\n';
                    std::cout << "Sender Size is " << Sender.OPRFSum.size() << " Receiver Size is " << Receiver.OPRFSum.size() << '\n';
                    client_io.ReceiveBytes(Receiver.OPRFSum.data(), n * sizeof(osuCrypto::block));
                    // macoro::sync_wait(Sender.evalDDH(Y, X.size(), prng));
                }

                // std::exception_ptr ep0, ep1;

                // std::thread tS([&]{
                //     try { macoro::sync_wait(Sender.evalDDH(Y, X.size(), prng)); }
                //     catch (...) { ep0 = std::current_exception(); }
                // });
                // std::thread tR([&]{
                //     try { macoro::sync_wait(Receiver.evalDDH(X, Y.size(), prng)); }
                //     catch (...) { ep1 = std::current_exception(); }
                // });

                // tS.join();
                // tR.join();

                // if (ep0) std::rethrow_exception(ep0);
                // if (ep1) std::rethrow_exception(ep1);
            }

            // int samecount = 0;
            // for (int i = 0; i < sendSet.size(); i++){
            //     if (Receiver.OPRFSum[i] == Sender.OPRFSum[i])
            //         samecount++;
            // }

            // std::cout << "samecount is " << samecount << "\n\n";

            AltModPsuSender send;
            AltModPsuReceiver recv;

            int beforeSize = Receiver.UID.size();
            {
                std::set<block, BlockLess> uni;
                uni.insert(Receiver.UID.begin(),    Receiver.UID.end());
                uni.insert(Receiver.OPRFSum.begin(), Receiver.OPRFSum.end());
                Receiver.UID.assign(uni.begin(), uni.end());
            }

            {
                std::set<block, BlockLess> uni;
                uni.insert(Sender.UID.begin(),    Sender.UID.end());
                uni.insert(Sender.OPRFSum.begin(), Sender.OPRFSum.end());
                Sender.UID.assign(uni.begin(), uni.end());
            }
            
            // std::cout << "After, Sender.UID difference is " << Sender.UID.size() - beforeSize << '\n';

            int samecount2 = 0;

            for (int i = beforeSize; i < Sender.UID.size(); i++){
                if (Receiver.UID[i] == Sender.UID[i])
                    samecount2++;
            }

            // std::cout << "samecount2 is " << samecount2 << "\n\n";
            // std::cout << "After, Sender.UID.size() is " << Sender.UID.size() << " Receiver.UID.size() is " << Receiver.UID.size() << "\n\n";

            // std::cout << "\nBefore PSU, SenderdiffSet.size() is " << SenderdiffSet.size() << ", ReceiverdiffSet.size() is " << ReceiverdiffSet.size()  <<'\n';
            {
                auto p0 = send.runUPSU(Sender.OPRFSum, Receiver.UID.size(), prng, chl1);
                auto p1 = recv.runUPSU(Receiver.UID, Sender.OPRFSum.size(), ReceiverdiffSet, prng, chl2);

                auto r = macoro::sync_wait(
                    macoro::when_all_ready(std::move(p0) | macoro::start_on(pool0),
                                        std::move(p1) | macoro::start_on(pool1)));
                std::get<0>(r).result();
                std::get<1>(r).result();
            }
            // std::cout << "End Psu1 and start Psu2 Receiver.OPRFSum.size() is " << Receiver.OPRFSum.size() << " Sender.UID.size() is " << Sender.UID.size() << '\n';
            {
                auto p0 = send.runUPSU(Receiver.OPRFSum, Sender.UID.size(), prng, chl1);
                auto p1 = recv.runUPSU(Sender.UID, Receiver.OPRFSum.size(), SenderdiffSet, prng, chl2);

                auto r = macoro::sync_wait(
                    macoro::when_all_ready(std::move(p0) | macoro::start_on(pool0),
                                        std::move(p1) | macoro::start_on(pool1)));
                std::get<0>(r).result();
                std::get<1>(r).result();
            }
            // std::cout << ("End Psu2\n");
            // exit(0);

            Receiver.UID.insert(Receiver.UID.end(),
                                ReceiverdiffSet.begin(), ReceiverdiffSet.end());

            Sender.UID.insert(Sender.UID.end(),
                            SenderdiffSet.begin(), SenderdiffSet.end());

            // int j = Receiver.UID.size();
            // Receiver.UID.resize(Receiver.UID.size() + ReceiverdiffSet.size());
            // std::cout << "i is " << j << " j is " << Receiver.UID.size();
            
            // for (int i = j; i < Receiver.UID.size(); i++){
            //     Receiver.UID[i] = ReceiverdiffSet[i - j];
            // }

            // j = Sender.UID.size();
            // Sender.UID.resize(Sender.UID.size() + SenderdiffSet.size());
            // for (int i = j; i < Sender.UID.size(); i++){
            //         Sender.UID[i] = SenderdiffSet[i - j];
            // }
        
            // std::cout << "\nSenderdiffSet.size() is " << SenderdiffSet.size() << " ReceiverdiffSet.size() is " << ReceiverdiffSet.size() << '\n';
            // std::cout << "Sender.UID.size() is " << Sender.UID.size() << " Receiver.UID.size() is " << Receiver.UID.size() << '\n' << '\n';
        }
}