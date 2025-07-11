#include "AltPsu.h"
#include "secure-join/Prf/AltModPrfProto.h"
#include "secure-join/Sort/RadixSort.h"
#include "secure-join/Join/OmJoin.h"
#include "secure-join/Perm/PprfPermGen.h"
#include "secure-join/GMW/Gmw.h"
// #include "secure-join/GMW/backup_volepsi_gmw/Gmw.h"
#define COPROTO_ENABLE_LOGGING

namespace secJoin
{

    Proto AltModPsuSender::run_correctness(span<block> Y, PRNG &prng, Socket &chl, Socket &socket_gmw)
    {
        MC_BEGIN(Proto, this, Y, &prng, &chl, &socket_gmw,
                i = int{},
                epsilon = double{},
                n = int{},
                m = int{},
                band_length= int{},
                okvs = band_okvs::BandOkvs{},
                okvs_encoding = std::vector<block>{},
                okvs_encoding2 = std::vector<block>{},
                decoded = std::vector<block>{},
                decoded2 = std::vector<block>{},
                recver = AltModWPrfReceiver{},
                ole1 = CorGenerator{},
                ole_gmw = CorGenerator{},
                tOle = macoro::task<void>{},
                tEvalS = macoro::task<void>{},
                tgmw = macoro::task<void>{},
                tgmw_ole = macoro::task<void>{},
                sk = std::vector<std::array<oc::block, 2>>{},
                output_2party_wprf = std::vector<block>{},
                cmp = std::make_unique<Gmw>(),
                cir = BetaCircuit{},
                in = oc::Matrix<u8>{},
                outView = oc::MatrixView<u8>{},
                flags = oc::BitVector{},
                receive_randomvalue = std::vector<block>{},
                send_wprf = std::vector<block>{},
                // timer = oc::Timer{},
                temp = block{},
                temp_ = block{},
                byte_matrix = oc::MatrixView<u8>{},
                seed = block{},
                
                keyOtSender = std::make_unique<oc::SilentOtExtSender>(),
                sk = std::vector<std::array<oc::block, 2>>{}, 

                finalOtSender = std::make_unique<oc::SilentOtExtSender>(),
                
                finalOtMsgs = std::vector<std::array<block, 2>>{},
                
                otSend = OtSend{ }

        );

        MC_AWAIT(chl.send(Y));

        epsilon = 0.1;
        n = Y.size();
        m = static_cast<int>((1 + epsilon) * n);
        band_length = 128;

        okvs.Init(n, m, band_length, oc::ZeroBlock);

        okvs_encoding.resize(okvs.Size());
        okvs_encoding2.resize(okvs.Size());
        receive_randomvalue.resize(Y.size());
        MC_AWAIT(chl.recv(okvs_encoding));
        MC_AWAIT(chl.recv(okvs_encoding2));
        MC_AWAIT(chl.recv(receive_randomvalue));

        decoded.resize(Y.size());
        decoded2.resize(Y.size());
        okvs.Decode(Y.data(), okvs_encoding.data(), decoded.data());
        okvs.Decode(Y.data(), okvs_encoding2.data(), decoded2.data());		

        ole1.init(chl.fork(), prng, 1, 1, 1 << 18, 0);

        keyOtSender->configure(AltModPrf::KeySize);
        sk.resize(AltModPrf::KeySize);
        MC_AWAIT(keyOtSender->send(sk, prng, chl));

        recver.init(Y.size(), ole1, AltModPrfKeyMode::SenderOnly, AltModPrfInputMode::ReceiverOnly, {}, sk);
        recver.mUseMod2F4Ot = true;
        recver.setTimer(timer);

        output_2party_wprf.resize(Y.size());
        tOle   = ole1.start();
        tEvalS = recver.evaluate(decoded, output_2party_wprf, chl, prng);

        MC_AWAIT(when_all_ready(tOle, tEvalS));

        cir = isZeroCircuit(u64(80));

        in.resize(Y.size(), 10);
        send_wprf.resize(Y.size());
        for (i = 0; i < Y.size(); i++){
            temp = output_2party_wprf[i]^decoded2[i];
            send_wprf[i] = output_2party_wprf[i]^decoded2[i];
            std::memcpy(&in(i, 0), &temp, 10);  
        }

        seed = prng.get<oc::block>();

        ole_gmw.init(socket_gmw.fork(), prng, 1, 1, 1 << 18, 0);

        cmp->init(Y.size(), cir, ole_gmw);

        cmp->setInput(0, in);

        cmp->preprocess();
        
        tgmw = cmp->run(socket_gmw);
        tgmw_ole = ole_gmw.start();
        MC_AWAIT(when_all_ready(tgmw, tgmw_ole));

        // ole_gmw.start();
        // MC_AWAIT(cmp->run(socket_gmw));
        // MC_AWAIT(cmp->run(chl));

        outView = cmp->getOutputView(0);

        // flags(outView.data(), Y.size(), false);
        flags.resize(Y.size());
        // flags.assign(outView.data(), /*bitLen=*/Y.size(), /*copyData=*/false);
        flags = oc::BitVector(outView.data(), Y.size(), /*copyData=*/false);
        MC_AWAIT(chl.send(flags));

        //OT phase
        finalOtMsgs.resize(Y.size());

        for (u64 i = 0; i < Y.size(); i++){

            if(flags[i] == 0){
                finalOtMsgs[i][0] = Y[i];
                finalOtMsgs[i][1] = osuCrypto::ZeroBlock;
            }
            else{
                finalOtMsgs[i][0] = osuCrypto::ZeroBlock;
                finalOtMsgs[i][1] = Y[i];
            }

            
        }
        //finalOtSender->configure(Y.size(), 2, mNumThreads);
        finalOtSender->configure(Y.size(), 2, 1);

        MC_AWAIT(finalOtSender->sendChosen(finalOtMsgs, prng, chl));

        MC_AWAIT(chl.send(decoded));
        MC_AWAIT(chl.send(send_wprf));

        MC_END();
    }
    
    Proto AltModPsuReceiver::run_correctness(span<block> X, PRNG &prng, Socket &chl, Socket &socket_gmw)
    {
        MC_BEGIN(Proto, this, X, &prng, &chl, &socket_gmw,
                i = int{},
                epsilon = double{},
                n = int{},
                m = int{},
                band_length= int{},
                okvs = band_okvs::BandOkvs{},
                okvs_encoding = std::vector<block>{},
                okvs_encoding2 = std::vector<block>{},
                random_value = std::vector<block>{},
                ole0 = CorGenerator{},
                ole_gmw = CorGenerator{},
                indicator_string = oc::block{},
                rk = std::vector<oc::block>{},
                sk = std::vector<std::array<oc::block, 2>>{},
                sock_virtual = coproto::LocalAsyncSocket::makePair(),
                sock2_virtual = coproto::LocalAsyncSocket::makePair(),
                // ciphertext_of_wprf = std::vector<oc::block>{},
                sender = AltModWPrfSender{},
                sender_virtual = AltModWPrfSender{},
                recver_virtual = AltModWPrfReceiver{},
                output_1party_wprf = std::vector<oc::block>{},
                y0 = std::vector<oc::block>{},
                y1 = std::vector<oc::block>{},
                y = std::vector<oc::block>{},
                kk = AltModPrf::KeyType{},
                // r = macoro::result<void>{},
                e0 = macoro::thread_pool::work{},
                e1 = macoro::thread_pool::work{},
                ole0_virtual = CorGenerator{},
                ole1_virtual = CorGenerator{},
                tOle = macoro::task<void>{},
                tEvalR = macoro::task<void>{},
                tgmw = macoro::task<void>{},
                tgmw_ole = macoro::task<void>{},
                output_2party_wprf = std::vector<block>{},
                compute_2party_wprf = std::vector<block>{},
                numThreads = osuCrypto::u64{},
                cmp = std::make_unique<Gmw>(),
                cir = BetaCircuit{},
                in = oc::Matrix<u8>{},
                outView = oc::MatrixView<u8>{},
                ot_choice = oc::BitVector{},
                // timer = oc::Timer{},
                receive_Y = std::vector<block>{},
                set_X = std::set<block>{},
                set_Y_X = std::set<block>{},
                set_random = std::set<block>{},
                set_xor_wprf = std::set<block>{},
                temp = block{},
                temp_ = block{},

                count_intersection = int{},
                count_receive = int{},
                count_okvs_intersection = int{},
                receive_decoded = std::vector<block>{},
                receive_wprf = std::vector<block>{},
                count_xor_wprf = int{},
                receive_bitvec = oc::BitVector{},
                gmw_count = int{},
                byte_matrix = oc::MatrixView<u8>{},
                
                A = oc::BetaBundle{},
                B = oc::BetaBundle{},
                D = oc::BetaBundle{},
                Z = oc::BetaBundle{},
                cir_ = oc::BetaCircuit{},

                keyOtReceiver = std::make_unique<oc::SilentOtExtReceiver>(),
                rk = std::vector<oc::block>{},
                kk_bv = oc::BitVector{},

                finalOtReceiver = std::make_unique<oc::SilentOtExtReceiver>(),
                finalOtMsgs = std::vector<block>{},
                otRecv = OtRecv{ },
                k = AltModPrf::KeyType{}
        );
        receive_Y.resize(X.size());
        MC_AWAIT(chl.recv(receive_Y));

        for(auto &iter : X)
            set_X.insert(iter);
        count_intersection = 0;

        for(auto &iter : receive_Y){
            if(set_X.count(iter) == true){
                set_Y_X.insert(iter);
                count_intersection++;
            }
        }

        std::cout << "count_intersection is " << count_intersection << '\n';

        // use AltModPrf only receiver
        // std::cout << "start 1party wprf\n";
        {
            AltModPrf dm(prng.get());
            kk = dm.getKey();
            y.resize(X.size());
            random_value.resize(X.size());

            prng.get(random_value.data(), X.size());
            dm.eval(random_value, y);

            for (auto & t : random_value){
                set_random.insert(t);
            }
        }

        indicator_string = prng.get();

        output_1party_wprf.resize(X.size());
        for (i = 0; i < X.size(); i++){
            output_1party_wprf[i] = y[i] ^ indicator_string;
        }

        // make rb_okvs
        epsilon = 0.1;
        n = X.size();
        m = static_cast<int>((1 + epsilon) * n);
        band_length = 128;

        okvs.Init(n, m, band_length, oc::ZeroBlock);

        // std::cout << "start okvs encoding\n";

        okvs_encoding.resize(okvs.Size());
        if (!okvs.Encode(X.data(), random_value.data(), okvs_encoding.data())) {
            std::cout << "Failed to encode!" << std::endl;
            exit(0);
        }

        okvs_encoding2.resize(okvs.Size());
        if (!okvs.Encode(X.data(), output_1party_wprf.data(), okvs_encoding2.data())) {
            std::cout << "Failed to encode!" << std::endl;
            exit(0);
        }

        // std::cout << "okvs encoding end\n";

        MC_AWAIT(chl.send(okvs_encoding));
        MC_AWAIT(chl.send(okvs_encoding2));
        MC_AWAIT(chl.send(random_value));

        ole0.init(chl.fork(), prng, 0, 1, 1 << 18, 0);

        keyOtReceiver->configure(AltModPrf::KeySize);
        rk.resize(AltModPrf::KeySize);
        kk_bv.append((u8*)kk.data(), AltModPrf::KeySize);

        MC_AWAIT(keyOtReceiver->receive(kk_bv, rk, prng, chl));

		sender.init(X.size(), ole0, AltModPrfKeyMode::SenderOnly, AltModPrfInputMode::ReceiverOnly, kk, rk);
        sender.mUseMod2F4Ot = true;
        sender.setTimer(timer);

        output_2party_wprf.resize(X.size());
        tOle   = ole0.start();
        tEvalR = sender.evaluate({}, output_2party_wprf, chl, prng);

        MC_AWAIT(when_all_ready(tOle, tEvalR));

        cir = isZeroCircuit(u64(80));

        numThreads = static_cast<osuCrypto::u64>(std::thread::hardware_concurrency());
        in.resize(X.size(), 10);
        for (i = 0; i < X.size(); i++){
            temp = output_2party_wprf[i]^indicator_string;
            std::memcpy(&in(i, 0), &temp, 10);
            set_xor_wprf.insert(output_2party_wprf[i]^indicator_string);
        }
 
        std::cout << "in.rows() is " << in.rows() << " in.cols() is " << in.cols() << '\n';
        std::cout << "in(1, 0) is " << int(in(1, 0)) << '\n';
        std::cout << "in(1, 1) is " << int(in(1, 1)) << '\n';
        std::cout << "in(1, 2) is " << int(in(1, 2)) << '\n';

        ole_gmw.init(socket_gmw.fork(), prng, 0, 1, 1 << 18, 0);

        cmp->init(X.size(), cir, ole_gmw);
        
        // cmp->implSetInput(0, in, 10);
        cmp->setInput(0, in);

        // cmp->mO.mDebug = true;

        cmp->preprocess();

        // std::cout << "run gmw\n";
        // ole_gmw.start();

        // MC_AWAIT(cmp->run(socket_gmw));
        tgmw = cmp->run(socket_gmw);
        tgmw_ole = ole_gmw.start();
        MC_AWAIT(when_all_ready(tgmw, tgmw_ole));

        // std::cout << "gmw end\n";

        outView = cmp->getOutputView(0);

        // std::cout << "start ot\n";

        std::cout << "size is " << outView.size() << '\n';

        ot_choice.resize(X.size());
        
        ot_choice = oc::BitVector(outView.data(), X.size(), /*copyData=*/false);

        finalOtMsgs.resize(ot_choice.size());
        finalOtReceiver->configure(ot_choice.size(), 2, 1);

        receive_bitvec.resize(ot_choice.size());
        MC_AWAIT(chl.recv(receive_bitvec));
        
        MC_AWAIT(finalOtReceiver->receiveChosen(ot_choice, finalOtMsgs, prng, chl));
        
        std::cout << timer << '\n';

        receive_decoded.resize(X.size());
        MC_AWAIT(chl.recv(receive_decoded));

        count_okvs_intersection = 0;

        for(auto &t : receive_decoded){
            if (set_random.count(t) == true)
                count_okvs_intersection++;
        }

        receive_wprf.resize(X.size());
        MC_AWAIT(chl.recv(receive_wprf));

        count_xor_wprf = 0;
        for(auto &t : receive_wprf){
            if(set_xor_wprf.count(t) == true)
                count_xor_wprf++;
        }

        count_receive = 0;
        for (auto &m : finalOtMsgs){
            if (m != oc::ZeroBlock)
                count_receive++;
        }

        gmw_count = 0;
        for (i = 0; i < X.size(); i++){
            if (receive_bitvec[i] ^ ot_choice[i] == 1){
                gmw_count++;
            }
        }

        std::cout << "count_okvs_intersection is " << count_okvs_intersection << '\n';
        std::cout << "count_xor_wprf is " << count_xor_wprf << '\n';
        std::cout << "gmw_count is " << gmw_count << '\n';
        std::cout << "number of intersection is " << count_intersection << " received intersction is " << count_receive << '\n';
        
        MC_END();

    }
}
