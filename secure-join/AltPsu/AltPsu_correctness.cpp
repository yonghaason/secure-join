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
                // gmw_inpiut = std::vector<block>{},
                numThreads = osuCrypto::u64{},
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
                finalOtSender = std::make_unique<oc::SilentOtExtSender>(),
                finalOtMsgs = std::vector<std::array<block, 2>>{}

                
        );

        MC_AWAIT(chl.send(Y));

        epsilon = 0.2;
        n = Y.size();
        m = static_cast<int>((1 + epsilon) * n);
        band_length = 128;

        okvs.Init(n, m, band_length, oc::ZeroBlock);

        okvs_encoding.resize(okvs.Size());
        okvs_encoding2.resize(okvs.Size());
        MC_AWAIT(chl.recv(okvs_encoding));
        MC_AWAIT(chl.recv(okvs_encoding2));
        receive_randomvalue.resize(Y.size());
        MC_AWAIT(chl.recv(receive_randomvalue));

        decoded.resize(Y.size());
        decoded2.resize(Y.size());
        okvs.Decode(Y.data(), okvs_encoding.data(), decoded.data());
        okvs.Decode(Y.data(), okvs_encoding2.data(), decoded2.data());

		ole1.init(chl.fork(), prng, 1, 1, 1 << 18, 1);

        // sk.resize(AltModPrf::KeySize);
		// for (u64 i = 0; i < 128; ++i)
		// {
		// 	sk[i][0] = oc::block(i, 0);
		// 	sk[i][1] = oc::block(i, 1);
		// }
        // recver.setKeyOts(sk);

        recver.init(Y.size(), ole1);
        recver.mUseMod2F4Ot = true;
        recver.setTimer(timer);

        // temp = receive_randomvalue[0];
        // receive_randomvalue[0] = receive_randomvalue[1];
        // receive_randomvalue[1] = temp;

        output_2party_wprf.resize(Y.size());
        tOle   = ole1.start();
        tEvalS = recver.evaluate(decoded, output_2party_wprf, chl, prng);

        MC_AWAIT(when_all_ready(tOle, tEvalS));

        cir = isZeroCircuit(u64(80));

        std::cout << "Y.size() is " << Y.size() << '\n';
        // numThreads = 1;
        numThreads = static_cast<osuCrypto::u64>(std::thread::hardware_concurrency());
        
        // in.resize(Y.size(), 16);
        in.resize(Y.size(), 10);
        send_wprf.resize(Y.size());
        for (i = 0; i < Y.size(); i++){

            // temp_ = oc::block(0, i);
            // temp_ = receive_randomvalue[i];
            temp = output_2party_wprf[i]^decoded2[i];
            send_wprf[i] = output_2party_wprf[i]^decoded2[i];
            std::memcpy(&in(i, 0), &temp, 10);   
            // in(i, 0) = output_2party_wprf[i];

        }

        seed = prng.get<oc::block>();

        ole_gmw.init(socket_gmw.fork(), prng, 1, 1, 1 << 18, 0);

        cmp->init(Y.size(), cir, ole_gmw);

        // cmp->implSetInput(0, in, 10);
        cmp->setInput(0, in);
        // cmp->mO.mDebug = true;

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
                secret_string = block{},
                rk = std::vector<oc::block>{},
                sk = std::vector<std::array<oc::block, 2>>{},
                sock_virtual = coproto::LocalAsyncSocket::makePair(),
                sock2_virtual = coproto::LocalAsyncSocket::makePair(),
                // ciphertext_of_wprf = std::vector<oc::block>{},
                sender = AltModWPrfSender{},
                sender_virtual = AltModWPrfSender{},
                recver_virtual = AltModWPrfReceiver{},
                output_1party_wprf = std::vector<oc::block>{},
                prng0 = PRNG{},
                prng1 = PRNG{},
                y0 = std::vector<oc::block>{},
                y1 = std::vector<oc::block>{},
                dm = AltModPrf{},
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
                

                finalOtReceiver = std::make_unique<oc::SilentOtExtReceiver>(),
                finalOtMsgs = std::vector<block>{}
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

		sender_virtual.mUseMod2F4Ot = true; // check
		recver_virtual.mUseMod2F4Ot = true;

		// ciphertext_of_wprf.resize(X.size());
        secret_string = prng.get();
		y0.resize(X.size());
        y1.resize(X.size());
        // separate function
        // use AltModPrf only receiver

        // std::cout << "start 1party wprf\n";
        {
            oc::Timer timer;
            sender_virtual.setTimer(timer);
		    recver_virtual.setTimer(timer);

            // sock_virtual = coproto::LocalAsyncSocket::makePair();
            // sock2_virtual = coproto::LocalAsyncSocket::makePair();
            macoro::thread_pool pool0;
            auto e0 = pool0.make_work();
            pool0.create_threads(1);
            macoro::thread_pool pool1;
            auto e1 = pool1.make_work();
            pool1.create_threads(1);
            sock_virtual[0].setExecutor(pool0);
            sock_virtual[1].setExecutor(pool1);
            sock2_virtual[0].setExecutor(pool0);
            sock2_virtual[1].setExecutor(pool1);

            prng0.SetSeed(oc::ZeroBlock);
            prng1.SetSeed(oc::OneBlock);

            kk = prng0.get();
            dm.setKey(kk);
            //sender.setKey(kk);
            indicator_string = prng0.get();

            ole0_virtual.init(sock2_virtual[0].fork(), prng0, 0, 1, 1 << 18, 1);
            ole1_virtual.init(sock2_virtual[1].fork(), prng1, 1, 1, 1 << 18, 1);

            random_value.resize(X.size());
            prng0.get(random_value.data(), X.size());

            for (auto & t : random_value){
                set_random.insert(t);
            }
            rk.resize(AltModPrf::KeySize);
            sk.resize(AltModPrf::KeySize);
            for (u64 i = 0; i < AltModPrf::KeySize; ++i)
            {
                sk[i][0] = oc::block(i, 0);
                sk[i][1] = oc::block(i, 1);
                rk[i] = oc::block(i, *oc::BitIterator((u8*)&sender_virtual.mKeyMultRecver.mKey, i));
            }
            sender_virtual.setKeyOts(kk, rk);
            recver_virtual.setKeyOts(sk);
            
            for (u64 t = 0; t < 1; ++t)
            {
                sender_virtual.init(X.size(), ole0_virtual);
                recver_virtual.init(X.size(), ole1_virtual);

                // std::cout << "start wating wprf protocol\n";
                auto r = coproto::sync_wait(coproto::when_all_ready(
                    ole0_virtual.start() | macoro::start_on(pool0),
                    ole1_virtual.start() | macoro::start_on(pool1),
                    sender_virtual.evaluate({}, y0, sock_virtual[0], prng0) | macoro::start_on(pool0),
                    recver_virtual.evaluate(random_value, y1, sock_virtual[1], prng1) | macoro::start_on(pool1)
                ));
                std::get<0>(r).result();
                std::get<1>(r).result();
                std::get<2>(r).result();
                std::get<3>(r).result();
            }
        }

        output_1party_wprf.resize(X.size());
        for (i = 0; i < X.size(); i++){
            output_1party_wprf[i] = y0[i]^y1[i]^indicator_string;
        }

        // make rb_okvs
        epsilon = 0.20;
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

        // std::cout << "init ole0\n";

        ole0.init(chl.fork(), prng, 0, 1, 1 << 18, 1);
        
        // for (u64 i = 0; i < AltModPrf::KeySize; ++i)
		// {
		// 	rk[i] = oc::block(i, *oc::BitIterator((u8*)&sender.mKeyMultRecver.mKey, i));
		// }
        // sender.setKeyOts(kk, rk);

        sender.init(X.size(), ole0);
        sender.mUseMod2F4Ot = true;// check
        sender.setTimer(timer);

        output_2party_wprf.resize(X.size());
        tOle   = ole0.start();
        tEvalR = sender.evaluate({}, output_2party_wprf, chl, prng0);

        // std::cout << "start 2party wprf\n";

        MC_AWAIT(when_all_ready(tOle, tEvalR));

        // std::cout << "start gmw\n";

        cir = isZeroCircuit(u64(80));

        numThreads = static_cast<osuCrypto::u64>(std::thread::hardware_concurrency());
        in.resize(X.size(), 10);
        for (i = 0; i < X.size(); i++){

            // temp_ = output_2party_wprf[i]^output_1party_wprf[i];
            // temp_ = oc::ZeroBlock;
            temp = output_2party_wprf[i]^indicator_string;

            std::memcpy(&in(i, 0), &temp, 10);

            set_xor_wprf.insert(output_2party_wprf[i]^indicator_string);
            // set_xor_wprf.insert(output_2party_wprf[i]^output_1party_wprf[i]);
        }
 
        std::cout << "in.rows() is " << in.rows() << " in.cols() is " << in.cols() << '\n';
        std::cout << "in(1, 0) is " << int(in(1, 0)) << '\n';
        std::cout << "in(1, 1) is " << int(in(1, 1)) << '\n';
        std::cout << "in(1, 2) is " << int(in(1, 2)) << '\n';

        numThreads = static_cast<osuCrypto::u64>(std::thread::hardware_concurrency());

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
