#include "AltPsu.h"
#include "secure-join/Prf/AltModPrfProto.h"
#include "secure-join/Sort/RadixSort.h"
#include "secure-join/Join/OmJoin.h"
#include "secure-join/Perm/PprfPermGen.h"
#include "secure-join/GMW/Gmw.h"
#define COPROTO_ENABLE_LOGGING

namespace secJoin
{

    Proto AltModPsuSender::run_debug(span<block> Y, PRNG &prng, Socket &chl, Socket &socket_gmw)
    {
        MC_BEGIN(Proto, this, Y, &prng, &chl, &socket_gmw,
                i = int{},
                epsilon = double{},
                n = int{},
                m = int{},
                band_length= int{},
                okvs = band_okvs::BandOkvs{},
                okvs_encoding = std::vector<block>{},
                decoded = std::vector<block>{},
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
                in = oc::Matrix<block>{},
                outView = oc::MatrixView<u8>{},
                flags = oc::BitVector{},
                // timer = oc::Timer{},

                seed = block{},
                finalOtSender = std::make_unique<oc::SilentOtExtSender>(),
                finalOtMsgs = std::vector<std::array<block, 2>>{}

                
        );

        epsilon = 0.1;
        n = Y.size();
        m = static_cast<int>((1 + epsilon) * n);
        band_length = 128;

        okvs.Init(n, m, band_length, oc::ZeroBlock);

        okvs_encoding.resize(okvs.Size());
        MC_AWAIT(chl.recv(okvs_encoding));

        decoded.resize(Y.size());
        okvs.Decode(Y.data(), okvs_encoding.data(), decoded.data());

		ole1.init(chl.fork(), prng, 1, 1, 1 << 18, 0);

        sk.resize(AltModPrf::KeySize);
		for (u64 i = 0; i < 128; ++i)
		{
			sk[i][0] = oc::block(i, 0);
			sk[i][1] = oc::block(i, 1);
		}
        recver.setKeyOts(sk);

        recver.init(Y.size(), ole1);
        recver.mUseMod2F4Ot = true;
        recver.setTimer(timer);

        // ole1.start()
        // recver.evaluate(x, y1, sock[1], prng1)

        output_2party_wprf.resize(Y.size());
        tOle   = ole1.start();
        tEvalS = recver.evaluate(decoded, output_2party_wprf, chl, prng);

        MC_AWAIT(when_all_ready(tOle, tEvalS));
        // MC_AWAIT(when_all_ready(tOle));
        // MC_AWAIT(when_all_ready(tEvalS));

        // gmw_inpiut.resize();
        // for(i = 0, i < Y.size(); i++){
        //     gmw_inpiut[i] = output_2party_wprf[i] ^ decoded[i]
        // }

        cir = isZeroCircuit(128);

        std::cout << "Y.size() is " << Y.size() << '\n';
        // numThreads = 1;
        numThreads = static_cast<osuCrypto::u64>(std::thread::hardware_concurrency());
        
        in.resize(Y.size(), 1);
        for (i = 0; i < Y.size(); i++)
            in(i, 0) = output_2party_wprf[i];

        seed = prng.get<oc::block>();

        ole_gmw.init(socket_gmw.fork(), prng, 1, 1, 1 << 18, 0);
        cmp->init(Y.size(), cir, ole_gmw);

        cmp->setInput(0, in);
        cmp->mO.mDebug = true;

        cmp->preprocess();
        
        // ole_gmw.start();
        // MC_AWAIT(cmp->run(socket_gmw));
        tgmw = cmp->run(socket_gmw);
        tgmw_ole = ole_gmw.start();
        MC_AWAIT(when_all_ready(tgmw, tgmw_ole));


        outView = cmp->getOutputView(0);

        // flags(outView.data(), Y.size(), false);
        flags.resize(Y.size());
        // flags.assign(outView.data(), /*bitLen=*/Y.size(), /*copyData=*/false);
        flags = oc::BitVector(outView.data(), Y.size(), /*copyData=*/false);
        //OT phase
        finalOtMsgs.resize(Y.size());

        for (u64 i = 0; i < Y.size(); i++){

            if(flags[i] == 0){
                finalOtMsgs[i][1] = Y[i];
                finalOtMsgs[i][0] = osuCrypto::ZeroBlock;
            }
            else{
                finalOtMsgs[i][1] = osuCrypto::ZeroBlock;
                finalOtMsgs[i][0] = Y[i];
            }

            
        }
        //finalOtSender->configure(Y.size(), 2, mNumThreads);
        finalOtSender->configure(Y.size(), 2, 1);

        MC_AWAIT(finalOtSender->sendChosen(finalOtMsgs, prng, chl));

        MC_END();
    }
    
    Proto AltModPsuReceiver::run_debug(span<block> X, PRNG &prng, Socket &chl, Socket &socket_gmw)
    {
        MC_BEGIN(Proto, this, X, &prng, &chl, &socket_gmw,
                i = int{},
                epsilon = double{},
                n = int{},
                m = int{},
                band_length= int{},
                okvs = band_okvs::BandOkvs{},
                okvs_encoding = std::vector<block>{},
                random_value = std::vector<block>{},
                ole0 = CorGenerator{},
                ole_gmw = CorGenerator{},
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
                numThreads = osuCrypto::u64{},
                cmp = std::make_unique<Gmw>(),
                cir = BetaCircuit{},
                in = oc::Matrix<block>{},
                outView = oc::MatrixView<u8>{},
                ot_choice = oc::BitVector{},
                // timer = oc::Timer{},

                finalOtReceiver = std::make_unique<oc::SilentOtExtReceiver>(),
                finalOtMsgs = std::vector<block>{}
        );

		sender_virtual.mUseMod2F4Ot = true; // check
		recver_virtual.mUseMod2F4Ot = true;

		// ciphertext_of_wprf.resize(X.size());
        secret_string = prng.get();
		y0.resize(X.size());
        y1.resize(X.size());
        // separate function
        // use AltModPrf only receiver

        std::cout << "start 1party wprf\n";
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

            ole0_virtual.init(sock2_virtual[0].fork(), prng0, 0, 1, 1 << 18, 1);
            ole1_virtual.init(sock2_virtual[1].fork(), prng1, 1, 1, 1 << 18, 1);

            random_value.resize(X.size());
            prng0.get(random_value.data(), X.size());
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

                std::cout << "start wating wprf protocol\n";
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

        std::cout << "1party wprf end\n";

        // ciphertext_of_wprf.resize(X.size());
        // for (i = 0; i < X.size();, i++){
        //     ciphertext_of_wprf[i] = secret_string^y0[i]^y1[i];
        // }
        
        output_1party_wprf.resize(X.size());
        for (i = 0; i < X.size(); i++){
            output_1party_wprf[i] = y0[i]^y1[i];
        }

        // make rb_okvs
        epsilon = 0.1;
        n = X.size();
        m = static_cast<int>((1 + epsilon) * n);
        band_length = 128;

        okvs.Init(n, m, band_length, oc::ZeroBlock);

        std::cout << "start okvs encoding\n";

        okvs_encoding.resize(okvs.Size());
        if (!okvs.Encode(X.data(), random_value.data(), okvs_encoding.data())) {
            std::cout << "Failed to encode!" << std::endl;
            exit(0);
        }

        std::cout << "okvs encoding end\n";

        MC_AWAIT(chl.send(okvs_encoding));

        std::cout << "init ole0\n";

        ole0.init(chl.fork(), prng, 0, 1, 1 << 18, 0);
        
        for (u64 i = 0; i < AltModPrf::KeySize; ++i)
		{
			rk[i] = oc::block(i, *oc::BitIterator((u8*)&sender.mKeyMultRecver.mKey, i));
		}
        sender.setKeyOts(kk, rk);

        sender.init(X.size(), ole0);
        sender.mUseMod2F4Ot = true;// check
        sender.setTimer(timer);

        // ole0.start();
        // sender.evaluate({}, y0, sock[0], prng0);

        output_2party_wprf.resize(X.size());
        tOle   = ole0.start();
        tEvalR = sender.evaluate({}, output_2party_wprf, chl, prng0);

        std::cout << "start 2party wprf\n";

        MC_AWAIT(when_all_ready(tOle, tEvalR));
        // MC_AWAIT(when_all_ready(tOle));
        // std::cout << "2party ole end wprf\n";
        // MC_AWAIT(when_all_ready(tEvalR));

        std::cout << "start gmw\n";

        cir = isZeroCircuit(128);

        numThreads = static_cast<osuCrypto::u64>(std::thread::hardware_concurrency());
        in.resize(X.size(), 1);
        for (i = 0; i < X.size(); i++)
            in(i, 0) = output_2party_wprf[i]^output_1party_wprf[i];
        
        ole_gmw.init(socket_gmw.fork(), prng, 0, 1, 1 << 18, 0);

        cmp->init(X.size(), cir, ole_gmw);
        cmp->setInput(0, in);
        cmp->mO.mDebug = true;

        cmp->preprocess();

        std::cout << "run gmw\n";
        // ole_gmw.start();

        // MC_AWAIT(cmp->run(socket_gmw));
        tgmw = cmp->run(socket_gmw);
        tgmw_ole = ole_gmw.start();
        MC_AWAIT(when_all_ready(tgmw, tgmw_ole));

        std::cout << "gmw end\n";

        outView = cmp->getOutputView(0);

        std::cout << "start ot\n";

        ot_choice.resize(X.size());
        // ot_choice.assign(outView.data(), /*bitLen=*/X.size(), /*copyData=*/false);
        ot_choice = oc::BitVector(outView.data(), X.size(), /*copyData=*/false);

        finalOtMsgs.resize(ot_choice.size());
        finalOtReceiver->configure(ot_choice.size(), 2, 1);
        
        MC_AWAIT(finalOtReceiver->receiveChosen(ot_choice, finalOtMsgs, prng, chl));
        
        std::cout << timer << '\n';
        
        MC_END();

    }


    // //AltPsu Part
    // {
	// 	u64 n = cmd.getOr("n", 1ull << cmd.getOr("nn", 10));
	// 	u64 trials = cmd.getOr("trials", 1);
	// 	bool nt = cmd.getOr("nt", 1);
	// 	auto useOle = cmd.isSet("ole");

	// 	oc::Timer timer;

	// 	AltModWPrfSender sender;
	// 	AltModWPrfReceiver recver;

	// 	sender.mUseMod2F4Ot = !useOle;
	// 	recver.mUseMod2F4Ot = !useOle;

	// 	sender.setTimer(timer);
	// 	recver.setTimer(timer);

	// 	std::vector<oc::block> x(n);
	// 	std::vector<oc::block> y0(n), y1(n);

	// 	auto sock = coproto::LocalAsyncSocket::makePair();
	// 	auto sock2 = coproto::LocalAsyncSocket::makePair();
    //     auto sock_virtual = coproto::LocalAsyncSocket::makePair();
	// 	auto sock2_virtual = coproto::LocalAsyncSocket::makePair();
	// 	macoro::thread_pool pool0;
	// 	auto e0 = pool0.make_work();
	// 	pool0.create_threads(nt);
	// 	macoro::thread_pool pool1;
	// 	auto e1 = pool1.make_work();
	// 	pool1.create_threads(nt);
	// 	sock[0].setExecutor(pool0);
	// 	sock[1].setExecutor(pool1);
	// 	sock2[0].setExecutor(pool0);
	// 	sock2[1].setExecutor(pool1);


	// 	PRNG prng0(oc::ZeroBlock);
	// 	PRNG prng1(oc::OneBlock);

	// 	AltModPrf dm;
	// 	AltModPrf::KeyType kk;
	// 	kk = prng0.get();
	// 	dm.setKey(kk);
	// 	//sender.setKey(kk);

	// 	CorGenerator ole0, ole1;
	// 	ole0.init(sock2[0].fork(), prng0, 0, nt, 1 << 18, cmd.getOr("mock", 1));
	// 	ole1.init(sock2[1].fork(), prng1, 1, nt, 1 << 18, cmd.getOr("mock", 1));


	// 	prng0.get(x.data(), x.size());
	// 	std::vector<oc::block> rk(AltModPrf::KeySize);
	// 	std::vector<std::array<oc::block, 2>> sk(AltModPrf::KeySize);
	// 	for (u64 i = 0; i < AltModPrf::KeySize; ++i)
	// 	{
	// 		sk[i][0] = oc::block(i, 0);
	// 		sk[i][1] = oc::block(i, 1);
	// 		rk[i] = oc::block(i, *oc::BitIterator((u8*)&sender.mKeyMultRecver.mKey, i));
	// 	}
	// 	sender.setKeyOts(kk, rk);
	// 	recver.setKeyOts(sk);
	// 	u64 numOle = 0;
	// 	u64 numF4BitOt = 0;
	// 	u64 numOt = 0;

	// 	auto begin = timer.setTimePoint("begin");
	// 	for (u64 t = 0; t < trials; ++t)
	// 	{
	// 		sender.init(n, ole0);
	// 		recver.init(n, ole1);

	// 		numOle += ole0.mGenState->mNumOle;
	// 		numF4BitOt += ole0.mGenState->mNumF4BitOt;
	// 		numOt += ole0.mGenState->mNumOt;

	// 		auto r = coproto::sync_wait(coproto::when_all_ready(
	// 			ole0.start() | macoro::start_on(pool0),
	// 			ole1.start() | macoro::start_on(pool1),
	// 			sender.evaluate({}, y0, sock[0], prng0) | macoro::start_on(pool0),
	// 			recver.evaluate(x, y1, sock[1], prng1) | macoro::start_on(pool1)
	// 		));
	// 		std::get<0>(r).result();
	// 		std::get<1>(r).result();
	// 		std::get<2>(r).result();
	// 		std::get<3>(r).result();
	// 	}
	// 	auto end = timer.setTimePoint("end");

	// 	auto ntr = n * trials;

	// 	std::cout << "AltModWPrf n:" << n << ", " <<
	// 		std::chrono::duration_cast<std::chrono::nanoseconds>(end - begin).count() / double(ntr) << "ns/eval " <<
	// 		sock[0].bytesSent() / double(ntr) << "+" << sock[0].bytesReceived() / double(ntr) << "=" <<
	// 		(sock[0].bytesSent() + sock[0].bytesReceived()) / double(ntr) << " bytes/eval ";

	// 	std::cout << numOle / double(ntr) << " ole/eval ";
	// 	std::cout << numF4BitOt / double(ntr) << " f4/eval ";
	// 	std::cout << numOt / double(ntr) << " ot/eval ";

	// 	std::cout << std::endl;

	// 	if (cmd.isSet("v"))
	// 	{
	// 		std::cout << timer << std::endl;
	// 		std::cout << sock[0].bytesReceived() / 1000.0 << " " << sock[0].bytesSent() / 1000.0 << " kB " << std::endl;
	// 	}
	// }


}