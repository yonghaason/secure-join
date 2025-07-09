#include "AltPsu.h"
#include "secure-join/Prf/AltModPrfProto.h"
#include "secure-join/Sort/RadixSort.h"
#include "secure-join/Join/OmJoin.h"
#include "secure-join/Perm/PprfPermGen.h"
#include "secure-join/GMW/Gmw.h"

using namespace std;

namespace secJoin
{

    Proto AltModPsuSender::run_co(span<block> Y, PRNG &prng, Socket &chl)
    {
        // receive okvs encoding / okvs decode

        timer.setTimePoint("start");

        double epsilon = 0.1;
        size_t n = Y.size();
        size_t m = static_cast<size_t>((1 + epsilon) * n);
        size_t band_length = 128;

        band_okvs::BandOkvs okvs;
        okvs.Init(n, m, band_length, oc::ZeroBlock);

        vector<block> okvs_encoding(okvs.Size());
        co_await chl.recv(okvs_encoding);

        // prng.get(okvs_encoding.data(), okvs.Size());

        timer.setTimePoint("Recv OKVS");

        vector<block> decoded(Y.size());
        okvs.Decode(Y.data(), okvs_encoding.data(), decoded.data());

        timer.setTimePoint("Decode OKVS");

        // 2aprty wprf
        CorGenerator ole1;
		ole1.init(chl.fork(), prng, 1, 1, 1 << 18, 0);
        
        // vector<std::array<block, 2>> sk(AltModPrf::KeySize);
        // for (size_t i = 0; i < 128; ++i)
		// {
		// 	sk[i][0] = oc::block(i, 0);
		// 	sk[i][1] = oc::block(i, 1);
		// }

        AltModWPrfReceiver recver;
        // recver.setKeyOts(sk);

        recver.init(Y.size(), ole1);
        recver.mUseMod2F4Ot = true;
        recver.setTimer(timer);

        vector<block> sharedPRF(Y.size());
        // auto tOle = ole1.start();
        // auto tEvalS = recver.evaluate(decoded, sharedPRF, chl, prng);
        // co_await macoro::when_all_ready(tOle, tEvalS);

        co_await macoro::when_all_ready(
            ole1.start(), 
            recver.evaluate(decoded, sharedPRF, chl, prng)
        );

        timer.setTimePoint("Shared PRF eval");

        // gmw part
        BetaCircuit cir = isZeroCircuit(80);
        
        oc::Matrix<u8> in(Y.size(), 10);
        for (size_t i = 0; i < Y.size(); i++){
            std::memcpy(&in(i, 0), &sharedPRF[i], 10);
        }

        CorGenerator ole_gmw;
        ole_gmw.init(chl.fork(), prng, 1, 1, 1 << 18, 0);

        Gmw cmp;
        cmp.init(in.rows(), cir, ole_gmw);
        cmp.setInput(0, in);

        auto tgmw = cmp.run(chl);
        auto tgmw_ole = ole_gmw.start();
        co_await macoro::when_all_ready(tgmw, tgmw_ole);

        auto outView = cmp.getOutputView(0);

        oc::BitVector flags(Y.size());
        flags = oc::BitVector(outView.data(), Y.size(), /*copyData=*/false);

        timer.setTimePoint("GMW");

        //OT phase
        std::vector<std::array<block, 2>> finalOtMsgs(Y.size());

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
        
        oc::SilentOtExtSender finalOtSender;
        finalOtSender.configure(Y.size(), 2, 1);

        co_await finalOtSender.sendChosen(finalOtMsgs, prng, chl);

        timer.setTimePoint("ot");

        std::cout << "Sender Timer" << std::endl; 
        std::cout << timer << '\n';
    };

    Proto AltModPsuReceiver::run_co(span<block> X, PRNG &prng, Socket &chl)
    {
        timer.setTimePoint("start");
        double communication_cost;

        // use AltModPrf only receiver
        AltModPrf dm(prng.get());
        vector<block> myPRF(X.size());
        vector<block> random_value(X.size());
        
        prng.get(random_value.data(), X.size());
        dm.eval(random_value, myPRF);

        timer.setTimePoint("Local PRF computation");

        // make rb_okvs
        double epsilon = 0.1;
        size_t n = X.size(); // Should be Y size
        size_t m = static_cast<int>((1 + epsilon) * n);
        size_t band_length = 128;

        band_okvs::BandOkvs okvs;
        okvs.Init(n, m, band_length, oc::ZeroBlock);

        vector<block> okvs_encoding(okvs.Size());
        if (!okvs.Encode(X.data(), random_value.data(), okvs_encoding.data())) {
            std::cout << "Failed to encode!" << std::endl;
            exit(0);
        }
        
        // send okvs encoding
        co_await chl.send(std::move(okvs_encoding));
        timer.setTimePoint("okvs encode");

        std::cout << "okvs communication is " << ((chl.bytesSent() + chl.bytesReceived()) - communication_cost) / 1024 / 1024 << "MB\n";
        communication_cost = (chl.bytesSent() + chl.bytesReceived());
        
        // 2party wprf part

        CorGenerator ole0;
        ole0.init(chl.fork(), prng, 0, 1, 1 << 18, 0);
        
        vector<block> rk(AltModPrf::KeySize);
        AltModWPrfSender sender;
        // for (u64 i = 0; i < AltModPrf::KeySize; ++i)
		// {
		// 	rk[i] = oc::block(i, *oc::BitIterator((u8*)&dm.mExpandedKey, i));
		// }
        // sender.setKeyOts(dm.getKey(), rk);

        sender.init(X.size(), ole0); // Should be Y size
        sender.mUseMod2F4Ot = true;// check
        sender.setTimer(timer);

        vector<block> sharedPRF(X.size()); // Should be Y size
        // auto tOle = ole0.start();
        // auto tEvalR = sender.evaluate({}, sharedPRF, chl, prng);
        // co_await macoro::when_all_ready(tOle, tEvalR);

        co_await macoro::when_all_ready( 
            ole0.start(),
            sender.evaluate({}, sharedPRF, chl, prng)
        );

        timer.setTimePoint("Shared PRF eval");

        std::cout << "wprf communication is " << ((chl.bytesSent() + chl.bytesReceived()) - communication_cost) / 1024 / 1024 << "MB\n";
        communication_cost = (chl.bytesSent() + chl.bytesReceived());

        // gmw part
        BetaCircuit cir = isZeroCircuit(80);

        oc::Matrix<u8> in(X.size(), 10);
        for (size_t i = 0; i < X.size(); i++){
            block tmp = sharedPRF[i]^myPRF[i];
            std::memcpy(&in(i, 0), &tmp, 10);
        }

        CorGenerator ole_gmw;
        ole_gmw.init(chl.fork(), prng, 0, 1, 1 << 18, 0);
        
        Gmw cmp;
        cmp.init(in.rows(), cir, ole_gmw);
        cmp.setInput(0, in);

        auto tgmw = cmp.run(chl);
        auto tgmw_ole = ole_gmw.start();
        co_await macoro::when_all_ready(tgmw, tgmw_ole);

        std::cout << "gmw communication is " << ((chl.bytesSent() + chl.bytesReceived()) - communication_cost) / 1024 / 1024 << "MB\n";
        communication_cost = (chl.bytesSent() + chl.bytesReceived());
        
        auto outView = cmp.getOutputView(0);

        oc::BitVector ot_choice(X.size());
        ot_choice = oc::BitVector(outView.data(), X.size(), /*copyData=*/false);

        timer.setTimePoint("gmw");

        // ot part
        vector<block> finalOtMsgs(ot_choice.size());
        oc::SilentOtExtReceiver finalOtReceiver;
        finalOtReceiver.configure(ot_choice.size(), 2, 1);
        
        co_await(finalOtReceiver.receiveChosen(ot_choice, finalOtMsgs, prng, chl));

        std::cout << "ot communication is " << ((chl.bytesSent() + chl.bytesReceived()) - communication_cost) / 1024 / 1024 << "MB\n";
        communication_cost = (chl.bytesSent() + chl.bytesReceived());
        
        timer.setTimePoint("ot");

        std::cout << "Receiver Timer" << std::endl;
        std::cout << timer << '\n';
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
