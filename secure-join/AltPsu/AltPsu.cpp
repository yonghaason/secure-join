#include "AltPsu.h"
#include "secure-join/Prf/AltModPrfProto.h"
#include "secure-join/Sort/RadixSort.h"
#include "secure-join/Join/OmJoin.h"
#include "secure-join/Perm/PprfPermGen.h"
#include "secure-join/GMW/Gmw.h"

using namespace std;



namespace secJoin
{
    u64 log_batch = 22;

    Proto AltModPsuSender::run(span<block> Y, PRNG& prng, Socket& chl)
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
        vector<block> okvs_encoding2(okvs.Size());

        co_await chl.recv(okvs_encoding);
        co_await chl.recv(okvs_encoding2);

        // prng.get(okvs_encoding.data(), okvs.Size());

        timer.setTimePoint("Recv OKVS");

        vector<block> decoded(Y.size());
        vector<block> decoded2(Y.size());
        okvs.Decode(Y.data(), okvs_encoding.data(), decoded.data());
        okvs.Decode(Y.data(), okvs_encoding2.data(), decoded2.data());

        timer.setTimePoint("Decode OKVS");

        // 2aprty wprf
        CorGenerator ole1;
        ole1.init(chl.fork(), prng, 1, 1, 1 << log_batch, 0);

        oc::SilentOtExtSender keyOtSender;
        std::vector<std::array<oc::block, 2>> sk(AltModPrf::KeySize);
        keyOtSender.configure(AltModPrf::KeySize);
        co_await keyOtSender.send(sk, prng, chl);

        AltModWPrfReceiver recver;
        recver.init(Y.size(), ole1, AltModPrfKeyMode::SenderOnly, AltModPrfInputMode::ReceiverOnly, {}, sk);
        recver.mUseMod2F4Ot = true;
        recver.setTimer(timer);

        vector<block> sharedPRF(Y.size());

        co_await macoro::when_all_ready(
            ole1.start(),
            recver.evaluate(decoded, sharedPRF, chl, prng)
        );

        timer.setTimePoint("Shared PRF eval");

        // gmw part
        u64 prf_bitlen = 80;
        BetaCircuit cir = isZeroCircuit(prf_bitlen);

        oc::Matrix<u8> in(Y.size(), (prf_bitlen+7)/8);
        block temp;
        for (size_t i = 0; i < Y.size(); i++) {
            temp = sharedPRF[i] ^ decoded2[i];
            std::memcpy(&in(i, 0), &temp, (prf_bitlen+7)/8);
        }

        CorGenerator ole_gmw;
        ole_gmw.init(chl.fork(), prng, 1, 1, 1 << log_batch, 0);

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

        for (u64 i = 0; i < Y.size(); i++) {    
            finalOtMsgs[i][flags[i]] = Y[i];
            finalOtMsgs[i][!flags[i]] = oc::ZeroBlock;
        }

        oc::SilentOtExtSender finalOtSender;
        finalOtSender.configure(Y.size());

        co_await finalOtSender.sendChosen(finalOtMsgs, prng, chl);

        std::cout << "Sender Timer" << std::endl;
        std::cout << timer << '\n';
    };

    Proto AltModPsuReceiver::run(span<block> X, std::vector<block>& D, PRNG& prng, Socket& chl)
    {
        timer.setTimePoint("start");
        double communication_cost;

        // use AltModPrf only receiver
        AltModPrf dm(prng.get());
        vector<block> myPRF(X.size());
        vector<block> random_value(X.size());

        // Local F_k(X)
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
        vector<block> okvs_encoding2(okvs.Size());
        if (!okvs.Encode(X.data(), myPRF.data(), okvs_encoding2.data())) {
            std::cout << "Failed to encode!" << std::endl;
            exit(0);
        }

        // send okvs encoding
        co_await chl.send(std::move(okvs_encoding));
        co_await chl.send(std::move(okvs_encoding2));
        timer.setTimePoint("okvs encode");

        std::cout << "okvs communication is " << ((chl.bytesSent() + chl.bytesReceived()) - communication_cost) / 1024 / 1024 << "MB\n";
        communication_cost = (chl.bytesSent() + chl.bytesReceived());

        // 2party wprf part
        CorGenerator ole0;
        ole0.init(chl.fork(), prng, 0, 1, 1 << log_batch, 0);

        oc::SilentOtExtReceiver keyOtReceiver;
        std::vector<oc::block> rk(AltModPrf::KeySize);
        keyOtReceiver.configure(AltModPrf::KeySize);
        oc::BitVector kk_bv;
        kk_bv.append((u8*)dm.getKey().data(), AltModPrf::KeySize);

        co_await keyOtReceiver.receive(kk_bv, rk, prng, chl);

        AltModWPrfSender sender;
        sender.init(X.size(), ole0, AltModPrfKeyMode::SenderOnly, AltModPrfInputMode::ReceiverOnly, dm.getKey(), rk); // Should be Y size

        // sender.init(X.size(), ole0);
        sender.mUseMod2F4Ot = true;
        sender.setTimer(timer);

        vector<block> sharedPRF(X.size()); // Should be Y size

        co_await macoro::when_all_ready(
            ole0.start(),
            sender.evaluate({}, sharedPRF, chl, prng)
        );

        timer.setTimePoint("Shared PRF eval");

        std::cout << "wprf communication is " << ((chl.bytesSent() + chl.bytesReceived()) - communication_cost) / 1024 / 1024 << "MB\n";
        communication_cost = (chl.bytesSent() + chl.bytesReceived());

        // gmw part
        u64 prf_bitlen = 80;
        BetaCircuit cir = isZeroCircuit(prf_bitlen);

        oc::Matrix<u8> in(X.size(), (prf_bitlen+7)/8);
        block tmp;
        for (size_t i = 0; i < X.size(); i++) {
            tmp = sharedPRF[i];
            std::memcpy(&in(i, 0), &tmp, (prf_bitlen+7)/8);
        }

        CorGenerator ole_gmw;
        ole_gmw.init(chl.fork(), prng, 0, 1, 1 << log_batch, 0);        

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
        finalOtReceiver.configure(ot_choice.size());

        co_await(finalOtReceiver.receiveChosen(ot_choice, finalOtMsgs, prng, chl));

        std::cout << "ot communication is " << ((chl.bytesSent() + chl.bytesReceived()) - communication_cost) / 1024 / 1024 << "MB\n";
        communication_cost = (chl.bytesSent() + chl.bytesReceived());

        timer.setTimePoint("ot");

        std::cout << "Receiver Timer" << std::endl;
        std::cout << timer << '\n';

        for (auto &m : finalOtMsgs){
            if (m != oc::ZeroBlock)
                D.push_back(m);
        }
    }
}