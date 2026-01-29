#pragma once
#include "cryptoTools/Common/Timer.h"
#include "cryptoTools/Common/BitVector.h"
#include "secure-join/GMW/Gmw.h"
#include "secure-join/AltPsu/AltPsu.h"
#include "secure-join/volePSI/RsOprf.h"
#include "secure-join/Prf/AltModPrfProto.h"
#include "secure-join/Sort/RadixSort.h"
#include "secure-join/Join/OmJoin.h"
#include "secure-join/Perm/PprfPermGen.h"

#include "libOTe/Vole/Silent/SilentVoleSender.h"
#include "libOTe/Vole/Silent/SilentVoleReceiver.h"
#include "secure-join/volePSI/Paxos.h"

// #include "ddh_oprf.hpp"

namespace secJoin
{
    using Proto = coproto::task<>;
    using Socket = coproto::Socket;

    class AltModPidSender : public oc::TimerAdapter
    {
        AltModPsuSender PsuSender;
        AltModPsuSender PsuReceiver;
        u64 SenderSetSize;

    public:

        std::vector<block> OPRFSum;
        std::vector<block> OPRFTable;
        std::vector<block> UID;
        AltModPrf dm;
        int flag = 0;
        std::atomic<int> ddhRuns{0};

        std::vector<uint8_t> key;

        // Key Fixed OPRF
        std::vector<block> OPRFkey;
        int myKeySize;
        int initSetSize;
        block delta;
        oc::SilentVoleSender<block,block, oc::CoeffCtxGF128> mVoleSender;
        oc::SilentVoleReceiver<block, block, oc::CoeffCtxGF128> mVoleRecver;
        // auto fu = macoro::eager_task<void>{};
        Baxos mPaxos;
        Baxos Paxos;
        u64 mBinSize = 1 << 14;
        u64 mSsp = 40;
        u64 numThreads = 1;

        // DDH-OPRF
        int invokeNumber = 0;

        // Proto run(span<block> Y, u64 XSize, PRNG& prng, Socket& chl);

        // Proto update(span<block> Y, u64 XSize, PRNG& prng, Socket& chl);

        Proto evalOPRF(span<block> Y, u64 XSize, PRNG& prng, Socket& chl);
        Proto evalRR22(span<block> Y, u64 XSize, PRNG& prng, Socket& chl);
        void evalDDH(span<block> Y, u64 XSize, PRNG& prng);


        // Proto update(span<block> Y, u64 XSize, PRNG& prng, Socket& chl);
        
    };

    class AltModPidReceiver :public oc::TimerAdapter
    {
        AltModPsuSender PsuSender;
        AltModPsuSender PsuReceiver;
        u64 ReceiverSetSize;

    public:

        std::vector<block> OPRFSum;
        std::vector<block> OPRFTable;
        std::vector<block> UID;
        AltModPrf dm;
        int flag = 0;

        std::vector<uint8_t> key;

        // Key Fixed OPRF
        std::vector<block> OPRFkey;
        block delta;
        int myKeySize;
        int initSetSize;
        oc::SilentVoleSender<block,block, oc::CoeffCtxGF128> mVoleSender;
        oc::SilentVoleReceiver<block, block, oc::CoeffCtxGF128> mVoleRecver;
        // auto fu = macoro::eager_task<void>{};
        Baxos mPaxos;
        Baxos Paxos;
        u64 mBinSize = 1 << 14;
        u64 mSsp = 40;
        u64 numThreads = 1;

        // DDH-OPRF
        int invokeNumber = 0;

        // Proto run(span<block> X, u64 YSize,PRNG& prng, Socket& chl);    

        // Proto update(span<block> X, u64 YSize,PRNG& prng, Socket& chl);

        Proto evalOPRF(span<block> X, u64 YSize, PRNG& prng, Socket& chl);
        Proto evalRR22(span<block> X, u64 YSize, PRNG& prng, Socket& chl);
        void evalDDH(span<block> X, u64 YSize, PRNG& prng);

        // Proto update(span<block> X, u64 YSize, PRNG& prng, Socket& chl);

    };

    void runPID(AltModPidSender& Sender, AltModPidReceiver& Receiver, int OPRFflag, span<block> X, span<block> Y, PRNG& prng, Socket& chl1, Socket& chl2, int PartyFlag = 0);

    void runUpdate(AltModPidSender& Sender, AltModPidReceiver& Receiver, int OPRFflag, int updateNumber, PRNG& prng, Socket& chl1, Socket& chl2, int PartyFlag);

    

}
