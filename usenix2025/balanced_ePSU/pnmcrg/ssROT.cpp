#include "ssROT.h"


void softSend(u32 numElements, Socket &chl, PRNG& prng, AlignedVector<std::array<block, 2>> &sMsgs, u32 numThreads)
{
    SoftSpokenShOtSender<> sender;
    sender.init(fieldBits, true);
    const size_t numBaseOTs = sender.baseOtCount();
    PRNG prngOT(prng.get<block>());
    AlignedVector<block> baseMsg;
    // choice bits for baseOT
    BitVector baseChoice;

    // OTE's sender is base OT's receiver
    DefaultBaseOT base;
    baseMsg.resize(numBaseOTs);
    // randomize the base OT's choice bits
    baseChoice.resize(numBaseOTs);
    baseChoice.randomize(prngOT);
    // perform the base ot, call sync_wait to block until they have completed.
    coproto::sync_wait(base.receive(baseChoice, baseMsg, prngOT, chl));

    sender.setBaseOts(baseMsg, baseChoice);
    // perform random ots

    sMsgs.resize(numElements);
    coproto::sync_wait(sender.send(sMsgs, prngOT, chl));

}

void softRecv(u32 numElements, BitVector bitV, Socket &chl, PRNG& prng, AlignedVector<block> &rMsgs, u32 numThreads)
{

    SoftSpokenShOtReceiver<> receiver;
    receiver.init(fieldBits, true);
    const size_t numBaseOTs = receiver.baseOtCount();
    AlignedVector<std::array<block, 2>> baseMsg(numBaseOTs);
    PRNG prngOT(prng.get<block>());

    // OTE's receiver is base OT's sender
    DefaultBaseOT base;
    // perform the base ot, call sync_wait to block until they have completed.
    coproto::sync_wait(base.send(baseMsg, prngOT, chl));

    receiver.setBaseOts(baseMsg);

    rMsgs.resize(numElements);
    coproto::sync_wait(receiver.receive(bitV, rMsgs, prngOT, chl));

}


void ssROT(bool isSender, u32 numBins, Socket &chl, BitVector bitV, std::vector<block> &Out, PRNG& prng, u32 numThreads)
{
    Out.resize(numBins);
    AlignedVector<std::array<block, 2>> sMsgs(numBins);
    AlignedVector<block> rMsgs(numBins);

    if(isSender){
        softSend(numBins, chl, prng, sMsgs, numThreads);

        for(u32 i = 0; i < numBins; ++i){
            Out[i] = sMsgs[i][bitV[i]];
        }        
    }
    else{
        softRecv(numBins, bitV, chl, prng, rMsgs, numThreads);
        memcpy(Out.data(), rMsgs.data(), numBins * sizeof(block));
    }

    return;    
}
