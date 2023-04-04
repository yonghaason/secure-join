#include "OleGenerator.h"

#define LOG(X) log(X)

namespace secJoin
{

    macoro::task<> OleGenerator::Gen::start()
    {
        MC_BEGIN(macoro::task<>, this,
            slotIdx = u64{},
            done = false,
            sendMsg = oc::AlignedUnVector<std::array<oc::block, 2>>{},
            recvMsg = oc::AlignedUnVector<oc::block>{},
            bv = oc::BitVector{},
            diff = oc::BitVector{},
            chunk = Chunk{}
        );

        LOG("start");

        while (true)
        {
            MC_AWAIT_SET(chunk, mInQueue->pop());
            LOG("pop chunk " + std::to_string(chunk.mIdx));
            MC_AWAIT(macoro::transfer_to(*mParent->mThreadPool));
            LOG("transfered " + std::to_string(chunk.mIdx));
            //A// std::cout << "pop chunk" << std::endl;


            if (chunk.mBaseRecv.size() == 0 && chunk.mBaseSend.size() == 0)
            {
                MC_AWAIT(mParent->mControlQueue->push({ Command::GenStopped{chunk.mIdx} }));
                LOG("genStop");

                MC_RETURN_VOID();
            }

            if (mParent->mRole == Role::Sender)
            {
                //diff.resize(chunk.mBaseSend.size());
                //MC_AWAIT(mChl.recv(diff));
                //LOG("recv diff " + std::to_string(chunk.mIdx));

                ////A// std::cout << "recv diff" << std::endl;

                //for (u64 i = 0; i < diff.size(); ++i)
                //{
                //    if (diff[i])
                //        std::swap(chunk.mBaseSend[i][0], chunk.mBaseSend[i][1]);
                //}

                //mSender->configure(mParent->mChunkSize);
                //mSender->setSilentBaseOts(chunk.mBaseSend);

                sendMsg.resize(mParent->mChunkSize);
                MC_AWAIT(mSender->silentSend(sendMsg, mPrng, mChl));
                LOG("silentSend " + std::to_string(chunk.mIdx));
                //A// std::cout << "send ot " << sendMsg[0][0] << " " << sendMsg[0][1] << std::endl;

                chunk.mAdd.resize(mParent->mChunkSize / 128);
                chunk.mMult.resize(mParent->mChunkSize / 128);
                compressSender(sendMsg, chunk.mAdd, chunk.mMult);
            }
            else
            {
                //mRecver->configure(mParent->mChunkSize);
                //diff = mRecver->sampleBaseChoiceBits(mPrng) ^ chunk.mBaseChoice;;
                //MC_AWAIT(mChl.send(std::move(diff)));
                //LOG("send diff " + std::to_string(chunk.mIdx));
                //mRecver->setSilentBaseOts(chunk.mBaseRecv);

                recvMsg.resize(mParent->mChunkSize);
                bv.resize(mParent->mChunkSize);
                MC_AWAIT(mRecver->silentReceive(bv, recvMsg, mPrng, mChl));
                LOG("silentReceive " + std::to_string(chunk.mIdx));
                //A// std::cout << "recv ot " << recvMsg[0] << " " << bv[0] << std::endl;

                chunk.mAdd.resize(mParent->mChunkSize / 128);
                chunk.mMult.resize(mParent->mChunkSize / 128);
                compressRecver(bv, recvMsg, chunk.mAdd, chunk.mMult);
            }

            //A// std::cout << "push" << std::endl;
            LOG("publish " + std::to_string(chunk.mIdx));

            MC_AWAIT(mParent->mControlQueue->push({ Command::ChunkComplete{std::move(chunk)} }));
            LOG("published " + std::to_string(chunk.mIdx));
        }

        MC_END();
    }



    macoro::task<> OleGenerator::stop()
    {
        MC_BEGIN(macoro::task<>, this);


        if (!mFakeGen)
        {
            MC_AWAIT(mControlQueue->push({ Command::Stop{} }));
            MC_AWAIT(mCtrl);
        }

        MC_END();
    }

    //macoro::task<> OleGenerator::baseOtProvider(oc::block seed)
    //{
    //    MC_BEGIN(macoro::task<>, this, 
    //        sender = oc::SoftSpokenShOtSender{},
    //        recver = oc::SoftSpokenShOtReceiver{},
    //        prng = oc::PRNG(seed),
    //        n = u64{},
    //        base = Command::BaseOt{}
    //        );

    //    if (mRole == Role::Sender)
    //    {
    //        MC_AWAIT(recver.genBaseOts(prng, mChl));

    //        do {
    //            MC_AWAIT_SET(n, mBaseOtQueue->pop());
    //            
    //            if (n)
    //            {
    //                base.mRecvChoice.resize(n);
    //                base.mRecvChoice.randomize(prng);

    //                base.mRecvOt.resize(n);
    //                MC_AWAIT(recver.receive(base.mRecvChoice, base.mRecvOt, prng, mChl));

    //                MC_AWAIT(mControlQueue->push(Command{ std::move(base) }));
    //            }

    //        } while (n);
    //    }
    //    else
    //    {
    //        MC_AWAIT(sender.genBaseOts(prng, mChl));

    //        do {
    //            MC_AWAIT_SET(n, mBaseOtQueue->pop());

    //            if (n)
    //            {
    //                base.mRecvChoice.resize(n);
    //                base.mRecvOt.resize(n);
    //                MC_AWAIT(sender.send(base.mSendOt, prng, mChl));

    //                MC_AWAIT(mControlQueue->push(Command{ std::move(base) }));
    //            }

    //        } while (n);
    //    }


    //    MC_END();
    //}

    macoro::task<> OleGenerator::control()
    {
        MC_BEGIN(macoro::task<>, this,
            i = u64{},
            chunk = Chunk{},
            cmd = Command{},
            pushIdxs = std::vector<u64>{},
            popIdx = u64{},
            numTasks = u64{},
            pendingChunks = std::vector<Chunk>{},
            getEvent = (macoro::async_manual_reset_event*)nullptr,
            baseLeft = u64{},
            baseReservoirCapacity = u64{},
            baseReservoir = u64{},
            baseSender = oc::SoftSpokenMalOtSender{},
            baseRecver = oc::SoftSpokenMalOtReceiver{}

        );

        //A// std::cout << "control " << std::endl;
        LOG("control: start");

        numTasks = 0;

        {
            oc::SilentOtExtSender s;
            s.configure(mChunkSize);
            mBaseSize = s.silentBaseOtCount();
            //std::cout << "total base " << mNumChunks * mBaseSize << " = n " << mNumChunks << " * s " << mBaseSize << std::endl;
        }

        if (mRole == Role::Sender)
        {
            MC_AWAIT(baseSender.genBaseOts(mPrng, mChl));
        }
        else
        {
            MC_AWAIT(baseRecver.genBaseOts(mPrng, mChl));
        }

        LOG("Base done");

        mGens.resize(mNumConcurrent);
        for (i = 0; i < mNumConcurrent; ++i)
        {

            if (mRole == Role::Sender)
            {
                mGens[i].mSender.reset(new oc::SilentOtExtSender);
                mGens[i].mSender->mOtExtSender = baseSender.splitBase();
            }
            else
            {
                mGens[i].mRecver.reset(new oc::SilentOtExtReceiver);
                mGens[i].mRecver->mOtExtRecver = baseRecver.splitBase();
            }

            ++numTasks;
            mGens[i].mIdx = i;
            mGens[i].mInQueue.reset(new macoro::spsc::channel<Chunk>(oc::divCeil(mReservoirSize, mNumConcurrent)));
            mGens[i].mParent = this;
            mGens[i].mPrng.SetSeed(mPrng.get());

            mGens[i].mChl = mChl.fork();
            mGens[i].mChl.setExecutor(*mThreadPool);

            mGens[i].mTask = mGens[i].start()
                | macoro::make_eager();
        }


        pushIdxs.resize(mNumConcurrent);
        for (i = 0;
            i < std::min<u64>(mReservoirSize, mNumChunks);
            ++i)
        {

            chunk.mIdx = i;
            getBaseOts(chunk);
            LOG("control: push chunk " + std::to_string(i));

            pushIdxs[i % mNumConcurrent] = i;
            //pendingChunks.push_back(std::move(chunk));

            MC_AWAIT(mGens[i % mNumConcurrent].mInQueue->push(std::move(chunk)));
        }


        popIdx = 0;
        while (true)
        {
            MC_AWAIT_SET(cmd, mControlQueue->pop());

            if (cmd.mOp.index() == cmd.mOp.index_of<Command::ChunkComplete>())
            {

                i = cmd.mOp.get<Command::ChunkComplete>().mChunk.mIdx;
                LOG("control: ChunkComplete " + std::to_string(i));

                //assert((mChunks.size() == 0 && pushIdx == 0) || mChunks.back().mIdx + 1 == pushIdx);
                if (popIdx == i && getEvent)
                {
                    ++popIdx;
                    mCurChunk = std::move(cmd.mOp.get<Command::ChunkComplete>().mChunk);
                    getEvent->set();
                    getEvent = nullptr;
                }
                else 
                    mChunks.emplace(i, std::move(cmd.mOp.get<Command::ChunkComplete>().mChunk));


                pushIdxs[i % mNumConcurrent] += mNumConcurrent;
                i = pushIdxs[i % mNumConcurrent];
                //A// std::cout << "chunk complete " << cmd.mOp.get<Command::ChunkComplete>().mChunk.mIdx << std::endl;

                if (i < mNumChunks)
                {
                    chunk.mIdx = i;
                    getBaseOts(chunk);
                    //A//  std::cout << "\n\npush chunk " << i << std::endl;
                    LOG("control: push chunk " + std::to_string(i));
                    MC_AWAIT(mGens[i % mNumConcurrent].mInQueue->push(std::move(chunk)));

                }
            }
            else if (cmd.mOp.index() == cmd.mOp.index_of<Command::Stop>())
            {
                LOG("control: stop request");
                mStopRequested = true;
                for (i = 0; i < mNumConcurrent; ++i)
                {
                    chunk.mIdx = i;
                    MC_AWAIT(mGens[i].mInQueue->push(std::move(chunk)));
                    LOG("control: gen stop sent " + std::to_string(i));

                }
            }
            else if (cmd.mOp.index() == cmd.mOp.index_of<Command::GenStopped>())
            {
                //A// std::cout << "gen " << cmd.mOp.get<Command::GenStopped>().mIdx << " stopped" << std::endl;
                LOG("control: gen stopped " + std::to_string(cmd.mOp.get<Command::GenStopped>().mIdx));

                MC_AWAIT(mGens[cmd.mOp.get<Command::GenStopped>().mIdx].mTask);

                if (--numTasks == 0)
                {
                    //A// std::cout << "control stopped" << std::endl;
                    LOG("control: stopped ");
                    MC_RETURN_VOID();
                }
            }
            else if (cmd.mOp.index() == cmd.mOp.index_of<Command::GetChunk>())
            {
                LOG("control: get ");
                assert(getEvent == nullptr);
                if (popIdx == mNumChunks)
                {
                    mCurChunk = {};
                    mCurChunk.mIdx = ~0ull;
                    cmd.mOp.get<Command::GetChunk>().mEvent->set();
                }
                else if (mChunks.find(popIdx) != mChunks.end())
                {
                    mCurChunk = std::move(mChunks[popIdx]);
                    mChunks.erase(mChunks.find(popIdx));
                    assert(mCurChunk.mIdx == popIdx);
                    ++popIdx;

                    //A// std::cout << "control get " << mCurChunk.mIdx << std::endl;
                    cmd.mOp.get<Command::GetChunk>().mEvent->set();
                }
                else
                {
                    //A// std::cout << "control get pending " << popIdx << std::endl;
                    getEvent = cmd.mOp.get<Command::GetChunk>().mEvent;
                }
            }
            else if (cmd.mOp.index() == cmd.mOp.index_of<Command::BaseOt>())
            {

            }
            else
            {
                throw RTE_LOC;
            }
        }

        MC_END();
    }

    void OleGenerator::getBaseOts(Chunk& chunk)
    {
        if (mRole == Role::Sender)
        {
            chunk.mBaseSend.resize(mBaseSize);
            for (u64 j = 0; j < mBaseSize; ++j)
            {
                chunk.mBaseSend[j][0] = oc::block(123 * j, 23423 * j);
                chunk.mBaseSend[j][1] = oc::block(123 * j, 23423 * j + 324);
            }
        }
        else
        {
            chunk.mBaseChoice.resize(mBaseSize);
            chunk.mBaseRecv.resize(mBaseSize);
            for (u64 j = 0; j < mBaseSize; ++j)
            {
                chunk.mBaseChoice[j] = j & 1;
                chunk.mBaseRecv[j] = oc::block(123 * j, 23423 * j + (324 * (j & 1)));
            }
        }
    }


    void OleGenerator::init(Role role, macoro::thread_pool& threadPool, coproto::Socket chl, oc::PRNG& prng, u64 totalSize, u64 reservoirSize, u64 numConcurrent, u64 chunkSize)
    {
        if (!numConcurrent)
            throw std::runtime_error("OleGenerator::numConcurrent must be non-zero");

        mRole = role;
        mThreadPool = &threadPool;
        mChl = chl.fork();
        mChl.setExecutor(threadPool);
        mPrng.SetSeed(prng.get());
        mCurSize = 0;
        mChunkSize = oc::roundUpTo(1ull<<oc::log2ceil(chunkSize), 128);
        mReservoirSize = oc::divCeil(reservoirSize, mChunkSize);
        mNumConcurrent = numConcurrent;
        mNumChunks = totalSize ? oc::divCeil(totalSize, mChunkSize) : ~0ull;
        mControlQueue.reset(new macoro::mpsc::channel<Command>(1024));

        if(!mFakeGen)
            mCtrl = control() | macoro::make_eager();
    }

    void OleGenerator::Gen::compressSender(span<std::array<oc::block, 2>> sendMsg, span<oc::block> add, span<oc::block> mult)
    {

        auto bIter16 = (u16*)add.data();
        auto aIter16 = (u16*)mult.data();

        if (add.size() * 128 != sendMsg.size())
            throw RTE_LOC;
        if (mult.size() * 128 != sendMsg.size())
            throw RTE_LOC;

        auto shuffle = std::array<block, 16>{};
        memset(shuffle.data(), 1 << 7, sizeof(*shuffle.data()) * shuffle.size());
        for (u64 i = 0; i < 16; ++i)
            shuffle[i].set<u8>(i, 0);

        for (u64 i = 0; i < sendMsg.size(); i += 16)
        {
            block a00 = _mm_shuffle_epi8(sendMsg[i + 0][0], shuffle[0]);
            block a01 = _mm_shuffle_epi8(sendMsg[i + 1][0], shuffle[1]);
            block a02 = _mm_shuffle_epi8(sendMsg[i + 2][0], shuffle[2]);
            block a03 = _mm_shuffle_epi8(sendMsg[i + 3][0], shuffle[3]);
            block a04 = _mm_shuffle_epi8(sendMsg[i + 4][0], shuffle[4]);
            block a05 = _mm_shuffle_epi8(sendMsg[i + 5][0], shuffle[5]);
            block a06 = _mm_shuffle_epi8(sendMsg[i + 6][0], shuffle[6]);
            block a07 = _mm_shuffle_epi8(sendMsg[i + 7][0], shuffle[7]);
            block a08 = _mm_shuffle_epi8(sendMsg[i + 8][0], shuffle[8]);
            block a09 = _mm_shuffle_epi8(sendMsg[i + 9][0], shuffle[9]);
            block a10 = _mm_shuffle_epi8(sendMsg[i + 10][0], shuffle[10]);
            block a11 = _mm_shuffle_epi8(sendMsg[i + 11][0], shuffle[11]);
            block a12 = _mm_shuffle_epi8(sendMsg[i + 12][0], shuffle[12]);
            block a13 = _mm_shuffle_epi8(sendMsg[i + 13][0], shuffle[13]);
            block a14 = _mm_shuffle_epi8(sendMsg[i + 14][0], shuffle[14]);
            block a15 = _mm_shuffle_epi8(sendMsg[i + 15][0], shuffle[15]);

            block b00 = _mm_shuffle_epi8(sendMsg[i + 0][1], shuffle[0]);
            block b01 = _mm_shuffle_epi8(sendMsg[i + 1][1], shuffle[1]);
            block b02 = _mm_shuffle_epi8(sendMsg[i + 2][1], shuffle[2]);
            block b03 = _mm_shuffle_epi8(sendMsg[i + 3][1], shuffle[3]);
            block b04 = _mm_shuffle_epi8(sendMsg[i + 4][1], shuffle[4]);
            block b05 = _mm_shuffle_epi8(sendMsg[i + 5][1], shuffle[5]);
            block b06 = _mm_shuffle_epi8(sendMsg[i + 6][1], shuffle[6]);
            block b07 = _mm_shuffle_epi8(sendMsg[i + 7][1], shuffle[7]);
            block b08 = _mm_shuffle_epi8(sendMsg[i + 8][1], shuffle[8]);
            block b09 = _mm_shuffle_epi8(sendMsg[i + 9][1], shuffle[9]);
            block b10 = _mm_shuffle_epi8(sendMsg[i + 10][1], shuffle[10]);
            block b11 = _mm_shuffle_epi8(sendMsg[i + 11][1], shuffle[11]);
            block b12 = _mm_shuffle_epi8(sendMsg[i + 12][1], shuffle[12]);
            block b13 = _mm_shuffle_epi8(sendMsg[i + 13][1], shuffle[13]);
            block b14 = _mm_shuffle_epi8(sendMsg[i + 14][1], shuffle[14]);
            block b15 = _mm_shuffle_epi8(sendMsg[i + 15][1], shuffle[15]);

            a00 = a00 ^ a08;
            a01 = a01 ^ a09;
            a02 = a02 ^ a10;
            a03 = a03 ^ a11;
            a04 = a04 ^ a12;
            a05 = a05 ^ a13;
            a06 = a06 ^ a14;
            a07 = a07 ^ a15;

            b00 = b00 ^ b08;
            b01 = b01 ^ b09;
            b02 = b02 ^ b10;
            b03 = b03 ^ b11;
            b04 = b04 ^ b12;
            b05 = b05 ^ b13;
            b06 = b06 ^ b14;
            b07 = b07 ^ b15;

            a00 = a00 ^ a04;
            a01 = a01 ^ a05;
            a02 = a02 ^ a06;
            a03 = a03 ^ a07;

            b00 = b00 ^ b04;
            b01 = b01 ^ b05;
            b02 = b02 ^ b06;
            b03 = b03 ^ b07;

            a00 = a00 ^ a02;
            a01 = a01 ^ a03;

            b00 = b00 ^ b02;
            b01 = b01 ^ b03;

            a00 = a00 ^ a01;
            b00 = b00 ^ b01;

            a00 = _mm_slli_epi16(a00, 7);
            b00 = _mm_slli_epi16(b00, 7);

            u16 ap = _mm_movemask_epi8(a00);
            u16 bp = _mm_movemask_epi8(b00);

            assert(aIter16 < (u16*)(mult.data() + mult.size()));
            assert(bIter16 < (u16*)(add.data() + add.size()));

            *aIter16++ = ap ^ bp;
            *bIter16++ = ap;
        }
    }

    void OleGenerator::Gen::compressRecver(oc::BitVector& bv, span<oc::block> recvMsg, span<oc::block> add, span<oc::block> mult)
    {
        auto aIter16 = (u16*)add.data();
        auto bIter16 = (u16*)mult.data();

        if (bv.size() != recvMsg.size())
            throw RTE_LOC;
        if (add.size() * 128 != recvMsg.size())
            throw RTE_LOC;
        if (mult.size() * 128 != recvMsg.size())
            throw RTE_LOC;

        auto shuffle = std::array<block, 16>{};
        memset(shuffle.data(), 1 << 7, sizeof(*shuffle.data()) * shuffle.size());
        for (u64 i = 0; i < 16; ++i)
            shuffle[i].set<u8>(i, 0);

        memcpy(bIter16, bv.data(), bv.sizeBytes());

        for (u64 i = 0; i < recvMsg.size(); i += 16)
        {
            // _mm_shuffle_epi8(a, b): 
            //     FOR j := 0 to 15
            //         i: = j * 8
            //         IF b[i + 7] == 1
            //             dst[i + 7:i] : = 0
            //         ELSE
            //             index[3:0] : = b[i + 3:i]
            //             dst[i + 7:i] : = a[index * 8 + 7:index * 8]
            //         FI
            //     ENDFOR

            // _mm_sll_epi16 : shifts 16 bit works left
            // _mm_movemask_epi8: packs together the MSG

            block a00 = _mm_shuffle_epi8(recvMsg[i + 0], shuffle[0]);
            block a01 = _mm_shuffle_epi8(recvMsg[i + 1], shuffle[1]);
            block a02 = _mm_shuffle_epi8(recvMsg[i + 2], shuffle[2]);
            block a03 = _mm_shuffle_epi8(recvMsg[i + 3], shuffle[3]);
            block a04 = _mm_shuffle_epi8(recvMsg[i + 4], shuffle[4]);
            block a05 = _mm_shuffle_epi8(recvMsg[i + 5], shuffle[5]);
            block a06 = _mm_shuffle_epi8(recvMsg[i + 6], shuffle[6]);
            block a07 = _mm_shuffle_epi8(recvMsg[i + 7], shuffle[7]);
            block a08 = _mm_shuffle_epi8(recvMsg[i + 8], shuffle[8]);
            block a09 = _mm_shuffle_epi8(recvMsg[i + 9], shuffle[9]);
            block a10 = _mm_shuffle_epi8(recvMsg[i + 10], shuffle[10]);
            block a11 = _mm_shuffle_epi8(recvMsg[i + 11], shuffle[11]);
            block a12 = _mm_shuffle_epi8(recvMsg[i + 12], shuffle[12]);
            block a13 = _mm_shuffle_epi8(recvMsg[i + 13], shuffle[13]);
            block a14 = _mm_shuffle_epi8(recvMsg[i + 14], shuffle[14]);
            block a15 = _mm_shuffle_epi8(recvMsg[i + 15], shuffle[15]);

            a00 = a00 ^ a08;
            a01 = a01 ^ a09;
            a02 = a02 ^ a10;
            a03 = a03 ^ a11;
            a04 = a04 ^ a12;
            a05 = a05 ^ a13;
            a06 = a06 ^ a14;
            a07 = a07 ^ a15;

            a00 = a00 ^ a04;
            a01 = a01 ^ a05;
            a02 = a02 ^ a06;
            a03 = a03 ^ a07;

            a00 = a00 ^ a02;
            a01 = a01 ^ a03;

            a00 = a00 ^ a01;

            a00 = _mm_slli_epi16(a00, 7);

            u16 ap = _mm_movemask_epi8(a00);

            *aIter16++ = ap;
        }
    }
}