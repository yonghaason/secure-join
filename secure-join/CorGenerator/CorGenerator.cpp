#include "CorGenerator.h"
#include "macoro/macros.h"
#include "BinOleBatch.h"
#include "OtBatch.h"
#include <map>

namespace secJoin
{

    std::shared_ptr<RequestState> CorGenerator::request(CorType t, u64 role, u64  n)
    {
        if (mGenState == nullptr)
            throw RTE_LOC; // call init first.

        if (mGenState->mDebug)
        {
            mGenState->mReqs.push_back({ t, role, n });
        }
        auto r = std::make_shared<RequestState>(t, role, n, mGenState, mGenState->mReqIndex++);


        switch (r->mType)
        {
        case CorType::Ot:
            mGenState->mNumOt += n;
            break;
        case CorType::Ole:
            mGenState->mNumOle += n;
            break;
        default:
            std::terminate();
        }

        for (u64 j = 0;j < r->mSize;)
        {
            std::shared_ptr<Batch>& batch = [&]() -> std::shared_ptr<Batch>&
                {
                    switch (r->mType)
                    {
                    case CorType::Ot:
                        return mGenState->mOtBatch[r->mSender];
                    case CorType::Ole:
                        return mGenState->mOleBatch[r->mSender];
                    default:
                        std::terminate();
                    }
                }();

                if (batch == nullptr)
                {
                    auto ss = mGenState->mSock.fork();
                    mGenState->mBatches.push_back(makeBatch(mGenState.get(), r->mSender, r->mType, std::move(ss), mGenState->mPrng.fork()));
                    mGenState->mBatches.back()->mIndex = mGenState->mBatches.size() - 1;
                    batch = mGenState->mBatches.back();
                }

                auto begin = batch->mSize;
                auto remReq = r->mSize - j;
                auto remAvb = mGenState->mBatchSize - begin;
                auto size = oc::roundUpTo(std::min<u64>(remReq, remAvb), 128);
                assert(size <= remAvb);

                batch->mSize += size;
                r->addBatch(BatchSegment{ batch, begin, size });
                j += size;

                if (remAvb == size)
                    batch = nullptr;
        }

        return r;
    }

    struct Config
    {
        u32 size;
        u16 type;
        u16 role;
    };

    macoro::task<> GenState::start()
    {
        MC_BEGIN(macoro::task<>, this,
            This = this->shared_from_this(),
            i = u64{},
            j = u64{},
            r = u64{},
            s = u64{},
            sMsg = oc::AlignedUnVector<std::array<oc::block, 2>>{},
            rMsg = oc::AlignedUnVector<oc::block>{},
            sProto = macoro::task<>{},
            rProto = macoro::task<>{},
            sPrng = PRNG{},
            rPrng = PRNG{},
            socks = std::array<oc::Socket, 2>{},
            req = BaseRequest{},
            reqs = std::vector<BaseRequest>{},
            temp = std::vector<u8>{},
            res = macoro::result<void>{},
            reqChecks = std::map<CorType, oc::RandomOracle>{},
            theirReq = std::vector<ReqInfo>{},
            threadState = std::vector<BatchThreadState>{}
        );

        setTimePoint("GenState::start");
        mOtBatch = {};
        mOleBatch = {};

        // make base OT requests
        reqs.reserve(mBatches.size());
        for (i = 0; i < mBatches.size();++i)
        {
            auto& batch = *mBatches[i];
            if (!batch.mSize)
                std::terminate();
            reqs.push_back(batch.getBaseRequest());
        }

        if (mDebug)
        {

            for (i = 0; i < mReqs.size(); ++i)
            {
                MC_AWAIT(mSock.send(coproto::copy(mReqs)));
                MC_AWAIT(mSock.recvResize(theirReq));
                for (i = 0; i < theirReq.size(); ++i)
                    theirReq[i].mRole ^= 1;
            }
            if (mReqs != theirReq)
            {
                std::lock_guard<std::mutex> lock(oc::gIoStreamMtx);
                std::cout << "party " << mPartyIdx << std::endl;
                for (i = 0; i < mReqs.size();++i)
                {
                    bool failed = false;
                    ReqInfo exp = { CorType::Ole,0,0 };
                    if (theirReq.size() > i)
                    {
                        exp = theirReq[i];
                        if (exp != mReqs[i])
                            failed = true;
                    }
                    else
                        failed = true;

                    if (failed)
                    {
                        std::cout << oc::Color::Red;
                    }

                    auto t = mReqs[i].mType;
                    auto r = mReqs[i].mRole;
                    auto s = mReqs[i].mSize;

                    std::cout << "request " << i << ": " << t << "." << r << " " << s;

                    if (failed)
                    {
                        if (exp.mSize)
                        {
                            std::cout << " ~  theirs " << theirReq[i].mType << "." << theirReq[i].mRole << " " << theirReq[i].mSize;
                        }
                        std::cout << oc::Color::Default;
                    }

                    std::cout << std::endl;
                }
                throw RTE_LOC;
            }
            setTimePoint("GenState::debug");

        }

        req = BaseRequest(reqs);

        socks[0] = mSock;
        socks[1] = mSock.fork();


        if (req.mSendSize)
        {
            sMsg.resize(req.mSendSize);
            sPrng = mPrng.fork();
            sMsg.resize(req.mSendSize);
            sProto = mSendBase.send(sMsg, sPrng, socks[mPartyIdx]);
        }

        // perform recv base OTs
        if (req.mChoice.size())
        {
            rPrng = mPrng.fork();
            rMsg.resize(req.mChoice.size());
            rProto = mRecvBase.receive(req.mChoice, rMsg, mPrng, socks[1 ^ mPartyIdx]);
        }

        // perform the protocol (in parallel if both are active).
        if (req.mSendSize && req.mChoice.size())
        {
            MC_AWAIT(macoro::when_all_ready(
                std::move(rProto), std::move(sProto)
            ));
        }
        else if (req.mSendSize)
        {
            MC_AWAIT(sProto);
        }
        else if (req.mChoice.size())
        {
            MC_AWAIT(rProto);
        }

        setTimePoint("GenState::base");

        threadState.resize(mNumConcurrent);



        for (i = 0, r = 0, s = 0, j = -mNumConcurrent + 1; j != mBatches.size(); ++i, ++j)
        {
            if (i < mBatches.size())
            {
                MC_AWAIT(mBatches[i]->mStart);

                if (mBatches[i]->mAbort == false)
                {

                    auto& batch = *mBatches[i];
                    auto rBase = rMsg.subspan(r, reqs[i].mChoice.size());
                    r += reqs[i].mChoice.size();

                    auto sBase = sMsg.subspan(s, reqs[i].mSendSize);
                    s += reqs[i].mSendSize;

                    batch.setBase(rBase, sBase);

                    setTimePoint("GenState::batch.begin " + std::to_string(i));

                    if (mPool)
                    {
                        // launch the next batch
                        threadState[i % mNumConcurrent].mTask =
                            mBatches[i]->getTask(threadState[i % mNumConcurrent]) |
                            macoro::start_on(*mPool);
                    }
                    else
                    {
                        // launch the next batch
                        threadState[i % mNumConcurrent].mTask =
                            mBatches[i]->getTask(threadState[i % mNumConcurrent]) |
                            macoro::make_eager();
                    }
                }
            }


            // join the previous batch
            if (j < mBatches.size())
            {
                if(threadState[j % mNumConcurrent].mTask.handle())
                    MC_AWAIT(threadState[j % mNumConcurrent].mTask);

                setTimePoint("GenState::batch.end " + std::to_string(j));
                mBatches[j] = {};
            }
        }

        mBatches = {};
        setTimePoint("GenState::done ");

        MC_END();
    }

    void GenState::set(SendBase& b) { auto v = b.get(); mRecvBase.setBaseOts(v); }
    void GenState::set(RecvBase& b) { auto v = b.get(); mSendBase.setBaseOts(v, b.mChoice); }

}