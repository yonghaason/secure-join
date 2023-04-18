#pragma once
// © 2022 Visa.
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
// 
// The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
// 
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.


#include "secure-join/Defines.h"

#include <vector>
#include <libOTe/TwoChooseOne/Silent/SilentOtExtSender.h>
#include <libOTe/TwoChooseOne/Silent/SilentOtExtReceiver.h>
#include "macoro/thread_pool.h"
#include "macoro/channel_spsc.h"
#include "macoro/manual_reset_event.h"
#include <map>

namespace secJoin
{
    class OleGenerator;

    struct OtSend
    {
        oc::AlignedUnVector<std::array<oc::block, 2>> mMsg;
        //oc::AlignedUnVector<std::array<oc::block, 2>> mMem;

        u64 size() const
        {
            return mMsg.size();
        }
    };

    struct OtRecv
    {
        oc::BitVector mChoice;
        oc::AlignedUnVector<oc::block> mMsg;
        //oc::AlignedUnVector<oc::block> mMem;

        u64 size() const
        {
            return mMsg.size();
        }
    };

    struct BinOle
    {
        oc::AlignedUnVector<oc::block> mMult, mAdd;
        //oc::AlignedUnVector<oc::block> mMemAdd, mMemMult;

        u64 size() const
        {
            return mMult.size() * 128;
        }
    };

    struct ArithTriple {

        u64 mBitCount;
        //oc::AlignedUnVector<oc::block> mMemA, mMemB, mMemC;
        oc::AlignedUnVector<oc::block> mA, mB, mC;
    };


    struct CorRequest
    {

        template< typename T>
        struct Req : T
        {
            std::shared_ptr<macoro::mpsc::channel<std::pair<u64, T>>> mQueue;
        };
        using OtRecvReq = Req<OtRecv>;
        using OtSendReq = Req<OtSend>;
        using BinOleReq = Req<BinOle>;
        using ArithTripleReq = Req<ArithTriple>;

        CorRequest()
            : mOp(BinOleReq{})
        {}

        CorRequest(oc::block sid, u64 n, u64 idx, macoro::variant<BinOleReq, OtRecvReq, OtSendReq, ArithTripleReq> op)
            : mSessionID(sid)
            , mN(n)
            , mSequence(idx)
            , mOp(std::move(op))
        {}

        oc::block mSessionID;
        u64 mN = 0;
        u64 mSequence = -1;
        macoro::variant<BinOleReq, OtRecvReq, OtSendReq, ArithTripleReq> mOp;

        u64 sizeBytes()
        {
            return 1 + sizeof(oc::block) + sizeof(u64) + sizeof(u64) + 1;
        }

        void toBytes(span<u8> bytes)
        {
            if (bytes.size() < sizeBytes())
                throw RTE_LOC;
            bytes[0] = mOp.index(); bytes = bytes.subspan(1);
            memcpy(&bytes[0], &mSessionID, sizeof(oc::block)); bytes = bytes.subspan(sizeof(oc::block));
            memcpy(&bytes[0], &mN, sizeof(u64)); bytes = bytes.subspan(sizeof(u64));
            memcpy(&bytes[0], &mSequence, sizeof(u64)); bytes = bytes.subspan(sizeof(u64));
            if (mOp.index() == 3)
                bytes[0] = mOp.get<3>().mBitCount;
            else
                bytes[0] = 0;
        }


        void fromBytes(span<u8> bytes)
        {
            if (bytes.size() < sizeBytes())
                throw RTE_LOC;

            auto idx = mOp.index(); bytes = bytes.subspan(1);
            memcpy(&mSessionID, &bytes[0], sizeof(oc::block)); bytes = bytes.subspan(sizeof(oc::block));
            memcpy(&mN, &bytes[0], sizeof(u64)); bytes = bytes.subspan(sizeof(u64));
            memcpy(&mSequence, &bytes[0], sizeof(u64)); bytes = bytes.subspan(sizeof(u64));

            switch (idx)
            {
            case 0:
                mOp.emplace<0>();
                break;
            case 1:
                mOp.emplace<1>();
                break;
            case 2:
                mOp.emplace<2>();
                break;
            case 3:
                mOp.emplace<3>();
                mOp.get<3>().mBitCount = bytes[0];
                break;
            default:
                throw RTE_LOC;
                break;
            }
        }
    };
    template<typename T>
    struct Request
    {
        Request() = default;
        Request(const Request&) = delete;
        Request(Request&& o)
            : mSessionID(std::exchange(o.mSessionID, oc::ZeroBlock))
            , mSize(std::exchange(o.mSize, 0))
            , mIdx(std::exchange(o.mIdx, 0))
            , mCorrelations(std::move(o.mCorrelations))
            , mRemReq(std::move(o.mRemReq))
            , mGen(std::exchange(o.mGen, nullptr))
            , mChl(std::move(o.mChl))
        {}

        Request(oc::block sessionID, u64 size, u64 numChunks, std::vector<CorRequest>&& rem, OleGenerator* g, std::shared_ptr<macoro::mpsc::channel<std::pair<u64, T>>> chl)
            : mSessionID(sessionID)
            , mSize(size)
            , mCorrelations(numChunks)
            , mRemReq(std::move(rem))
            , mGen(g)
            , mChl(std::move(chl))
        {}

        Request& operator=(Request&& o)
        {
            mSessionID = std::exchange(o.mSessionID, oc::ZeroBlock);
            mSize = std::exchange(o.mSize, 0);
            mCorrelations = std::move(o.mCorrelations);
            mRemReq = std::move(o.mRemReq);
            mGen = std::exchange(o.mGen, nullptr);
            mChl = std::move(o.mChl);
            return *this;
        }

        using value_type = T;
        oc::block mSessionID = oc::ZeroBlock;
        u64 mSize = 0, mIdx = 0;
        std::vector<macoro::optional<T>> mCorrelations;
        std::vector<CorRequest> mRemReq;
        OleGenerator* mGen = nullptr;
        std::shared_ptr<macoro::mpsc::channel<std::pair<u64, value_type>>> mChl;

        macoro::task<T> get();
    };

    class OleGenerator : public oc::TimerAdapter
    {
    public:
        enum class Role
        {
            Sender,
            Receiver
        };

        //struct Chunk 
        //{
        //    u64 mN;
        //    u64 mIdx;
        //    oc::block mSessionID;

        //    struct BinOle : secJoin::BinOle, CorRequest::BinOleReq {};
        //    struct OtRecv : secJoin::OtRecv, CorRequest::OtRecvReq {};
        //    struct OtSend : secJoin::OtSend, CorRequest::OtSendReq {};
        //    struct ArithTriple : secJoin::ArithTriple, CorRequest::ArithTripleReq {};
        //    macoro::variant<BinOle, OtRecv, OtSend, ArithTriple> mOp;
        //};


        struct Command
        {
            struct Stop {};
            struct ChunkComplete {
                u64 mWorkerId;
                CorRequest mChunk;
            };
            struct GenStopped
            {
                u64 mIdx = ~0ull;
            };
            macoro::variant<Stop, ChunkComplete, GenStopped, CorRequest> mOp;
        };

        struct Gen
        {
            OleGenerator* mParent;
            coproto::Socket mChl;
            std::unique_ptr<oc::SilentOtExtSender> mSender;
            std::unique_ptr<oc::SilentOtExtReceiver> mRecver;
            macoro::eager_task<> mTask;
            oc::PRNG mPrng;
            u64 mIdx = 0;

            oc::Log mLog;

            void log(std::string m)
            {
                std::stringstream ss;
                ss << "[" << std::this_thread::get_id() << "] ";
                ss << m;
                mLog.push(ss.str());
                mParent->log("gen " + std::to_string(mIdx) + ": " + m);
            }

            std::unique_ptr<macoro::spsc::channel<CorRequest>> mInQueue;


            void compressSender(
                span<oc::block> sendMsg, oc::block delta,
                span<oc::block> add,
                span<oc::block> mult
            );

            void compressRecver(
                span<oc::block> recvMsg,
                span<oc::block> add,
                span<oc::block> mult
            );


            void compressSender(
                span<std::array<oc::block, 2>> sendMsg,
                span<oc::block> add,
                span<oc::block> mult
            );

            void compressRecver(
                oc::BitVector& bv,
                span<oc::block> recvMsg,
                span<oc::block> add,
                span<oc::block> mult
            );

            macoro::task<> start();
        };

        bool mFakeGen = false;
        oc::block mCurSessionID = oc::ZeroBlock;
        //u64 mCurSize = 0;
        //u64 mNumChunks = 0;
        u64 mChunkSize = 0;
        u64 mNumConcurrent = 0;
        //u64 mReservoirSize = 0;
        u64 mBaseSize = 0;
        bool mStopRequested = false;
        Role mRole = Role::Sender;
        std::unique_ptr<macoro::mpsc::channel<Command>> mControlQueue;
        //std::map<u64, Chunk> mChunks;
        //Chunk mCurChunk;
        //u64 mRemChunk = 0;

        std::vector<std::array<oc::block, 2>> mBaseSendOts;
        std::vector<oc::block> mBaseRecvOts;
        macoro::thread_pool* mThreadPool = nullptr;
        coproto::Socket mChl;

        macoro::eager_task<> mBaseTask;

        macoro::eager_task<> mCtrl;
        oc::PRNG mPrng;
        oc::Log mLog;

        std::vector<Gen> mGens;
        macoro::async_manual_reset_event mGetEvent;


        bool isStopRequested()
        {
            return false;
        }

        macoro::task<> stop();

        macoro::task<> control();
        //macoro::task<> baseOtProvider(oc::block seed);


        void init(
            Role role,
            macoro::thread_pool& threadPool,
            coproto::Socket chl,
            oc::PRNG& prng)
        {
            init(role, threadPool, std::move(chl), prng, 1, 1 << 18);
        }

        void init(
            Role role,
            macoro::thread_pool& threadPool,
            coproto::Socket chl,
            oc::PRNG& prng,
            u64 numThreads,
            u64 chunkSize);



        void fakeInit(Role role)
        {
            mFakeGen = true;
            mRole = role;
            mThreadPool = nullptr;
            mPrng.SetSeed(oc::block((int)role, 132423));
            //mCurSize = 0;
            mChunkSize = 1 << 16;
            //mReservoirSize = oc::divCeil(1 << 20, mChunkSize);
            mNumConcurrent = 1;
            //mNumChunks = ~0ull;
        }

        //void getBaseOts(Chunk& chunk, CorRequest& ses);

        void fakeFill(BinOle& ole)
        {
            //oc::PRNG prng(oc::block(mCurSize++));

            for (u32 i = 0; i < ole.mAdd.size(); ++i)
            {
                oc::block m0 = std::array<u32, 4>{i, i, i, i};// prng.get();
                oc::block m1 = std::array<u32, 4>{i, i, i, i};//prng.get();
                oc::block a0 = std::array<u32, 4>{0, i, 0, i};//prng.get();
                auto a1 = std::array<u32, 4>{i, 0, i, 0};;// m0& m1^ a0;

                if (mRole == Role::Sender)
                {
                    ole.mMult[i] = m0;
                    ole.mAdd[i] = a0;
                }
                else
                {
                    ole.mMult[i] = m1;
                    ole.mAdd[i] = a1;
                }
            }
        }
        macoro::task<Request<BinOle>> binOleRequest(u64 numCorrelations, u64 reservoirSize = 0, oc::block sessionID = oc::ZeroBlock)
        {
            MC_BEGIN(macoro::task<Request<BinOle>>, this, numCorrelations, reservoirSize, sessionID,
                c = std::shared_ptr<macoro::mpsc::channel<std::pair<u64, BinOle>>>{},
                rem = std::vector<CorRequest>{},
                req = CorRequest{},
                cor = Request<BinOle>{},
                n = u64{}, m = u64{}, i = u64{});

            if (reservoirSize == 0)
                reservoirSize = numCorrelations;

            if (sessionID == oc::ZeroBlock)
            {
                sessionID = mCurSessionID;
                mCurSessionID += oc::block(2452345343234, 43253453452);
            }
            i = 0;
            n = 0;

            if (mFakeGen)
            {
                cor.mSessionID = sessionID;
                cor.mSize = numCorrelations;
                cor.mCorrelations.resize(oc::divCeil(numCorrelations, mChunkSize));

                for (u64 i = 0; i < cor.mCorrelations.size(); ++i)
                {
                    m = std::min<u64>(numCorrelations - n, mChunkSize);
                    m = 1ull << oc::log2ceil(m);
                    n += m;

                    cor.mCorrelations[i].emplace();
                    cor.mCorrelations[i]->mAdd.resize(m);
                    cor.mCorrelations[i]->mMult.resize(m);
                    fakeFill(*cor.mCorrelations[i]);
                }

                MC_RETURN(std::move(cor));
            }
            else
            {

                c.reset(new macoro::mpsc::channel<std::pair<u64, BinOle>>(1ull << oc::log2ceil(oc::divCeil(numCorrelations, mChunkSize))));
                while (n < numCorrelations)
                {
                    m = std::min<u64>(numCorrelations - n, mChunkSize);
                    m = 1ull << oc::log2ceil(m);

                    req = CorRequest{
                        sessionID ^ oc::block(i * 31212 ^ i,i),
                        m,
                        i++,
                        CorRequest::Req<BinOle>{
                            BinOle{},
                            c
                        }
                    };

                    if (n < reservoirSize)
                    {
                        MC_AWAIT(mControlQueue->push(OleGenerator::Command{ std::move(req) }));
                    }
                    else
                    {
                        rem.push_back(std::move(req));
                    }

                    n += m;
                }

                std::reverse(rem.begin(), rem.end());

                MC_RETURN((Request<BinOle>{
                    sessionID,
                        numCorrelations,
                        oc::divCeil(numCorrelations, mChunkSize),
                        std::move(rem),
                        this,
                        std::move(c)
                }));

            }
            MC_END();
        }
        macoro::task<Request<OtRecv>> otRecvRequest(u64 numCorrelations, u64 reservoirSize = 0, oc::block sessionID = oc::ZeroBlock);
        macoro::task<Request<OtSend>> otSendRequest(u64 numCorrelations, u64 reservoirSize = 0, oc::block sessionID = oc::ZeroBlock);
        macoro::task<Request<ArithTriple>> arithTripleRequest(u64 numCorrelations, u64 reservoirSize = 0, oc::block sessionID = oc::ZeroBlock);

        void log(std::string m)
        {
            std::stringstream ss;
            ss << "[" << std::this_thread::get_id() << "] ";
            ss << m;
            mLog.push(ss.str());
        }
    };

    template<typename T>
    macoro::task<T>  Request<T>::get()
    {

        if (mIdx >= mCorrelations.size())
            throw std::runtime_error("Out of correlations. " LOCATION);

        MC_BEGIN(macoro::task<T>, this,
            t = std::pair<u64, T>{},
            m = u64{});

        if (mIdx >= mCorrelations.size())
            throw std::runtime_error("Out of correlations. " LOCATION);

        while (!mCorrelations[mIdx])
        {
            MC_AWAIT_SET(t, mChl->pop());
            mCorrelations[t.first] = std::move(t.second);
            if (mRemReq.size())
            {
                MC_AWAIT(mGen->mControlQueue->push(OleGenerator::Command{ std::move(mRemReq.back()) }));
                mRemReq.pop_back();
            }
        }
        MC_RETURN(std::move(*mCorrelations[mIdx++]));
        MC_END();
    }

    //macoro::task<> get(BinOle& triples)
    //{
    //    MC_BEGIN(macoro::task<>, this, &triples
    //    );

    //    if (mRemChunk == 0)
    //    {
    //        mGetEvent.reset();
    //        if (mFakeGen)
    //        {
    //            mCurChunk.mAdd.resize(mChunkSize / 128);
    //            mCurChunk.mMult.resize(mChunkSize / 128);

    //            fakeFill(mCurChunk);
    //        }
    //        else
    //        {
    //            MC_AWAIT(mControlQueue->push({ Command::GetChunk{&mGetEvent} }));
    //            MC_AWAIT(mGetEvent);
    //        }

    //        mRemChunk = mCurChunk.mAdd.size();
    //    }

    //    if (mRemChunk)
    //    {
    //        auto m = mChunkSize / 128;
    //        auto n = mRemChunk;

    //        triples.mAdd = mCurChunk.mAdd.subspan(m - mRemChunk, n);
    //        triples.mMult = mCurChunk.mMult.subspan(m - mRemChunk, n);
    //        triples.mMemAdd = std::move(mCurChunk.mAdd);
    //        triples.mMemMult = std::move(mCurChunk.mMult);
    //        mRemChunk = 0;
    //    }
    //    else
    //        throw std::runtime_error("OleGenerator, no triples left. " LOCATION);
    //    MC_END();
    //}

}