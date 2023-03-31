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
#include "secure-join/GMW/SilentTripleGen.h"
#include "macoro/manual_reset_event.h"
#include <map>

namespace secJoin
{

    struct SharedTriple
    {
        span<oc::block> mMult, mAdd;


        u64 size() const
        {
            return mMult.size() * 128;
        }

        std::function<void()> mCallback;

        void free()
        {
            if (mCallback)
                mCallback();
            mCallback = nullptr;
        }

        ~SharedTriple()
        {
            free();
        }
    };

    class OleGenerator : public oc::TimerAdapter
    {
    public:
        enum class Role
        {
            Sender,
            Receiver
        };
        struct Chunk
        {
            std::vector<std::array<oc::block, 2>> mBaseSend;
            std::vector<oc::block> mBaseRecv;
            oc::BitVector mBaseChoice;
            u64 mIdx;

            oc::AlignedUnVector<oc::block> mMult, mAdd;
        };


        struct Command
        {
            struct Stop {};
            struct ChunkComplete {
                Chunk mChunk;
            };
            struct GenStopped
            {
                u64 mIdx = ~0ull;
            };
            struct GetChunk
            {
                macoro::async_manual_reset_event* mEvent;
            };
            macoro::variant<Stop, ChunkComplete, GenStopped, GetChunk> mOp;
        };

        u64 mCurSize = 0;
        u64 mNumChunks = 0;
        u64 mChunkSize = 0;
        u64 mNumConcurrent = 0;
        u64 mReservoirSize = 0;
        u64 mBaseSize = 0;
        bool mStopRequested = false;
        Role mRole = Role::Sender;
        std::unique_ptr<macoro::mpsc::channel<Command>> mControlQueue;
        std::map<u64, Chunk> mChunks;
        Chunk mCurChunk;
        u64 mRemChunk = 0;

        std::vector<std::array<oc::block, 2>> mBaseSendOts;
        std::vector<oc::block> mBaseRecvOts;
        macoro::thread_pool* mThreadPool = nullptr;
        coproto::Socket mChl;

        macoro::eager_task<> mCtrl;
        oc::PRNG mPrng;

        struct Gen
        {
            OleGenerator* mParent;
            coproto::Socket mChl;
            std::unique_ptr<oc::SilentOtExtSender> mSender;
            std::unique_ptr<oc::SilentOtExtReceiver> mRecver;
            macoro::eager_task<> mTask;
            oc::PRNG mPrng;
            u64 mIdx = 0;

            std::unique_ptr<macoro::spsc::channel<Chunk>> mInQueue;


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
        std::vector<Gen> mGens;


        bool isStopRequested()
        {
            return false;
        }

        macoro::task<> stop();

        macoro::task<> control();

        void init(
            Role role,
            macoro::thread_pool& threadPool,
            coproto::Socket chl,
            oc::PRNG& prng,
            u64 totalSize,
            u64 reservoirSize,
            u64 numConcurrent,
            u64 chunkSize = 1ull << 18);

        void getBaseOts(Chunk& chunk);


        macoro::async_manual_reset_event mGetEvent;
        macoro::task<> get(SharedTriple& triples, u64 n)
        {
            MC_BEGIN(macoro::task<>, this, &triples, n
            );

            if (mRemChunk == 0)
            {
                mGetEvent.reset();

                MC_AWAIT(mControlQueue->push({ Command::GetChunk{&mGetEvent} }));
                MC_AWAIT(mGetEvent);
                mRemChunk = mCurChunk.mAdd.size();
            }

            if (mRemChunk)
            {
                auto m = mChunkSize / 128;
                n = std::min<u64>(n, mRemChunk);
                triples.mAdd = mCurChunk.mAdd.subspan(m - mRemChunk, n);
                triples.mMult = mCurChunk.mMult.subspan(m - mRemChunk, n);
                mRemChunk -= n;
            }
            else
                throw std::runtime_error("OleGenerator, no triples left. " LOCATION);
            MC_END();
        }
        macoro::task<> get(span<oc::block> mult, span<oc::block> add, u64 n);
    };



}