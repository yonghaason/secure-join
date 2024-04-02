#pragma once
#include "secure-join/Util/ArrGate.h"
#include "secure-join/Util/Matrix.h"
#include "secure-join/GMW/Gmw.h"
#include "secure-join/Defines.h"
#include "secure-join/Join/Table.h"
#include "cryptoTools/Circuit/BetaLibrary.h"
#include "cryptoTools/Circuit/Gate.h"
#include "cryptoTools/Common/BitVector.h"
#include "secure-join/Defines.h"
#include "secure-join/Perm/ComposedPerm.h"
#include "secure-join/Util/Util.h"
#include "secure-join/Join/OmJoin.h"
#include "RemDummies.h"

namespace secJoin
{
    using SharedTable = Table;
	using SharedColumn = Column;
    using BetaLibrary = oc::BetaLibrary;
    using BitVector = oc::BitVector;
    using Optimized = BetaLibrary::Optimized;
    using IntType = BetaLibrary::IntType;

    enum WhType {Col, Number, String, InterOut, InterInt};
    struct WhBundle
    {
        BetaBundle mBundle;
        // BitVector is used to place the constant with the minimun bits required.
        BitVector mVal;
        WhType mType;

        WhBundle(BetaBundle& a, WhType c)
            : mBundle(a), mType(c) {}

        WhBundle(BetaBundle& a, BitVector& b, WhType c)
            : mBundle(a), mVal(b), mType(c) {}

        WhBundle(const WhBundle&) = default;
        WhBundle(WhBundle&&) = default;
    };
    struct Where{

        bool mInsecureMockSubroutines = false;
        bool mInsecurePrint = false;
        std::vector<WhBundle> mWhBundle;
        std::vector<BinMatrix> mGmwIn;
        Gmw mWhGmw;
        Gmw mUpdateActiveFlagGmw;
        Optimized mOp = Optimized::Depth;
        bool mRemDummiesFlag;
        RemDummies mRemDummies;


        void init(
            SharedTable& st,
            const std::vector<ArrGate>& gates,
            const std::vector<std::string>& literals,
            const std::vector<std::string>& literalsType,
            const u64 totalCol,
            const std::unordered_map<u64, u64>& map,
            CorGenerator& ole,
            bool remDummiesFlag = false);

        macoro::task<> where(
            SharedTable& st,
            SharedTable& out,
            coproto::Socket& sock,
            PRNG& prng);

        oc::BetaCircuit genWhCir(
            SharedTable& st, 
            const std::vector<ArrGate>& gates, 
            const std::vector<std::string>& literals,
            const std::vector<std::string>& literalsType,
            const u64 totalCol,
            const std::unordered_map<u64, u64>& map);


        void genWhBundle(
            const std::vector<std::string>& literals, 
            const std::vector<std::string>& literalsType, 
            const u64 totalCol, SharedTable& st, 
            const std::unordered_map<u64, u64>& map);

        u64 getInputColSize(
            SharedTable& st, 
            u64 gateInputIndex,
            u64 totalCol,
            const std::unordered_map<u64, u64>& map);
        
        void addToGmwInput(
            SharedTable& st, 
            u64 gateInputIndex,
            const std::unordered_map<u64, u64>& map, 
            WhType type);

        oc::BetaCircuit updateActiveFlagCir(
            const u64 aSize, 
            const u64 bSize, 
            const u64 cSize);
            
        macoro::task<> updateActiveFlag(
            std::vector<u8>& actFlag,
            BinMatrix& choice,
            coproto::Socket& sock);

        void addInputBundle(
            oc::BetaCircuit& cd, 
            SharedTable& st,
            const u64 gateInputIndex, 
            const std::unordered_map<u64, u64>& map);

        u64 getMapVal(
            const std::unordered_map<u64, u64>& map,
            u64 tag);

        void ArrTypeLessThanCir(
            const u64 inIndex1, 
            const u64 inIndex2, 
            oc::BetaCircuit& cd, 
            BetaBundle &c, 
            const bool lastOp);

        void ArrTypeAddCir(
            const u64 inIndex1, 
            const u64 inIndex2, 
            oc::BetaCircuit& cd, 
            BetaBundle &c, 
            const bool lastOp);

        void ArrTypeEqualCir(
            const u64 inIndex1, 
            const u64 inIndex2, 
            oc::BetaCircuit& cd, 
            BetaBundle &c, 
            const bool lastOp);

        void ArrTypeEqualInputs(
            const u64 inIndex1, 
            const u64 inIndex2, 
            SharedTable& st,
            oc::BetaCircuit& cd, 
            const std::unordered_map<u64, u64>& map);
        
        void signExtend(
            const u64 smallerSizeIndex, 
            const u64 biggerSize,
            const u64 biggerSizeIndex,
            SharedTable& st, 
            oc::BetaCircuit& cd,
            const std::unordered_map<u64, u64>& map);

        macoro::task<> getOutput(
            SharedTable& in, 
            SharedTable& out, 
            CorGenerator& ole,
            coproto::Socket& sock, 
            oc::PRNG& prng, 
            bool securePerm, 
            Perm& randPerm);


        void signExtend(BitVector& aa, const u64 size, const WhType type);
        void signExtend(BinMatrix& in, const u64 size, const TypeID type);
        void signExtend(BetaBundle& aa, const u64 size, const WhType type);
        void extendBetaBundle(BetaBundle& aa, const u64 size);
        void extendBitVector(BitVector& aa, const u8 bit, const u64 size);
    };
}


