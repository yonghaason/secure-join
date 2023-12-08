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

        // Remove this method once Peter fixes the Beta Bundle error
        void eq_build(BetaCircuit& cd, BetaBundle& a1, BetaBundle& a2,
		    BetaBundle& out);

        std::vector<WhBundle> mWhBundle;
        std::vector<BinMatrix> mGmwIn;
        // std::vector<BetaBundle> mTempWireBundle;
        Optimized mOp = Optimized::Size;
        macoro::task<> where(SharedTable& st, const std::vector<ArrGate>& gates, 
            const std::vector<std::string>& literals, const std::vector<std::string>& literalsType, 
            const u64 totalCol, SharedTable& out, const std::unordered_map<u64, u64>& map, 
            CorGenerator& ole, coproto::Socket& sock, const bool print);

        oc::BetaCircuit* genWhCir(SharedTable& st, const std::vector<ArrGate>& gates, 
            const std::vector<std::string>& literals, const std::vector<std::string>& literalsType,
            const u64 totalCol, const std::unordered_map<u64, u64>& map, const bool print);

        void genWhBundle(const std::vector<std::string>& literals, 
            const std::vector<std::string>& literalsType, const u64 totalCol, SharedTable& st, 
            const std::unordered_map<u64, u64>& map, const bool print);            

        u64 getInputColSize(SharedTable& st, u64 gateInputIndex, u64 totalCol,
            const std::unordered_map<u64, u64>& map);
        
        void addToGmwInput(SharedTable& st, u64 gateInputIndex,
            const std::unordered_map<u64, u64>& map, WhType type);
            
        macoro::task<> updateActiveFlag( std::vector<u8>& actFlag, BinMatrix& choice,
            CorGenerator& ole, coproto::Socket& sock);

        void addInputBundle(oc::BetaCircuit* cd, SharedTable& st,
            const u64 gateInputIndex, const std::unordered_map<u64, u64>& map);
        // void addOutputBundle(oc::BetaCircuit* cd, BetaBundle &c, const bool lastOp);

        u64 getMapVal(const std::unordered_map<u64, u64>& map, u64 tag);

        void ArrTypeLessThanCir(const u64 inIndex1, const u64 inIndex2, oc::BetaCircuit* cd, 
            BetaBundle &c, const bool lastOp);

        void ArrTypeAddCir(const u64 inIndex1, const u64 inIndex2, oc::BetaCircuit* cd, 
            BetaBundle &c, const bool lastOp);

        void ArrTypeEqualCir(const u64 inIndex1, const u64 inIndex2, oc::BetaCircuit* cd, 
            BetaBundle &c, const bool lastOp);

        void ArrTypeEqualInputs(const u64 inIndex1, const u64 inIndex2, SharedTable& st,
            oc::BetaCircuit* cd, const std::unordered_map<u64, u64>& map);
        

        void signExtend(const u64 smallerSizeIndex, const u64 biggerSize, const u64 biggerSizeIndex,
            SharedTable& st, oc::BetaCircuit* cd, const std::unordered_map<u64, u64>& map);

        void signExtend(BitVector& aa, const u64 size, const WhType type);
        void signExtend(BinMatrix& in, const u64 size, const TypeID type);
        void signExtend(BetaBundle& aa, const u64 size, const WhType type);
        void extendBetaBundle(BetaBundle& aa, const u64 size);
        void extendBitVector(BitVector& aa, const u8 bit, const u64 size);

    };
}


