#include "Where.h"

namespace secJoin {

    macoro::task<> Where::where(SharedTable& st,
        const std::vector<ArrGate>& gates, 
        const std::vector<std::string>& literals,
        const std::vector<std::string>& literalsType,
        const u64 totalCol,
        SharedTable& out,
        const std::unordered_map<u64, u64>& map,
        OleGenerator& ole,
        coproto::Socket& sock)
    {
        
        MC_BEGIN(macoro::task<>, this, &st, &gates, &literals, &literalsType, &out, &sock, 
            &map, totalCol, &ole,
            cd = oc::BetaCircuit{},
            gmw = Gmw{},
            rows = u64());

        cd = *genWhCircuit(st, gates, literals, literalsType, totalCol, map);
        rows = st[0].mCol.rows();
        gmw.init(rows, cd, ole);
        
        // Inputs to the protocol
        for(u64 i=0; i < mInputs.size(); i++)
            gmw.setInput(i, *mInputs[i]);

        MC_AWAIT(gmw.run(sock));

        // gmw.getOutput(0, temp);
        // out.resize(data.rows(), data.bitsPerEntry());
        // for (u64 i = 0; i < data.rows(); ++i)
        // {
        //     memcpy(out[i].subspan(0, offset), data[i].subspan(0, offset));
        //     out(i, offset) = temp(i);
        // }
        

        // Need to update the Active Flag
        MC_END();
    }

    oc::BetaCircuit* Where::genWhCircuit(SharedTable& st,
        const std::vector<ArrGate>& gates, 
        const std::vector<std::string>& literals,
        const std::vector<std::string>& literalsType,
        const u64 totalCol,
        const std::unordered_map<u64, u64>& map)
    {
        auto* cd = new BetaCircuit;
        bool lastOp = false;
        genWhBundle(literals, literalsType, totalCol, st, map);
        std::cout << "Beta Bundle Generated" << std::endl;
        for(u64 i = 0; i < gates.size(); i++)
        {
            u64 inIndex1 = gates[i].mInput[0];
            u64 inIndex2 = gates[i].mInput[1];

            // For the last operation we add Output Gate not tempwirebundle
            if( i == (gates.size() - 1))
                lastOp = true;

            if(gates[i].mType == ArrGateType::EQUALS || gates[i].mType == ArrGateType::NOT_EQUALS)
            {
                BetaBundle c;
                ArrTypeEqualsCir(inIndex1, inIndex2, st, cd, map, c, lastOp);

                if(gates[i].mType == ArrGateType::NOT_EQUALS)
                    cd->addInvert(c.mWires[0]);

                mWhBundle.emplace_back(c, WhType::InterOut);
            }
            else if(gates[i].mType == ArrGateType::AND || gates[i].mType == ArrGateType::OR)
            {
                // We assume that inputs to these gates are betabundles
                // bcoz they are logical and & or.
                BetaBundle in1 = mWhBundle[inIndex1].mBundle;
                BetaBundle in2 = mWhBundle[inIndex2].mBundle;
                BetaBundle c(1);
                
                addOutputBundle(cd, c, lastOp);

                assert(in1.mWires.size() == 1);
                assert(in2.mWires.size() == 1);

                if(gates[i].mType == ArrGateType::AND)
                    cd->addGate(in1.mWires[0], in2.mWires[0], oc::GateType::And, c.mWires[0]);
                else if(gates[i].mType == ArrGateType::OR)
                    cd->addGate(in1.mWires[0], in2.mWires[0], oc::GateType::Or, c.mWires[0]);

                // Add temp vector in the mInter vector
                mWhBundle.emplace_back(c, WhType::InterOut);
            }
            else if(gates[i].mType == ArrGateType::LESS_THAN || 
                gates[i].mType == ArrGateType::GREATER_THAN)
            {
                BetaBundle c;
                ArrTypeLessThanCir(inIndex1, inIndex2, st, cd, map, c, lastOp); 

                // This is greater than equals
                if(gates[i].mType == ArrGateType::GREATER_THAN)
                    cd->addInvert(c.mWires[0]);

                // Put the output in the mIter
                mWhBundle.emplace_back(c, WhType::InterOut);
            }
            else if(gates[i].mType == ArrGateType::ADDITION)
            {
                BetaBundle c;
                ArrTypeAddCir(inIndex1, inIndex2, st, cd, map, c, lastOp);

                // Put the output in the mIter
                mWhBundle.emplace_back(c, WhType::InterInt);
            }

        }

        return cd;
    }


    void Where::genWhBundle(const std::vector<std::string>& literals, 
        const std::vector<std::string>& literalType, const u64 totalCol,
        SharedTable& st, const std::unordered_map<u64, u64>& map)
    {
        // Adding all the columns
        for(u64 i=0; i < totalCol; i++)
        {
            if(literalType[i] != WHBUNDLE_COL_TYPE)
            {
                std::string temp = "Index = " + std::to_string(i) + " is not a column\n " + LOCATION;
                throw std::runtime_error(temp);
            }

            u64 size = getInputColSize(st, i, totalCol, map);
            BetaBundle a(size);
            mWhBundle.emplace_back(a, WhType::Col);
        }
        // Adding all the Const
        for(u64 i=totalCol; i<literals.size(); i++)
        {
            std::string lit = literals[i];

            if(literalType[i] == WHBUNDLE_NUM_TYPE)
            {
                long long number = std::stoll(lit);
                u64 numBits;
                if(number == 0)
                    numBits = 1; // log of zero is not define
                else
                    numBits = oc::log2ceil(std::abs(number)) + 1 + 1;
                
                BetaBundle a(numBits);
                oc::BitVector kk((oc::u8*)&number, numBits);
                mWhBundle.emplace_back(a, kk, WhType::Number);
            }
            else if(literalType[i] == WHBUNDLE_STRING_TYPE)
            {
                BetaBundle a(lit.size());
                oc::BitVector vec((oc::u8*)lit.data(), lit.size()*8);
                mWhBundle.emplace_back(a, vec, WhType::String);
            }
        }
        
        for(u64 i =0; i < mWhBundle.size(); i++)
        {
            std::cout << "BetaBundle Size is " << mWhBundle[i].mBundle.size()
                << " BitVector is " <<  mWhBundle[i].mVal
                << " Type is " << mWhBundle[i].mType
                << std::endl;
        }
        // InterMediate Outputs will be added when we are creating the circuit
    }

    void Where::addOutputBundle(oc::BetaCircuit* cd, BetaBundle &c, bool lastOp)
    {
        if(lastOp)
            cd->addOutputBundle(c);
        else
            cd->addTempWireBundle(c);
    }

    void Where::ArrTypeEqualsCir(const u64 inIndex1, const u64 inIndex2,
        SharedTable& st,
        oc::BetaCircuit* cd,
        const std::unordered_map<u64, u64>& map, 
        BetaBundle &c,
        bool lastOp)
    {
        BetaBundle a = mWhBundle[inIndex1].mBundle;
        BetaBundle b = mWhBundle[inIndex2].mBundle;
        u64 aSize = mWhBundle[inIndex1].mBundle.size();
        u64 bSize = mWhBundle[inIndex2].mBundle.size();

        if((mWhBundle[inIndex1].mType == WhType::Number && mWhBundle[inIndex2].mType == WhType::Number)
            || (mWhBundle[inIndex1].mType == WhType::String && mWhBundle[inIndex2].mType == WhType::String)
            || (mWhBundle[inIndex1].mType == WhType::String && mWhBundle[inIndex2].mType == WhType::Number)
            || (mWhBundle[inIndex1].mType == WhType::Number && mWhBundle[inIndex2].mType == WhType::String)
            || mWhBundle[inIndex1].mType == WhType::InterOut || mWhBundle[inIndex2].mType == WhType::InterOut)
        {
            std::string temp = "Index1 = " + std::to_string(inIndex1) + " Index2 = " +
            std::to_string(inIndex2) + " are not valid for equals operator" + "\n" + LOCATION;
            throw std::runtime_error(temp);
        }
        u64 biggerSize = aSize;        
        if(aSize > bSize)
        {
            signExtend(aSize, inIndex2, inIndex1, st, map);
            biggerSize = aSize;
        }
        else if(bSize > aSize)
        {
            signExtend(bSize, inIndex1, inIndex2, st, map);
            biggerSize = bSize;
        }

        a.resize(biggerSize);
        b.resize(biggerSize);        
        c.resize(1);

        if(mWhBundle[inIndex1].mType == WhType::Number || mWhBundle[inIndex1].mType == WhType::String)
        {
            BitVector aa = mWhBundle[inIndex1].mVal;
            cd->addConstBundle(a, aa);
        }
        else
            cd->addInputBundle(a);
        
        if(mWhBundle[inIndex2].mType == WhType::Number || mWhBundle[inIndex2].mType == WhType::String)
        {
            BitVector bb = mWhBundle[inIndex2].mVal;
            cd->addConstBundle(b, bb);
        }
        else
            cd->addInputBundle(b);

        addOutputBundle(cd, c, lastOp);

        BetaLibrary::eq_build(*cd, a, b, c);
    }

    void Where::signExtend(u64 biggerSize, u64 smallerSizeIndex, u64 biggerSizeIndex,
        SharedTable& st,
        const std::unordered_map<u64, u64>& map)
    {
        if(mWhBundle[biggerSizeIndex].mType == WhType::Col)
            addColInVec(st, biggerSizeIndex, map);

        if(mWhBundle[smallerSizeIndex].mType == WhType::Col)
        {
            u64 index = getMapVal(map, smallerSizeIndex);
            BinMatrix in = st[index].mCol.mData;
            BinMatrix* temp = signExtend(in, biggerSize, st[index].mCol.mType);
            mInputs.emplace_back(temp);
        }
        else if(mWhBundle[smallerSizeIndex].mType == WhType::Number)
        {
            mWhBundle[smallerSizeIndex].mBundle.resize(biggerSize);
            signExtend(mWhBundle[smallerSizeIndex].mVal, biggerSize, WhType::Number);
        }
        else if(mWhBundle[smallerSizeIndex].mType == WhType::String)
        {
            mWhBundle[smallerSizeIndex].mBundle.resize(biggerSize);
            signExtend(mWhBundle[smallerSizeIndex].mVal, biggerSize, WhType::String);

        }
        else if(mWhBundle[smallerSizeIndex].mType == WhType::InterInt)
        {
            signExtend(mWhBundle[smallerSizeIndex].mBundle, biggerSize, WhType::InterInt);
        }
    }
    
    void Where::signExtend(BitVector& aa, u64 size, WhType type)
    {
        if( aa.size() > size)
        {
            std::string temp = "Size of the Number is already greater \
                than the new size" LOCATION;
            throw std::runtime_error(temp);
        }

        u64 rem = size - aa.size();

        // Appending 0 to the string
        if(type == WhType::String)
            extendBitVector(aa, 0, rem); 
        else if(type == WhType::Number)
        {
            // Sign Extending Number
            if(aa[aa.size() - 1] == 1)
                extendBitVector(aa, 1, rem); 
            else
                extendBitVector(aa, 0, rem); 
        }

    }

    BinMatrix* Where::signExtend(BinMatrix& in, u64 size, TypeID type)
    {
        if(in.cols() > size)
        {
            std::string temp = "Size of the Number is already greater \
                than the new size" LOCATION;
            throw std::runtime_error(temp);
        }

        BinMatrix temp(in.rows(), size);
        temp.setZero();

        u64 tempBytes = temp.bytesPerEntry();
        u64 inBytes = in.bytesPerEntry();
        u64 inBits = in.bitsPerEntry();
        if(type == TypeID::StringID)
        {
            for(u64 i=0; i<in.rows(); i++)
                memcpy(temp.data(i), in.data(i), inBytes);
        }    
        else if(type == TypeID::IntID)
        {
            // Sign Extending Number
            for(u64 i=0; i<in.rows(); i++)
            {
                // Case where it is a negative number
                if((in(i, inBytes-1) & (1 << (inBits-1))) == (1 << (inBits-1)))
                    memset(temp.data(i), -1, tempBytes);

                memcpy(temp.data(i), in.data(i), inBytes);
            }
        }
        return &temp;
    }

    void Where::signExtend(BetaBundle& aa, u64 size, WhType type)
    {
        if(aa.size() > size)
        {
            std::string temp = "Size of the Matrix is already greater \
                than the new size" LOCATION;
            throw std::runtime_error(temp);
        }

        u64 rem = size - aa.size();

        // Sign Extending Number
        if(type == WhType::InterInt)
        {
            if(aa[aa.size() - 1] == 1)
                extendBetaBundle(aa, 1, rem); 
            else
                extendBetaBundle(aa, 0, rem); 
        }
    }

    void Where::extendBetaBundle(BetaBundle& aa, u32 bit, u64 size)
    {
        for(oc::u64 i=0; i<size; i++)
            aa.push_back(bit);
    }

    void Where::extendBitVector(BitVector& aa, u8 bit, u64 size)
    {
        for(oc::u64 i=0; i<size; i++)
            aa.pushBack(bit);
    }
    
    void Where::ArrTypeAddCir(u64 inIndex1, u64 inIndex2,
        SharedTable& st,
        oc::BetaCircuit* cd,
        const std::unordered_map<u64, u64>& map, 
        BetaBundle &c,
        bool lastOp)
    {
        BetaBundle a = mWhBundle[inIndex1].mBundle;
        BetaBundle b = mWhBundle[inIndex2].mBundle;
        u64 aSize = mWhBundle[inIndex1].mBundle.size();
        u64 bSize = mWhBundle[inIndex2].mBundle.size();
        u64 cSize = aSize > bSize ? aSize : bSize;
        BetaBundle t;
        c.resize(cSize);

        addOutputBundle(cd, c, lastOp);

        if((mWhBundle[inIndex1].mType == WhType::Number && mWhBundle[inIndex2].mType == WhType::Number)
            || mWhBundle[inIndex1].mType == WhType::String || mWhBundle[inIndex2].mType == WhType::String)
        {
            std::string temp = "index = "+ std::to_string(inIndex1) +
                " index = "+ std::to_string(inIndex2) + 
                " are not valid for addition operation in where clause" + "\n" + LOCATION;
            throw std::runtime_error(temp);
        }
        else if(mWhBundle[inIndex1].mType == WhType::Number)
        {
            BitVector aa = mWhBundle[inIndex1].mVal;
            t.resize(3 + 2 * cSize);

            cd->addConstBundle(a, aa);
            cd->addInputBundle(b);
            cd->addTempWireBundle(t);

            BetaLibrary::add_build(*cd, a, b, c, t, IntType::TwosComplement, mOp);
        }
        else if(mWhBundle[inIndex2].mType == WhType::Number)
        {
            BitVector bb = mWhBundle[inIndex2].mVal;
            t.resize(3 + 2 * cSize);
            
            cd->addInputBundle(a);
            cd->addConstBundle(b, bb);
            cd->addTempWireBundle(t);

            BetaLibrary::add_build(*cd, a, b, c, t, IntType::TwosComplement, mOp);
        }
        else
        {
            t.resize(mOp == Optimized::Size ? 4 : cSize * 2);
            cd->addInputBundle(a);
            cd->addInputBundle(b);
            cd->addTempWireBundle(t);

            // Ask Peter in cryptoTools we use IntType:: which is not getting compiled
            BetaLibrary::add_build(*cd, a, b, c, t, IntType::TwosComplement	, mOp);
        }

        if(mWhBundle[inIndex1].mType == WhType::Col)
            addColInVec(st, inIndex1, map);

        if(mWhBundle[inIndex2].mType == WhType::Col)
            addColInVec(st, inIndex2, map);
    }


    void Where::ArrTypeLessThanCir(u64 inIndex1, u64 inIndex2,
        SharedTable& st,
        oc::BetaCircuit* cd,
        const std::unordered_map<u64, u64>& map,  
        BetaBundle &c,
        bool lastOp)
    {
        BetaBundle a = mWhBundle[inIndex1].mBundle;
        BetaBundle b = mWhBundle[inIndex2].mBundle;
        c.resize(1);

        if((mWhBundle[inIndex1].mType == WhType::Number && mWhBundle[inIndex2].mType == WhType::Number)
            || (mWhBundle[inIndex1].mType == WhType::String && mWhBundle[inIndex2].mType == WhType::String)
            || (mWhBundle[inIndex1].mType == WhType::String && mWhBundle[inIndex2].mType == WhType::Number)
            || (mWhBundle[inIndex1].mType == WhType::Number && mWhBundle[inIndex2].mType == WhType::String))
        {
            std::string temp = "Index1 = " + std::to_string(inIndex1) + " Index2 = " +
            std::to_string(inIndex2) + " are not valid for less than operator" + "\n" + LOCATION;
            throw std::runtime_error(temp);
        }
        else if(mWhBundle[inIndex1].mType == WhType::Number || mWhBundle[inIndex1].mType == WhType::String)
        {
            BitVector aa = mWhBundle[inIndex1].mVal;
            cd->addConstBundle(a, aa);
            cd->addInputBundle(b);
            addOutputBundle(cd, c, lastOp);
        }
        else if(mWhBundle[inIndex2].mType == WhType::Number || mWhBundle[inIndex2].mType == WhType::String)
        {
            BitVector bb = mWhBundle[inIndex2].mVal;
            cd->addConstBundle(b, bb);
            cd->addInputBundle(a);
            addOutputBundle(cd, c, lastOp);
        }
        else
        {
            cd->addInputBundle(a);
            cd->addInputBundle(b);
            addOutputBundle(cd, c, lastOp);
        }
        BetaLibrary::lessThan_build(*cd, a, b, c, BetaLibrary::IntType::TwosComplement, mOp);

        if(mWhBundle[inIndex1].mType == WhType::Col)
            addColInVec(st, inIndex1, map);

        if(mWhBundle[inIndex2].mType == WhType::Col)
            addColInVec(st, inIndex2, map);
    }

    void Where::addColInVec(SharedTable& st,
        u64 gateInputIndex,
        const std::unordered_map<u64, u64>& map)
    {
        u64 index = getMapVal(map, gateInputIndex);
        BinMatrix temp = st[index].mCol.mData;
        mInputs.emplace_back(&temp);
    }

    u64 Where::getInputColSize(SharedTable& st,
        u64 gateInputIndex,
        u64 totalCol,
        const std::unordered_map<u64, u64>& map)
    {
        if(gateInputIndex < totalCol)
        {
            u64 index = getMapVal(map, gateInputIndex);
            // 
            if(index == -1)
                return 0;
            BinMatrix temp = st[index].mCol.mData;
            // return temp.bitsPerEntry();
            // this might not work bcoz BinMatrix's row has more extra trailing bits 
            return temp.bytesPerEntry() * 8;
        }
        std::string temp = "Index = "+ std::to_string(gateInputIndex) +
            " is not a column" + "\n" + LOCATION;
        throw std::runtime_error(temp);
    }

    u64 Where::getMapVal(const std::unordered_map<u64, u64>& map, u64 tag)
    {
        auto t = map.find(tag);
        if (t == map.end()){
            // std::string temp = "Column Index not present in the uMap "
            //     + std::to_string(tag) + " " + LOCATION;
            // throw std::runtime_error(temp);
            return -1;
        }
        return t->second;
    }
}