#include "Where.h"

namespace secJoin {

	void Where::eq_build(
		BetaCircuit& cd,
		BetaBundle& a1,
		BetaBundle& a2,
		BetaBundle& out)
	{
        auto bits = a1.mWires.size();
		BetaBundle temp(1);
		cd.addTempWireBundle(temp);
		cd.addGate(a1.mWires[0], a2.mWires[0],
			oc::GateType::Nxor, out.mWires[0]);

		for (u64 i = 1; i < bits; ++i)
		{
			cd.addGate(a1.mWires[i], a2.mWires[i],
				oc::GateType::Nxor, temp.mWires[0]);

			cd.addGate(temp.mWires[0], out.mWires[0],
				oc::GateType::And, out.mWires[0]);
		}
	}

    macoro::task<> Where::where(SharedTable& st,
        const std::vector<ArrGate>& gates, 
        const std::vector<std::string>& literals,
        const std::vector<std::string>& literalsType,
        const u64 totalCol,
        SharedTable& out,
        const std::unordered_map<u64, u64>& map,
        CorGenerator& ole,
        coproto::Socket& sock,
        const bool print)
    {
        MC_BEGIN(macoro::task<>, this, &st, &gates, &literals, &literalsType, &out, &sock, print,
            &map, totalCol, &ole,
            cd = oc::BetaCircuit{},
            gmw = Gmw{},
            rows = u64(),
            tempOut = oc::Matrix<u8>());

        cd = *genWhCir(st, gates, literals, literalsType, totalCol, map, ole.partyIdx(), print);
        rows = st.rows();
        gmw.init(rows, cd, ole);
        
        // Inputs to the GMW
        for(u64 i=0; i < mGmwIn.size(); i++)
            gmw.setInput(i, mGmwIn[i]);

        MC_AWAIT(gmw.run(sock));

        tempOut.resize(rows, 1);
        gmw.getOutput(0, tempOut);
        out = st;
        for (u64 i = 0; i < rows; ++i)
        {
            // memcpy(out[i].subspan(0, offset), data[i].subspan(0, offset));
            // out(i, offset) = temp(i);
            memcpy(&out.mIsActive[i], tempOut.data(i), 1);
        }
        

        // Need to update the Active Flag
        MC_END();
    }

    oc::BetaCircuit* Where::genWhCir(SharedTable& st,
        const std::vector<ArrGate>& gates, 
        const std::vector<std::string>& literals,
        const std::vector<std::string>& literalsType,
        const u64 totalCol,
        const std::unordered_map<u64, u64>& map,
        const u64 role,
        const bool print)
    {
        auto* cd = new BetaCircuit;
        bool lastOp = false;
        genWhBundle(literals, literalsType, totalCol, st, map, print);
        
        // Adding Input, temp, Output Bundles
        for(u64 i = 0; i < gates.size(); i++)
        {
            u64 inIndex1 = gates[i].mInput[0];
            u64 inIndex2 = gates[i].mInput[1];
            BetaBundle c;

            // For the last operation we add Output Gate not tempwirebundle
            if( i == (gates.size() - 1))
                lastOp = true;

            if(gates[i].mType == ArrGateType::EQUALS || gates[i].mType == ArrGateType::NOT_EQUALS)
            {
                ArrTypeEqualInputs(inIndex1, inIndex2, st, cd, map, c, lastOp);
                mWhBundle.emplace_back(c, WhType::InterOut);
            }
            else if(gates[i].mType == ArrGateType::AND || gates[i].mType == ArrGateType::OR)
            {
                // We assume that inputs to these gates are betabundles & are already part of WhBundle
                // bcoz they are logical and & or.
                c.resize(1);
                addOutBundle(cd, c, lastOp);
                mWhBundle.emplace_back(c, WhType::InterOut);
            }
            else if(gates[i].mType == ArrGateType::LESS_THAN || 
                gates[i].mType == ArrGateType::GREATER_THAN_EQUALS)
            {
                ArrTypeLessThanInputs(inIndex1, inIndex2, st, cd, map, c, lastOp); 
                mWhBundle.emplace_back(c, WhType::InterOut);
            }
            else if(gates[i].mType == ArrGateType::ADDITION)
            {
                ArrTypeAddInputs(inIndex1, inIndex2, st, cd, map, c, lastOp);
                mWhBundle.emplace_back(c, WhType::InterInt);
            }

        }
        // Adding Gates to the Circuit
        for(u64 i = 0; i < gates.size(); i++)
        {
            u64 inIndex1 = gates[i].mInput[0];
            u64 inIndex2 = gates[i].mInput[1];
            u64 outIndex = gates[i].mOutput;
            BetaBundle &a = mWhBundle[inIndex1].mBundle;
            BetaBundle &b = mWhBundle[inIndex2].mBundle;
            BetaBundle &c = mWhBundle[outIndex].mBundle;

            if(gates[i].mType == ArrGateType::EQUALS || gates[i].mType == ArrGateType::NOT_EQUALS)
            {
                assert(a.mWires.size() == b.mWires.size());
                assert(c.mWires.size() == 1);
                eq_build(*cd, a, b, c);

                if(gates[i].mType == ArrGateType::NOT_EQUALS && role == 0)
                    cd->addInvert(c.mWires[0]);
            }
            else if(gates[i].mType == ArrGateType::AND || gates[i].mType == ArrGateType::OR)
            {
                assert(a.mWires.size() == 1);
                assert(b.mWires.size() == 1);
                assert(c.mWires.size() == 1);

                if(gates[i].mType == ArrGateType::AND)
                    cd->addGate(a.mWires[0], b.mWires[0], oc::GateType::And, c.mWires[0]);
                else if(gates[i].mType == ArrGateType::OR)
                    cd->addGate(a.mWires[0], b.mWires[0], oc::GateType::Or, c.mWires[0]);
            }
            else if(gates[i].mType == ArrGateType::LESS_THAN || 
                gates[i].mType == ArrGateType::GREATER_THAN_EQUALS)
            {
                assert(c.mWires.size() == 1);
                BetaLibrary::lessThan_build(*cd, a, b, c, BetaLibrary::IntType::TwosComplement, mOp);

                // This is greater than equals
                if(gates[i].mType == ArrGateType::GREATER_THAN_EQUALS  && role == 0)
                    cd->addInvert(c.mWires[0]);

            }
            else if(gates[i].mType == ArrGateType::ADDITION)
            {
                u64 cSize = a.mWires.size() > b.mWires.size() ? a.mWires.size() : b.mWires.size();
                assert(c.mWires.size() == cSize);
                assert(mTempWireBundle.size() > 0);
                BetaBundle t = mTempWireBundle[0];
                // Removing the first entry from the temp Wire Bundle
                mTempWireBundle.erase(mTempWireBundle.begin()); 
                BetaLibrary::add_build(*cd, a, b, c, t, IntType::TwosComplement, mOp);
            }

        }

        return cd;
    }


    void Where::genWhBundle(const std::vector<std::string>& literals, 
        const std::vector<std::string>& literalsType, const u64 totalCol,
        SharedTable& st, const std::unordered_map<u64, u64>& map, const bool print)
    {
        assert(literals.size() == literalsType.size());
        // Adding all the columns
        for(u64 i=0; i < totalCol; i++)
        {
            if(literalsType[i] != WHBUNDLE_COL_TYPE)
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

            if(literalsType[i] == WHBUNDLE_NUM_TYPE)
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
            else if(literalsType[i] == WHBUNDLE_STRING_TYPE)
            {
                u64 numBits = lit.size() * 8;
                BetaBundle a(numBits);
                oc::BitVector vec((oc::u8*)lit.data(), numBits);
                mWhBundle.emplace_back(a, vec, WhType::String);
            }
            else
                throw RTE_LOC;
        }
        if(print)
        {
            for(u64 i =0; i < mWhBundle.size(); i++)
            {
                std::cout << "BetaBundle Size is " << mWhBundle[i].mBundle.size()
                    << " BitVector is " <<  mWhBundle[i].mVal
                    << " Type is " << mWhBundle[i].mType
                    << std::endl;
            }
        }
        // InterMediate Outputs will be added when we are creating the circuit
    }

    void Where::addOutBundle(oc::BetaCircuit* cd, BetaBundle &c, bool lastOp)
    {
        if(lastOp)
            cd->addOutputBundle(c);
        else
            cd->addTempWireBundle(c);
    }

    void Where::ArrTypeEqualInputs(const u64 inIndex1, const u64 inIndex2,
        SharedTable& st,
        oc::BetaCircuit* cd,
        const std::unordered_map<u64, u64>& map, 
        BetaBundle &c,
        bool lastOp)
    {
        BetaBundle& a = mWhBundle[inIndex1].mBundle;
        BetaBundle& b = mWhBundle[inIndex2].mBundle;
        u64 aSize = mWhBundle[inIndex1].mBundle.size();
        u64 bSize = mWhBundle[inIndex2].mBundle.size();
        WhType typeIndex1 = mWhBundle[inIndex1].mType;
        WhType typeIndex2 = mWhBundle[inIndex2].mType;

        if((typeIndex1 == WhType::Number && typeIndex2 == WhType::Number)
            || (typeIndex1 == WhType::String && typeIndex2 == WhType::String)
            || (typeIndex1 == WhType::String && typeIndex2 == WhType::Number)
            || (typeIndex1 == WhType::Number && typeIndex2 == WhType::String)
            || typeIndex1 == WhType::InterOut || typeIndex2 == WhType::InterOut)
        {
            std::string temp = "Index1 = " + std::to_string(inIndex1) + " Index2 = " +
            std::to_string(inIndex2) + " are not valid for equals operator" + "\n" + LOCATION;
            throw std::runtime_error(temp);
        }
        u64 biggerSize = aSize;        
        if(aSize > bSize)
        {
            signExtend(inIndex2, aSize, inIndex1, st, map);
            biggerSize = aSize;
        }
        else if(bSize > aSize)
        {
            signExtend(inIndex1, bSize, inIndex2, st, map);
            biggerSize = bSize;
        }
        else
        {
            // SignExtend Adds GMW Input but the case where 
            // input size are equal, we are adding it here
            addToGmwInput(st, inIndex1, map, typeIndex1);
            addToGmwInput(st, inIndex2, map, typeIndex2);
        }

        a.resize(biggerSize);
        b.resize(biggerSize);        
        c.resize(1);

        if(typeIndex1 == WhType::Number || typeIndex1 == WhType::String)
        {
            BitVector aa = mWhBundle[inIndex1].mVal;
            cd->addConstBundle(a, aa);
        }
        else
            cd->addInputBundle(a);
        
        if(typeIndex2 == WhType::Number || typeIndex2 == WhType::String)
        {
            BitVector bb = mWhBundle[inIndex2].mVal;
            cd->addConstBundle(b, bb);
        }
        else
            cd->addInputBundle(b);

        addOutBundle(cd, c, lastOp);
        
    }

    void Where::signExtend(u64 smallerSizeIndex, u64 biggerSize, u64 biggerSizeIndex,
        SharedTable& st,
        const std::unordered_map<u64, u64>& map)
    {
        addToGmwInput(st, biggerSizeIndex, map, mWhBundle[biggerSizeIndex].mType);

        if(mWhBundle[smallerSizeIndex].mType == WhType::Col)
        {
            u64 index = getMapVal(map, smallerSizeIndex);
            BinMatrix in = st[index].mCol.mData;
            signExtend(in, biggerSize, st[index].mCol.mType);
        }
        else if(mWhBundle[smallerSizeIndex].mType == WhType::Number)
            signExtend(mWhBundle[smallerSizeIndex].mVal, biggerSize, WhType::Number);
        else if(mWhBundle[smallerSizeIndex].mType == WhType::String)
            signExtend(mWhBundle[smallerSizeIndex].mVal, biggerSize, WhType::String);
        else if(mWhBundle[smallerSizeIndex].mType == WhType::InterInt)
            signExtend(mWhBundle[smallerSizeIndex].mBundle, biggerSize, WhType::InterInt);
        
    }
    
    void Where::signExtend(BitVector& aa, u64 size, WhType type)
    {
        if( aa.size() > size)
        {
            std::string temp = "Size of the Number is already greater \
                than the new size " LOCATION;
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

    void Where::signExtend(BinMatrix& in, u64 size, TypeID type)
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
        mGmwIn.emplace_back(temp);
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
    
    void Where::ArrTypeAddInputs(u64 inIndex1, u64 inIndex2,
        SharedTable& st,
        oc::BetaCircuit* cd,
        const std::unordered_map<u64, u64>& map, 
        BetaBundle &c,
        bool lastOp)
    {
        if(lastOp)
        {
            std::string temp = "index = "+ std::to_string(inIndex1) +
                " index = "+ std::to_string(inIndex2) + 
                " is an invalid circuit. This addition can't be the last operation" + "\n" + LOCATION;
            throw std::runtime_error(temp);
        }

        BetaBundle& a = mWhBundle[inIndex1].mBundle;
        BetaBundle& b = mWhBundle[inIndex2].mBundle;
        u64 aSize = mWhBundle[inIndex1].mBundle.size();
        u64 bSize = mWhBundle[inIndex2].mBundle.size();
        WhType typeIndex1 = mWhBundle[inIndex1].mType;
        WhType typeIndex2 = mWhBundle[inIndex2].mType;

        u64 cSize = aSize > bSize ? aSize : bSize;
        BetaBundle t;
        c.resize(cSize);

        if((typeIndex1 == WhType::Number && typeIndex2 == WhType::Number)
            || typeIndex1 == WhType::String || typeIndex2 == WhType::String)
        {
            std::string temp = "index = "+ std::to_string(inIndex1) +
                " index = "+ std::to_string(inIndex2) + 
                " are not valid for addition operation in where clause" + "\n" + LOCATION;
            throw std::runtime_error(temp);
        }
        else if(typeIndex1 == WhType::Number)
        {
            BitVector aa = mWhBundle[inIndex1].mVal;
            t.resize(3 + 2 * cSize);
            cd->addConstBundle(a, aa);
            cd->addInputBundle(b);
        }
        else if(typeIndex2 == WhType::Number)
        {
            BitVector bb = mWhBundle[inIndex2].mVal;
            t.resize(3 + 2 * cSize);
            cd->addInputBundle(a);
            cd->addConstBundle(b, bb);
        }
        else
        {
            t.resize(mOp == Optimized::Size ? 4 : cSize * 2);
            cd->addInputBundle(a);
            cd->addInputBundle(b);
        }
        cd->addTempWireBundle(t);
        mTempWireBundle.emplace_back(t);
        addOutBundle(cd, c, lastOp);

        // BetaLibrary::add_build(*cd, a, b, c, t, IntType::TwosComplement	, mOp);
        
        // Adding GMW Inputs
        addToGmwInput(st, inIndex1, map, typeIndex1);
        addToGmwInput(st, inIndex2, map, typeIndex2);
    }

    void Where::ArrTypeLessThanInputs(u64 inIndex1, u64 inIndex2,
        SharedTable& st,
        oc::BetaCircuit* cd,
        const std::unordered_map<u64, u64>& map,  
        BetaBundle &c,
        bool lastOp)
    {
        BetaBundle& a = mWhBundle[inIndex1].mBundle;
        BetaBundle& b = mWhBundle[inIndex2].mBundle;
        WhType typeIndex1 = mWhBundle[inIndex1].mType;
        WhType typeIndex2 = mWhBundle[inIndex2].mType;

        c.resize(1);

        if((typeIndex1 == WhType::Number && typeIndex2 == WhType::Number)
            || (typeIndex1 == WhType::String && typeIndex2 == WhType::String)
            || (typeIndex1 == WhType::String && typeIndex2 == WhType::Number)
            || (typeIndex1 == WhType::Number && typeIndex2 == WhType::String))
        {
            std::string temp = "Index1 = " + std::to_string(inIndex1) + " Index2 = " +
            std::to_string(inIndex2) + " are not valid for less than operator" + "\n" + LOCATION;
            throw std::runtime_error(temp);
        }
        else if(typeIndex1 == WhType::Number || typeIndex1 == WhType::String)
        {
            BitVector aa = mWhBundle[inIndex1].mVal;
            cd->addConstBundle(a, aa);
            cd->addInputBundle(b);
        }
        else if(typeIndex2 == WhType::Number || typeIndex2 == WhType::String)
        {
            BitVector bb = mWhBundle[inIndex2].mVal;
            cd->addConstBundle(b, bb);
            cd->addInputBundle(a);
        }
        else
        {
            cd->addInputBundle(a);
            cd->addInputBundle(b);
        }

        addOutBundle(cd, c, lastOp);

        // Adding GMW Inputs
        addToGmwInput(st, inIndex1, map, typeIndex1);
        addToGmwInput(st, inIndex2, map, typeIndex2);
    }

    void Where::addToGmwInput(SharedTable& st,
        u64 gateInputIndex,
        const std::unordered_map<u64, u64>& map,
        WhType type)
    {
        if(type == WhType::Col)
        {
            u64 index = getMapVal(map, gateInputIndex);
            BinMatrix temp = st[index].mCol.mData;
            mGmwIn.emplace_back(temp);
        }
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