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
            tempOut = BinMatrix{});

        cd = *genWhCir(st, gates, literals, literalsType, totalCol, map, print);
        rows = st.rows();
        gmw.init(rows, cd, ole);
        
        // Inputs to the GMW
        for(u64 i=0; i < mGmwIn.size(); i++)
            gmw.setInput(i, mGmwIn[i]);

        MC_AWAIT(gmw.run(sock));

        // Where evaulates to either true or false (1 bit)
        tempOut.resize(rows, 1);
        gmw.getOutput(0, tempOut);
        out = st;

        assert(out.mIsActive.size() == rows);
        // for (u64 i = 0; i < rows; ++i)
        //     memcpy(&out.mIsActive[i], tempOut.data(i), 1);

        MC_AWAIT(updateActiveFlag(out.mIsActive, tempOut, ole, sock));
        
        MC_END();
    }

    // Active Flag = previous Active flag & Active Flag from where
    macoro::task<> Where::updateActiveFlag(
        std::vector<u8>& actFlag,
        BinMatrix& choice,
        CorGenerator& ole,
        coproto::Socket& sock)
    {
        MC_BEGIN(macoro::task<>, &actFlag, &choice, &ole, &sock,
            gmw = Gmw{},
            cir = oc::BetaCircuit{},
            temp = BinMatrix{},
            a = BetaBundle{},
            b = BetaBundle{},
            c = BetaBundle{}
        );
        // Circuit Design
        a.mWires.resize(1);
        b.mWires.resize(1);
        c.mWires.resize(1);

        cir.addInputBundle(a);
        cir.addInputBundle(b);
        cir.addOutputBundle(c);

        cir.addGate(a.mWires[0], b.mWires[0], oc::GateType::And, c.mWires[0]);
        gmw.init(actFlag.size(), cir);
        gmw.request(ole);

        temp.resize(actFlag.size(), 1);

        for (u64 i = 0; i < actFlag.size(); ++i)
            temp(i) = actFlag[i];

        gmw.setInput(0, choice);
        gmw.setInput(1, temp);

        MC_AWAIT(gmw.run(sock));

        gmw.getOutput(0, temp);
        
        for (u64 i = 0; i < actFlag.size(); ++i)
            actFlag[i] = temp(i);
        

        MC_END();    
    }

    oc::BetaCircuit* Where::genWhCir(SharedTable& st,
        const std::vector<ArrGate>& gates, 
        const std::vector<std::string>& literals,
        const std::vector<std::string>& literalsType,
        const u64 totalCol,
        const std::unordered_map<u64, u64>& map,
        const bool print)
    {
        auto* cd = new BetaCircuit;
        BetaBundle outBundle(1);
        genWhBundle(literals, literalsType, totalCol, st, map, print);

        // Adding Inputbundles
        for(u64 i = 0; i < gates.size(); i++)
        {
            u64 inIndex1 = gates[i].mInput[0];
            u64 inIndex2 = gates[i].mInput[1];

            if(gates[i].mType == ArrGateType::EQUALS || gates[i].mType == ArrGateType::NOT_EQUALS)
                ArrTypeEqualInputs(inIndex1, inIndex2, st, cd, map);
            else
            {
                addInputBundle(cd, st, inIndex1, map);
                addInputBundle(cd, st, inIndex2, map);
            }

            // Adding new Bundles in mWhBundle otherwise
            // InterInts for ArrTypeEqualInputs will fail to signExtend
            if(gates[i].mType == ArrGateType::ADDITION)
            {
                u64 aSize = mWhBundle[inIndex1].mBundle.size();
                u64 bSize = mWhBundle[inIndex2].mBundle.size();
                u64 cSize = aSize > bSize ? aSize : bSize;
                BetaBundle c(cSize);
                mWhBundle.emplace_back(c, WhType::InterInt);
            }
            else
            {
                BetaBundle c(1);
                mWhBundle.emplace_back(c, WhType::InterOut);
            }
        }

        // Adding Output Bundle 
        cd->addOutputBundle(outBundle);
        
        bool lastOp = false;
        // Adding tempBundles & Gates
        for(u64 i = 0; i < gates.size(); i++)
        {
            u64 inIndex1 = gates[i].mInput[0];
            u64 inIndex2 = gates[i].mInput[1];
            u64 outIndex = gates[i].mOutput;
            BetaBundle &a = mWhBundle[inIndex1].mBundle;
            BetaBundle &b = mWhBundle[inIndex2].mBundle;
            BetaBundle &c = mWhBundle[outIndex].mBundle;

            // For the last operation we add Output Gate not tempwirebundle
            if( i == (gates.size() - 1))
            {
                c = outBundle;
                lastOp = true;
            }

            if(gates[i].mType == ArrGateType::EQUALS || gates[i].mType == ArrGateType::NOT_EQUALS)
            {
                assert(a.mWires.size() == b.mWires.size());
                assert(c.mWires.size() == 1);
                ArrTypeEqualCir(inIndex1, inIndex2, cd, c, lastOp);
                
                if(gates[i].mType == ArrGateType::NOT_EQUALS)
                    cd->addInvert(c.mWires[0]);

            }
            else if(gates[i].mType == ArrGateType::AND || gates[i].mType == ArrGateType::OR)
            {
                // Assuming these are logical AND & OR
                assert(a.mWires.size() == 1);
                assert(b.mWires.size() == 1);
                assert(c.mWires.size() == 1);

                if(!lastOp)
                    cd->addTempWireBundle(c);

                if(gates[i].mType == ArrGateType::AND)
                    cd->addGate(a.mWires[0], b.mWires[0], oc::GateType::And, c.mWires[0]);
                else if(gates[i].mType == ArrGateType::OR)
                    cd->addGate(a.mWires[0], b.mWires[0], oc::GateType::Or, c.mWires[0]);

            }
            else if(gates[i].mType == ArrGateType::LESS_THAN || 
                gates[i].mType == ArrGateType::GREATER_THAN_EQUALS)
            {
                ArrTypeLessThanCir(inIndex1, inIndex2, cd, c, lastOp); 
                
                // This is greater than equals
                if(gates[i].mType == ArrGateType::GREATER_THAN_EQUALS)
                    cd->addInvert(c.mWires[0]);
            }
            else if(gates[i].mType == ArrGateType::ADDITION)
            {
                ArrTypeAddCir(inIndex1, inIndex2, cd, c, lastOp);
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

    void Where::addInputBundle(oc::BetaCircuit* cd, SharedTable& st,
        const u64 gateInputIndex, const std::unordered_map<u64, u64>& map)
    {
        if(gateInputIndex >= mWhBundle.size())
            return;

        BetaBundle &a = mWhBundle[gateInputIndex].mBundle;
        WhType type = mWhBundle[gateInputIndex].mType;
        if(type == WhType::Col)
        {
            cd->addInputBundle(a);
            addToGmwInput(st, gateInputIndex, map,type);
        }
            
    }

    void Where::ArrTypeEqualCir(const u64 inIndex1, const u64 inIndex2,
        oc::BetaCircuit* cd, BetaBundle &c, const bool lastOp)
    {
        BetaBundle& a = mWhBundle[inIndex1].mBundle;
        BetaBundle& b = mWhBundle[inIndex2].mBundle;
        u64 aSize = mWhBundle[inIndex1].mBundle.size();
        u64 bSize = mWhBundle[inIndex2].mBundle.size();
        WhType typeIndex1 = mWhBundle[inIndex1].mType;
        WhType typeIndex2 = mWhBundle[inIndex2].mType;
        c.resize(1);

        assert(aSize == bSize);

        if(typeIndex1 == WhType::Number || typeIndex1 == WhType::String)
        {
            BitVector aa = mWhBundle[inIndex1].mVal;
            cd->addConstBundle(a, aa);
        }
        
        if(typeIndex2 == WhType::Number || typeIndex2 == WhType::String)
        {
            BitVector bb = mWhBundle[inIndex2].mVal;
            cd->addConstBundle(b, bb);
        }

        if(!lastOp)
            cd->addTempWireBundle(c);

        eq_build(*cd, a, b, c);

    }

    void Where::ArrTypeEqualInputs(const u64 inIndex1, const u64 inIndex2,
        SharedTable& st,
        oc::BetaCircuit* cd,
        const std::unordered_map<u64, u64>& map)
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
            signExtend(inIndex2, aSize, inIndex1, st, cd, map);
            biggerSize = aSize;
        }
        else if(bSize > aSize)
        {
            signExtend(inIndex1, bSize, inIndex2, st, cd, map);
            biggerSize = bSize;
        }
        else
        {
            // SignExtend Adds GMW Input but the case where 
            // input size are equal, we are adding it here
            addInputBundle(cd, st, inIndex1, map);
            addInputBundle(cd, st, inIndex2, map);
        }

        // Resizing the BetaBundles
        a.resize(biggerSize);
        b.resize(biggerSize);   
    }

    void Where::signExtend(u64 smallerSizeIndex, u64 biggerSize, u64 biggerSizeIndex,
        SharedTable& st, oc::BetaCircuit* cd,
        const std::unordered_map<u64, u64>& map)
    {
        addInputBundle(cd, st, biggerSizeIndex, map);

        if(mWhBundle[smallerSizeIndex].mType == WhType::Col)
        {
            u64 index = getMapVal(map, smallerSizeIndex);
            BinMatrix in = st[index].mCol.mData;
            // signExtend extends the BinMatrix & adds it in GmwIns
            signExtend(in, biggerSize, st[index].mCol.mType);
            // Adding Input Bundle
            cd->addInputBundle(mWhBundle[smallerSizeIndex].mBundle);
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

        // Sign Extending Number
        if(type == WhType::InterInt)
            extendBetaBundle(aa, size);
    }

    void Where::extendBetaBundle(BetaBundle& aa, u64 size)
    {
        while(aa.size() < size) 
            aa.push_back(aa.back());
    }

    void Where::extendBitVector(BitVector& aa, u8 bit, u64 size)
    {
        for(oc::u64 i=0; i<size; i++)
            aa.pushBack(bit);
    }
    
    void Where::ArrTypeAddCir(const u64 inIndex1, const u64 inIndex2,
        oc::BetaCircuit* cd, BetaBundle &c, const bool lastOp)
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
        }
        else if(typeIndex2 == WhType::Number)
        {
            BitVector bb = mWhBundle[inIndex2].mVal;
            t.resize(3 + 2 * cSize);
            cd->addConstBundle(b, bb);
        }
        else
            t.resize(mOp == Optimized::Size ? 4 : cSize * 2);
        
        cd->addTempWireBundle(t);
        if(!lastOp)
            cd->addTempWireBundle(c);

        BetaLibrary::add_build(*cd, a, b, c, t, IntType::TwosComplement, mOp);
    }

    void Where::ArrTypeLessThanCir(const u64 inIndex1, const u64 inIndex2,
        oc::BetaCircuit* cd, BetaBundle &c, const bool lastOp)
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
        }
        else if(typeIndex2 == WhType::Number || typeIndex2 == WhType::String)
        {
            BitVector bb = mWhBundle[inIndex2].mVal;
            cd->addConstBundle(b, bb);
        }

        if(!lastOp)
            cd->addTempWireBundle(c);

        BetaLibrary::lessThan_build(*cd, a, b, c, BetaLibrary::IntType::TwosComplement, mOp);
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