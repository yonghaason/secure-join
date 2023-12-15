#include "Where_Test.h"
using namespace secJoin;


void Where_genWhBundle_Test(const oc::CLP& cmd)
{
    u64 nT = cmd.getOr("T", 511);
    bool printSteps = cmd.isSet("print");
    Table T;

    T.init(nT, { {
        {"T1", TypeID::IntID, 8},
        {"T2", TypeID::IntID, 16},
        {"T3", TypeID::StringID, 16},
    } });
    u64 totalCol = T.cols();

    std::vector<std::string> literals = {"T1", "T2", "T3", "TestString", "10"};
    std::vector<std::string> literalsType = { WHBUNDLE_COL_TYPE, WHBUNDLE_COL_TYPE, 
        WHBUNDLE_COL_TYPE, WHBUNDLE_STRING_TYPE, WHBUNDLE_NUM_TYPE};

    std::unordered_map<u64, u64> map;
    for(oc::u64 i = 0; i < totalCol; i++)
        map[i] = i;
    
    Where wh;

    wh.genWhBundle(literals, literalsType, totalCol, T, map, printSteps);

    for(u64 i=0; i<wh.mWhBundle.size(); i++)
    {
        if(wh.mWhBundle[i].mType == WhType::Col)
        {
            if(i >= totalCol)
                throw RTE_LOC;
            u64 size = wh.getInputColSize(T, i, totalCol, map);
            if(wh.mWhBundle[i].mBundle.size() != size)
                throw RTE_LOC;
        }
        else if(wh.mWhBundle[i].mType == WhType::Number)
        {
            BitVector bitVector = wh.mWhBundle[i].mVal;
            oc::u64 exp = 0;
            memcpy( &exp, bitVector.data(), oc::divCeil(bitVector.size(), 8));
            oc::u64 act = stoll(literals[i]);

            if(act != exp)
                throw RTE_LOC;
        }
        else if(wh.mWhBundle[i].mType == WhType::String)
        {
            BitVector bitVector = wh.mWhBundle[i].mVal;
            std::string exp;
            exp.resize(bitVector.size()/8);
            memcpy(exp.data(), bitVector.data(), bitVector.size()/8);

            std::string act = literals[i];
            if(act.compare(exp) != 0)
                throw RTE_LOC;
        }
        else
            throw RTE_LOC;
    }
}

void Where_ArrType_Greater_Than_Equals_Test(const oc::CLP& cmd)
{
    u64 nT = cmd.getOr("nT", 10);
    bool printSteps = cmd.isSet("print");
    bool mock = !cmd.isSet("noMock");
    Table T;
    PRNG prng0(oc::ZeroBlock);
    PRNG prng1(oc::OneBlock);


    T.init(nT, { {
        {"T0", TypeID::IntID, 16},
        {"T1", TypeID::IntID, 16},
        {"T2", TypeID::IntID, 8},
        {"T3", TypeID::IntID, 8},
        {"T4", TypeID::StringID, 128},
        {"T5", TypeID::StringID, 96}
    } });
    
    T.mIsActive.resize(nT);
    for(u64 i=0; i < nT; i++)
        T.mIsActive[i] = (u8)1;

    std::string comparisionString = "TestString";
    std::string comparisionString1 = "dfgdfggds";

    for (u64 i = 0; i < nT; ++i)
    {
        T.mColumns[0].mData.mData(i, 0) = -1 * (i % 3);
        T.mColumns[1].mData.mData(i, 0) = i % 4;
        T.mColumns[2].mData.mData(i, 0) = i % 4;   
        T.mColumns[3].mData.mData(i, 0) = -1 * (i % 5);
        if(i % 3 == 0)
            memcpy(T.mColumns[4].mData.data(i), comparisionString.data(), comparisionString.size());
        else
            memcpy(T.mColumns[4].mData.data(i), comparisionString1.data(), comparisionString1.size());
        if(i % 4 == 0)
            memcpy(T.mColumns[5].mData.data(i), comparisionString.data(), comparisionString.size());
    }
    std::array<Table, 2> Ts;
    share(T, Ts, prng0);

    u64 totalCol = T.cols();

    std::vector<std::string> literals = {"T0", "T1", "T2", "T3", "T4", "T5", comparisionString, 
        "1", "-4"};
    std::vector<std::string> literalsType = { WHBUNDLE_COL_TYPE, WHBUNDLE_COL_TYPE, WHBUNDLE_COL_TYPE,
        WHBUNDLE_COL_TYPE, WHBUNDLE_COL_TYPE, WHBUNDLE_COL_TYPE, WHBUNDLE_STRING_TYPE, 
        WHBUNDLE_NUM_TYPE, WHBUNDLE_NUM_TYPE};

    std::unordered_map<u64, u64> map;
    for(oc::u64 i = 0; i < totalCol; i++)
        map[i] = i;
    

    auto sock = coproto::LocalAsyncSocket::makePair();
    CorGenerator ole0, ole1;
    ole0.init(sock[0].fork(), prng0, 0, 1 << 16, mock);
    ole1.init(sock[1].fork(), prng1, 1, 1 << 16, mock);

    std::vector<std::array<u64, 2>> inIdxs = {{2, 3}, {0, 1}, {0, 3}, {3, 0}, {4, 5}, {8, 3},
        {1, 7}, {4, 6}};

    for(u64 i = 0; i < inIdxs.size(); i++)
    {
        Where wh0, wh1;
        u64 inIdx1 = inIdxs[i][0], inIdx2 = inIdxs[i][1];
        ArrGate gate(ArrGateType::GREATER_THAN_EQUALS, inIdx1, inIdx2, literals.size());
        SharedTable out0, out1;
        
        auto r = macoro::sync_wait(macoro::when_all_ready( 
            wh0.where(Ts[0], {gate}, literals, literalsType, totalCol, out0, map, ole0, sock[0], false),
            wh1.where(Ts[1], {gate}, literals, literalsType, totalCol, out1, map, ole1, sock[1], false)
        ));

        std::get<1>(r).result();
        std::get<0>(r).result();

        auto act = reveal(out0, out1);

        Table exp = where(T, {gate}, literals, literalsType, totalCol, map, printSteps);

        if(exp != act)
            throw RTE_LOC;

    }
}

void Where_ArrType_Addition_Test(const oc::CLP& cmd)
{
    u64 nT = cmd.getOr("nT", 10);
    bool printSteps = cmd.isSet("print");
    bool mock = !cmd.isSet("noMock");
    Table T;
    PRNG prng0(oc::ZeroBlock);
    PRNG prng1(oc::OneBlock);


    T.init(nT, { {
        {"T0", TypeID::IntID, 16},
        {"T1", TypeID::IntID, 12},
        {"T2", TypeID::IntID, 8},
    } });
    
    T.mIsActive.resize(nT);
    for(u64 i=0; i < nT; i++)
        T.mIsActive[i] = (u8)1;

    for (u64 i = 0; i < nT; ++i)
    {
        T.mColumns[0].mData.mData(i, 0) = -1 * (i % 3);
        T.mColumns[1].mData.mData(i, 0) = i % 4;
        T.mColumns[2].mData.mData(i, 0) = 5;
    }
    std::array<Table, 2> Ts;
    share(T, Ts, prng0);

    u64 totalCol = T.cols();

    std::vector<std::string> literals = {"T0", "T1", "T2", "1", "-4"};
    std::vector<std::string> literalsType = { WHBUNDLE_COL_TYPE, WHBUNDLE_COL_TYPE,
        WHBUNDLE_COL_TYPE, WHBUNDLE_NUM_TYPE, WHBUNDLE_NUM_TYPE};

    std::unordered_map<u64, u64> map;
    for(oc::u64 i = 0; i < totalCol; i++)
        map[i] = i;
    

    auto sock = coproto::LocalAsyncSocket::makePair();
    CorGenerator ole0, ole1;
    ole0.init(sock[0].fork(), prng0, 0, 1 << 16, mock);
    ole1.init(sock[1].fork(), prng1, 1, 1 << 16, mock);

    // Case 1: Adding a column
    std::vector<ArrGate> gates1 = {
        {ArrGateType::ADDITION, 0, 1, 5} ,
        {ArrGateType::LESS_THAN, 5, 2, 6} };

    // Case 2: Adding a constant
    std::vector<ArrGate> gates2 = {
        {ArrGateType::ADDITION, 4, 1, 5} ,
        {ArrGateType::LESS_THAN, 5, 2, 6} };

    
    std::vector<std::vector<ArrGate>> gates = {gates1, gates2};

    for(u64 i = 0; i < gates.size(); i++)
    {
        Where wh0, wh1;
        SharedTable out0, out1;
        
        auto r = macoro::sync_wait(macoro::when_all_ready( 
            wh0.where(Ts[0], gates[i], literals, literalsType, totalCol, out0, map, ole0, sock[0], false),
            wh1.where(Ts[1], gates[i], literals, literalsType, totalCol, out1, map, ole1, sock[1], false)
        ));

        std::get<0>(r).result();    
        std::get<1>(r).result();

        auto act = reveal(out0, out1);

        Table exp = where(T, gates[i], literals, literalsType, totalCol, map, printSteps);

        if(exp != act)
            throw RTE_LOC;

    }
}

void Where_ArrType_And_Or_Test(const oc::CLP& cmd)
{
    u64 nT = cmd.getOr("nT", 10);
    bool printSteps = cmd.isSet("print");
    bool mock = !cmd.isSet("noMock");
    Table T;
    PRNG prng0(oc::ZeroBlock);
    PRNG prng1(oc::OneBlock);


    T.init(nT, { {
        {"T0", TypeID::IntID, 16},
        {"T1", TypeID::IntID, 12},
    } });
    
    T.mIsActive.resize(nT);
    for(u64 i=0; i < nT; i++)
        T.mIsActive[i] = (u8)1;


    for (u64 i = 0; i < nT; ++i)
    {
        T.mColumns[0].mData.mData(i, 0) = i % 3;
        T.mColumns[1].mData.mData(i, 0) = i % 4;
    }
    std::array<Table, 2> Ts;
    share(T, Ts, prng0);

    u64 totalCol = T.cols();

    std::vector<std::string> literals = {"T0", "T1", "1", "-4"};
    std::vector<std::string> literalsType = { WHBUNDLE_COL_TYPE, WHBUNDLE_COL_TYPE,
        WHBUNDLE_NUM_TYPE, WHBUNDLE_NUM_TYPE};

    std::unordered_map<u64, u64> map;
    for(oc::u64 i = 0; i < totalCol; i++)
        map[i] = i;
    

    auto sock = coproto::LocalAsyncSocket::makePair();
    CorGenerator ole0, ole1;
    ole0.init(sock[0].fork(), prng0, 0, 1 << 16, mock);
    ole1.init(sock[1].fork(), prng1, 1, 1 << 16, mock);

    // Case 1: AND Gate
    std::vector<ArrGate> gates1 = {
        {ArrGateType::EQUALS, 0, 1, 4} ,
        {ArrGateType::EQUALS, 0, 2, 5} ,
        {ArrGateType::AND, 4, 5, 6} };

    // Case 2: Or Gate
    std::vector<ArrGate> gates2 = {
        {ArrGateType::EQUALS, 0, 1, 4} ,
        {ArrGateType::EQUALS, 0, 2, 5} ,
        {ArrGateType::OR, 4, 5, 6} };

    
    std::vector<std::vector<ArrGate>> gates = {gates1, gates2};

    for(u64 i = 0; i < gates.size(); i++)
    {
        Where wh0, wh1;
        SharedTable out0, out1;
        
        auto r = macoro::sync_wait(macoro::when_all_ready( 
            wh0.where(Ts[0], gates[i], literals, literalsType, totalCol, out0, map, ole0, sock[0], false),
            wh1.where(Ts[1], gates[i], literals, literalsType, totalCol, out1, map, ole1, sock[1], false)
        ));

        std::get<0>(r).result();    
        std::get<1>(r).result();

        auto act = reveal(out0, out1);

        Table exp = where(T, gates[i], literals, literalsType, totalCol, map, printSteps);

        if(exp != act)
            throw RTE_LOC;

    }
}


void Where_ArrType_Less_Than_Test(const oc::CLP& cmd)
{
    u64 nT = cmd.getOr("nT", 10);
    bool printSteps = cmd.isSet("print");
    bool mock = !cmd.isSet("noMock");
    Table T;
    PRNG prng0(oc::ZeroBlock);
    PRNG prng1(oc::OneBlock);


    T.init(nT, { {
        {"T0", TypeID::IntID, 16},
        {"T1", TypeID::IntID, 16},
        {"T2", TypeID::IntID, 8},
        {"T3", TypeID::IntID, 8},
        {"T4", TypeID::StringID, 128},
        {"T5", TypeID::StringID, 96}
    } });
    
    T.mIsActive.resize(nT);
    for(u64 i=0; i < nT; i++)
        T.mIsActive[i] = (u8)1;

    std::string comparisionString = "TestString";
    std::string comparisionString1 = "dfgdfggds";

    for (u64 i = 0; i < nT; ++i)
    {
        T.mColumns[0].mData.mData(i, 0) = -1 * (i % 3);
        T.mColumns[1].mData.mData(i, 0) = i % 4;
        T.mColumns[2].mData.mData(i, 0) = i % 4;   
        T.mColumns[3].mData.mData(i, 0) = -1 * (i % 5);
        if(i % 3 == 0)
            memcpy(T.mColumns[4].mData.data(i), comparisionString.data(), comparisionString.size());
        else
            memcpy(T.mColumns[4].mData.data(i), comparisionString1.data(), comparisionString1.size());
        if(i % 4 == 0)
            memcpy(T.mColumns[5].mData.data(i), comparisionString.data(), comparisionString.size());
    }
    std::array<Table, 2> Ts;
    share(T, Ts, prng0);

    u64 totalCol = T.cols();

    std::vector<std::string> literals = {"T0", "T1", "T2", "T3", "T4", "T5", comparisionString, 
        "1", "-4"};
    std::vector<std::string> literalsType = { WHBUNDLE_COL_TYPE, WHBUNDLE_COL_TYPE, WHBUNDLE_COL_TYPE,
        WHBUNDLE_COL_TYPE, WHBUNDLE_COL_TYPE, WHBUNDLE_COL_TYPE, WHBUNDLE_STRING_TYPE, 
        WHBUNDLE_NUM_TYPE, WHBUNDLE_NUM_TYPE};

    std::unordered_map<u64, u64> map;
    for(oc::u64 i = 0; i < totalCol; i++)
        map[i] = i;
    

    auto sock = coproto::LocalAsyncSocket::makePair();
    CorGenerator ole0, ole1;
    ole0.init(sock[0].fork(), prng0, 0, 1 << 16, mock);
    ole1.init(sock[1].fork(), prng1, 1, 1 << 16, mock);

    std::vector<std::array<u64, 2>> inIdxs = {{2, 3}, {0, 1}, {0, 3}, {3, 0}, {4, 5} };
    // {8, 3}, {1, 7}, {4, 6}};

    for(u64 i = 5; i < inIdxs.size(); i++)
    {
        Where wh0, wh1;
        u64 inIdx1 = inIdxs[i][0], inIdx2 = inIdxs[i][1];
        ArrGate gate(ArrGateType::LESS_THAN, inIdx1, inIdx2, literals.size());
        SharedTable out0, out1;
        
        auto r = macoro::sync_wait(macoro::when_all_ready( 
            wh0.where(Ts[0], {gate}, literals, literalsType, totalCol, out0, map, ole0, sock[0], false),
            wh1.where(Ts[1], {gate}, literals, literalsType, totalCol, out1, map, ole1, sock[1], false)
        ));

        std::get<1>(r).result();
        std::get<0>(r).result();

        auto act = reveal(out0, out1);

        Table exp = where(T, {gate}, literals, literalsType, totalCol, map, printSteps);

        if(exp != act)
            throw RTE_LOC;

    }
}

void Where_ArrType_Equals_Test(const oc::CLP& cmd)
{
    u64 nT = cmd.getOr("nT", 10);
    bool printSteps = cmd.isSet("print");
    bool mock = !cmd.isSet("noMock");
    Table T;
    PRNG prng0(oc::ZeroBlock);
    PRNG prng1(oc::OneBlock);


    T.init(nT, { {
        {"T0", TypeID::IntID, 16},
        {"T1", TypeID::IntID, 16},
        {"T2", TypeID::IntID, 8},
        {"T3", TypeID::IntID, 8},
        {"T4", TypeID::StringID, 128},
        {"T5", TypeID::StringID, 96}
    } });
    
    T.mIsActive.resize(nT);
    for(u64 i=0; i < nT; i++)
        T.mIsActive[i] = (u8)1;

    std::string comparisionString = "TestString";
    std::string comparisionString1 = "ldetbjfejb";
    for (u64 i = 0; i < nT; ++i)
    {
        T.mColumns[0].mData.mData(i, 0) = -1 * (i % 3);
        T.mColumns[1].mData.mData(i, 0) = i % 4;
        T.mColumns[2].mData.mData(i, 0) = i % 4;   
        T.mColumns[3].mData.mData(i, 0) = -1 * (i % 5);
        if(i % 3 == 0)
            memcpy(T.mColumns[4].mData.data(i), comparisionString.data(), comparisionString.size());
        else
            memcpy(T.mColumns[4].mData.data(i), comparisionString1.data(), comparisionString1.size());
        if(i % 4 == 0)
            memcpy(T.mColumns[5].mData.data(i), comparisionString.data(), comparisionString.size());
    }
    std::array<Table, 2> Ts;
    share(T, Ts, prng0);

    u64 totalCol = T.cols();

    std::vector<std::string> literals = {"T0", "T1", "T2", "T3", "T4", "T5", comparisionString, 
        "1", "-4"};
    std::vector<std::string> literalsType = { WHBUNDLE_COL_TYPE, WHBUNDLE_COL_TYPE, WHBUNDLE_COL_TYPE,
        WHBUNDLE_COL_TYPE, WHBUNDLE_COL_TYPE, WHBUNDLE_COL_TYPE, WHBUNDLE_STRING_TYPE, 
        WHBUNDLE_NUM_TYPE, WHBUNDLE_NUM_TYPE};

    std::unordered_map<u64, u64> map;
    for(oc::u64 i = 0; i < totalCol; i++)
        map[i] = i;
    

    auto sock = coproto::LocalAsyncSocket::makePair();
    CorGenerator ole0, ole1;
    ole0.init(sock[0].fork(), prng0, 0, 1 << 16, mock);
    ole1.init(sock[1].fork(), prng1, 1, 1 << 16, mock);

    // Test Case doesn't cover the InterInt comparision
    std::vector<std::array<u64, 2>> inIdxs = {{4, 5}, {1, 2}, {1, 3}, {1, 7}, {3, 8}, {4, 6}};

    for(u64 i = 0; i < inIdxs.size(); i++)
    {
        Where wh0, wh1;
        u64 inIdx1 = inIdxs[i][0], inIdx2 = inIdxs[i][1];
        ArrGate gate(ArrGateType::EQUALS, inIdx1, inIdx2, literals.size());
        SharedTable out0, out1;
        
        auto r = macoro::sync_wait(macoro::when_all_ready( 
            wh0.where(Ts[0], {gate}, literals, literalsType, totalCol, out0, map, ole0, sock[0], false),
            wh1.where(Ts[1], {gate}, literals, literalsType, totalCol, out1, map, ole1, sock[1], false)
        ));

        std::get<1>(r).result();
        std::get<0>(r).result();

        auto act = reveal(out0, out1);

        Table exp = where(T, {gate}, literals, literalsType, totalCol, map, printSteps);

        if(exp != act)
            throw RTE_LOC;

    }
}

void Where_ArrType_Not_Equals_Test(const oc::CLP& cmd)
{
    u64 nT = cmd.getOr("nT", 10);
    bool printSteps = cmd.isSet("print");
    bool mock = !cmd.isSet("noMock");
    Table T;
    PRNG prng0(oc::ZeroBlock);
    PRNG prng1(oc::OneBlock);


    T.init(nT, { {
        {"T0", TypeID::IntID, 16},
        {"T1", TypeID::IntID, 16},
        {"T2", TypeID::IntID, 8},
        {"T3", TypeID::IntID, 8},
        {"T4", TypeID::StringID, 128},
        {"T5", TypeID::StringID, 96}
    } });
    
    T.mIsActive.resize(nT);
    for(u64 i=0; i < nT; i++)
        T.mIsActive[i] = (u8)1;

    std::string comparisionString = "TestString";
    std::string comparisionString1 = "ldetbjfejb";
    for (u64 i = 0; i < nT; ++i)
    {
        T.mColumns[0].mData.mData(i, 0) = -1 * (i % 3);
        T.mColumns[1].mData.mData(i, 0) = i % 4;
        T.mColumns[2].mData.mData(i, 0) = i % 4;   
        T.mColumns[3].mData.mData(i, 0) = -1 * (i % 5);
        if(i % 3 == 0)
            memcpy(T.mColumns[4].mData.data(i), comparisionString.data(), comparisionString.size());
        else
            memcpy(T.mColumns[4].mData.data(i), comparisionString1.data(), comparisionString1.size());
        if(i % 4 == 0)
            memcpy(T.mColumns[5].mData.data(i), comparisionString.data(), comparisionString.size());
    }
    std::array<Table, 2> Ts;
    share(T, Ts, prng0);

    u64 totalCol = T.cols();

    std::vector<std::string> literals = {"T0", "T1", "T2", "T3", "T4", "T5", comparisionString, 
        "1", "-4"};
    std::vector<std::string> literalsType = { WHBUNDLE_COL_TYPE, WHBUNDLE_COL_TYPE, WHBUNDLE_COL_TYPE,
        WHBUNDLE_COL_TYPE, WHBUNDLE_COL_TYPE, WHBUNDLE_COL_TYPE, WHBUNDLE_STRING_TYPE, 
        WHBUNDLE_NUM_TYPE, WHBUNDLE_NUM_TYPE};

    std::unordered_map<u64, u64> map;
    for(oc::u64 i = 0; i < totalCol; i++)
        map[i] = i;
    

    auto sock = coproto::LocalAsyncSocket::makePair();
    CorGenerator ole0, ole1;
    ole0.init(sock[0].fork(), prng0, 0, 1 << 16, mock);
    ole1.init(sock[1].fork(), prng1, 1, 1 << 16, mock);

    // Test Case doesn't cover the InterInt comparision
    std::vector<std::array<u64, 2>> inIdxs = {{4, 5}, {1, 2}, {1, 3}, {1, 7}, {3, 8}, {4, 6}};

    for(u64 i = 0; i < inIdxs.size(); i++)
    {
        Where wh0, wh1;
        u64 inIdx1 = inIdxs[i][0], inIdx2 = inIdxs[i][1];
        ArrGate gate(ArrGateType::NOT_EQUALS, inIdx1, inIdx2, literals.size());
        SharedTable out0, out1;
        
        auto r = macoro::sync_wait(macoro::when_all_ready( 
            wh0.where(Ts[0], {gate}, literals, literalsType, totalCol, out0, map, ole0, sock[0], false),
            wh1.where(Ts[1], {gate}, literals, literalsType, totalCol, out1, map, ole1, sock[1], false)
        ));

        std::get<1>(r).result();
        std::get<0>(r).result();

        auto act = reveal(out0, out1);

        Table exp = where(T, {gate}, literals, literalsType, totalCol, map, printSteps);

        if(exp != act)
            throw RTE_LOC;

    }
}

void Where_join_where_Test(const oc::CLP& cmd)
{
    u64 nT = cmd.getOr("nT", 10);
    bool printSteps = cmd.isSet("print");
    bool mock = !cmd.isSet("noMock");
    Table T;
    PRNG prng0(oc::ZeroBlock);
    PRNG prng1(oc::OneBlock);


    T.init(nT, { {
        {"T0", TypeID::IntID, 16},
        {"T1", TypeID::IntID, 16},
        {"T2", TypeID::IntID, 8},
        {"T3", TypeID::IntID, 8},
        {"T4", TypeID::StringID, 128},
        {"T5", TypeID::StringID, 96}
    } });
    
    T.mIsActive.resize(nT);
    for(u64 i=0; i < nT; i++)
        T.mIsActive[i] = (u8)1;

    std::string comparisionString = "TestString";
    std::string comparisionString1 = "ldetbjfejb";
    for (u64 i = 0; i < nT; ++i)
    {
        T.mColumns[0].mData.mData(i, 0) = -1 * (i % 3);
        T.mColumns[1].mData.mData(i, 0) = i % 4;
        T.mColumns[2].mData.mData(i, 0) = i % 4;   
        T.mColumns[3].mData.mData(i, 0) = -1 * (i % 5);
        if(i % 3 == 0)
            memcpy(T.mColumns[4].mData.data(i), comparisionString.data(), comparisionString.size());
        else
            memcpy(T.mColumns[4].mData.data(i), comparisionString1.data(), comparisionString1.size());
        if(i % 4 == 0)
            memcpy(T.mColumns[5].mData.data(i), comparisionString.data(), comparisionString.size());
    }
    std::array<Table, 2> Ts;
    share(T, Ts, prng0);

    u64 totalCol = T.cols();

    std::vector<std::string> literals = {"T0", "T1", "T2", "T3", "T4", "T5", comparisionString, 
        "1", "-4"};
    std::vector<std::string> literalsType = { WHBUNDLE_COL_TYPE, WHBUNDLE_COL_TYPE, WHBUNDLE_COL_TYPE,
        WHBUNDLE_COL_TYPE, WHBUNDLE_COL_TYPE, WHBUNDLE_COL_TYPE, WHBUNDLE_STRING_TYPE, 
        WHBUNDLE_NUM_TYPE, WHBUNDLE_NUM_TYPE};

    std::unordered_map<u64, u64> map;
    for(oc::u64 i = 0; i < totalCol; i++)
        map[i] = i;
    

    auto sock = coproto::LocalAsyncSocket::makePair();
    CorGenerator ole0, ole1;
    ole0.init(sock[0].fork(), prng0, 0, 1 << 16, mock);
    ole1.init(sock[1].fork(), prng1, 1, 1 << 16, mock);

    // Col1 < Col2 && Col3 == Const
    std::vector<ArrGate> gates1 = {
        {ArrGateType::LESS_THAN, 0, 1, 9} ,
        {ArrGateType::EQUALS, 0, 3, 10} ,
        {ArrGateType::AND, 9, 10, 11} };
    
    std::vector<std::vector<ArrGate>> gates = {gates1};


    for(u64 i = 0; i < gates.size(); i++)
    {
        Where wh0, wh1;
        SharedTable out0, out1;
        
        auto r = macoro::sync_wait(macoro::when_all_ready( 
            wh0.where(Ts[0], gates[i], literals, literalsType, totalCol, out0, map, ole0, sock[0], false),
            wh1.where(Ts[1], gates[i], literals, literalsType, totalCol, out1, map, ole1, sock[1], false)
        ));

        std::get<1>(r).result();
        std::get<0>(r).result();

        auto act = reveal(out0, out1);

        Table exp = where(T, gates[i], literals, literalsType, totalCol, map, printSteps);

        if(exp != act)
            throw RTE_LOC;

    }    
}


void Where_join_where_csv_Test(const oc::CLP& cmd)
{
    
    std::string rootPath(SEC_JOIN_ROOT_DIRECTORY);
    std::string visaCsvPath = rootPath + "/tests/tables/visa.csv";
    std::string bankCsvPath = rootPath + "/tests/tables/bank.csv";
    std::string visaMetaDataPath = rootPath + "/tests/tables/visa_meta.txt";
    std::string clientMetaDataPath = rootPath + "/tests/tables/bank_meta.txt";
    
    // literals, literalType, opInfo is generated by Java
    std::vector<std::string> literals = {"PAN", "Risk_Score", "Date", "PAN", "Balance", 
        "Risk_Score", "8375"};
    std::vector<std::string> literalsType = { "Col", "Col", "Col", "Col", "Col", 
        "Col", "Number"};
    // std::vector<i64> opInfo{2, 0, 3, 4, 1, 0, 4, 5, 1, 0, 2, 1, 4, 4, 5,
    //      5, 1, 8, 7, 8, 6, 9, 6, 0, 7, 10, 3, 9, 10, 11, -1};
    // Risk_Score + Balance == 61784
    std::vector<i64> opInfo{ 2, 0, 3, 4, 0, 1, 4, 5, 1, 0, 2, 1, 4, 2, 5, 4, 5, 
        7, 1, 6, 7, 8, -1};
    bool printSteps = cmd.isSet("print");
    bool mock = !cmd.isSet("noMock");

    std::vector<u64> joinCols, selectCols, groupByCols, avgCols;
    std::vector<ArrGate> gates;
    parseColsArray(joinCols, selectCols, groupByCols, avgCols, gates, opInfo, printSteps);

    u64 lRowCount = 0, rRowCount = 0, lColCount = 0, rColCount = 0;

    std::vector<ColumnInfo> lColInfo, rColInfo;
    getFileInfo(visaMetaDataPath, lColInfo, lRowCount, lColCount);
    getFileInfo(clientMetaDataPath, rColInfo, rRowCount, rColCount);
    u64 totalCol = lColCount + rColCount;

    Table L, R;

    L.init( lRowCount, lColInfo);
    R.init( rRowCount, rColInfo);

    populateTable(L, visaCsvPath, lRowCount);
    populateTable(R, bankCsvPath, rRowCount);

    // Get Select Col Refs
    std::vector<secJoin::ColRef> selectColRefs = getSelectColRef(selectCols, L, R);

    // if (printSteps)
    // {
    //     std::cout << "L\n" << L << std::endl;
    //     std::cout << "R\n" << R << std::endl;
    // }

    PRNG prng(oc::ZeroBlock);
    std::array<Table, 2> Ls, Rs;
    share(L, Ls, prng);
    share(R, Rs, prng);

    OmJoin join0, join1;

    join0.mInsecurePrint = printSteps;
    join1.mInsecurePrint = printSteps;

    join0.mInsecureMockSubroutines = mock;
    join1.mInsecureMockSubroutines = mock;

    PRNG prng0(oc::ZeroBlock);
    PRNG prng1(oc::OneBlock);
    auto sock = coproto::LocalAsyncSocket::makePair();

    CorGenerator ole0, ole1;
    ole0.init(sock[0].fork(), prng0, 0, 1 << 16, mock);
    ole1.init(sock[1].fork(), prng1, 1, 1 << 16, mock);

    Table tempOut[2], out[2];
    
    u64 lJoinColIndex = joinCols[0];
    u64 rJoinColIndex = getRColIndex(joinCols[1], lColCount, rColCount);

    auto joinExp = join(L[lJoinColIndex], R[rJoinColIndex], selectColRefs);
    
    std::vector<secJoin::ColRef> lSelectColRefs = getSelectColRef(selectCols, Ls[0], Rs[0]);
    std::vector<secJoin::ColRef> rSelectColRefs = getSelectColRef(selectCols, Ls[1], Rs[1]);

    auto r = macoro::sync_wait(macoro::when_all_ready(
        join0.join(Ls[0][lJoinColIndex], Rs[0][rJoinColIndex], lSelectColRefs, tempOut[0], prng0, ole0, sock[0]),
        join1.join(Ls[1][lJoinColIndex], Rs[1][rJoinColIndex], rSelectColRefs, tempOut[1], prng1, ole1, sock[1])
    ));
    std::get<0>(r).result();
    std::get<1>(r).result();

    auto res = reveal(tempOut[0], tempOut[1]);

    if (res != joinExp)
    {
        std::cout << "exp \n" << joinExp << std::endl;
        std::cout << "act \n" << res << std::endl;
        // std::cout << "ful \n" << reveal(out[0], out[1], false) << std::endl;
        throw RTE_LOC;
    }
    
    // Create a new mapping and store the new mapping in the cState
    std::unordered_map<u64, u64> map;
    createNewMapping(map, selectCols);
    if(printSteps)
    {
        std::cout << "Printing Map" << std::endl;
        for (auto i : map) 
            std::cout << i.first << " \t\t\t " << i.second << std::endl; 
    }
    Where wh0, wh1;
    
    auto r1 = macoro::sync_wait(macoro::when_all_ready(
        wh0.where(tempOut[0], gates, literals, literalsType, totalCol, out[0], map, ole0, sock[0], printSteps),
        wh1.where(tempOut[1], gates, literals, literalsType, totalCol, out[1], map, ole1, sock[1], printSteps)
    ));
    std::get<0>(r1).result();
    std::get<1>(r1).result();

    auto act = reveal(out[0], out[1]);

    Table exp = where(joinExp, gates, literals, literalsType, totalCol, map, printSteps);

    if(exp != act)
    {   
        std::cout << "exp \n" << exp << std::endl;
        std::cout << "act \n" << act << std::endl;
        throw RTE_LOC;
    }
    
    
}

void Where_avg_where_csv_Test(const oc::CLP& cmd)
{
    std::string rootPath(SEC_JOIN_ROOT_DIRECTORY);
    std::string visaCsvPath = rootPath + "/tests/tables/visa.csv";
    std::string bankCsvPath = rootPath + "/tests/tables/bank.csv";
    std::string visaMetaDataPath = rootPath + "/tests/tables/visa_meta.txt";
    std::string clientMetaDataPath = rootPath + "/tests/tables/bank_meta.txt";
    
    // literals, literalType, opInfo is generated by Java
    /*
    // Case 1: bank.Risk_Score + bank.Balance == 8375
    std::vector<std::string> literals = {"PAN", "Risk_Score", "Date", "PAN", "Balance", 
        "Risk_Score", "8375"};
    std::vector<std::string> literalsType = { "Col", "Col", "Col", "Col", "Col", 
        "Col", "Number"};
    std::vector<i64> opInfo{ 2, 0, 3, 4, 0, 1, 4, 5, 1, 0, 2, 1, 4, 2, 5, 4, 5, 
        7, 1, 6, 7, 8, -1};
    */
    //Case 2: PAN == 52522546320168 || PAN == 52474898920631 || Balance + Risk_Score == 8375
    std::vector<std::string> literals = {"PAN", "Risk_Score", "Date", "PAN", "Balance", 
        "Risk_Score", "8375", "52522546320168", "52474898920631"};
    std::vector<std::string> literalsType = { WHBUNDLE_COL_TYPE, WHBUNDLE_COL_TYPE, 
        WHBUNDLE_COL_TYPE, WHBUNDLE_COL_TYPE, WHBUNDLE_COL_TYPE, WHBUNDLE_COL_TYPE, 
        WHBUNDLE_NUM_TYPE, WHBUNDLE_NUM_TYPE, WHBUNDLE_NUM_TYPE};
    std::vector<i64> opInfo{ 2, 0, 3, 4, 0, 1, 4, 5, 1, 0, 2, 1, 4, 6, 5, 4, 5, 
        9, 1, 6, 9, 10, 1, 0, 7, 11, 4, 10, 11, 12, 1, 0, 8, 13, 4, 12, 13, 14, -1};
    

    bool printSteps = cmd.isSet("print");
    bool mock = !cmd.isSet("noMock");

    std::vector<u64> joinCols, selectCols, groupByCols, avgCols;
    std::vector<ArrGate> gates;
    parseColsArray(joinCols, selectCols, groupByCols, avgCols, gates, opInfo, printSteps);

    u64 lRowCount = 0, rRowCount = 0, lColCount = 0, rColCount = 0;

    std::vector<ColumnInfo> lColInfo, rColInfo;
    getFileInfo(visaMetaDataPath, lColInfo, lRowCount, lColCount);
    getFileInfo(clientMetaDataPath, rColInfo, rRowCount, rColCount);
    u64 totalCol = lColCount + rColCount;

    Table L, R;

    L.init( lRowCount, lColInfo);
    R.init( rRowCount, rColInfo);

    populateTable(L, visaCsvPath, lRowCount);
    populateTable(R, bankCsvPath, rRowCount);

    // Get Select Col Refs
    std::vector<secJoin::ColRef> selectColRefs = getSelectColRef(selectCols, L, R);

    // if (printSteps)
    // {
    //     std::cout << "L\n" << L << std::endl;
    //     std::cout << "R\n" << R << std::endl;
    // }

    PRNG prng(oc::ZeroBlock);
    std::array<Table, 2> Ls, Rs;
    share(L, Ls, prng);
    share(R, Rs, prng);

    OmJoin join0, join1;

    join0.mInsecurePrint = printSteps;
    join1.mInsecurePrint = printSteps;

    join0.mInsecureMockSubroutines = mock;
    join1.mInsecureMockSubroutines = mock;

    PRNG prng0(oc::ZeroBlock);
    PRNG prng1(oc::OneBlock);
    auto sock = coproto::LocalAsyncSocket::makePair();

    CorGenerator ole0, ole1;
    ole0.init(sock[0].fork(), prng0, 0, 1 << 16, mock);
    ole1.init(sock[1].fork(), prng1, 1, 1 << 16, mock);

    Table joinOut[2], whereOut[2], out[2];
    
    u64 lJoinColIndex = joinCols[0];
    u64 rJoinColIndex = getRColIndex(joinCols[1], lColCount, rColCount);

    auto joinExp = join(L[lJoinColIndex], R[rJoinColIndex], selectColRefs);
    
    std::vector<secJoin::ColRef> lSelectColRefs = getSelectColRef(selectCols, Ls[0], Rs[0]);
    std::vector<secJoin::ColRef> rSelectColRefs = getSelectColRef(selectCols, Ls[1], Rs[1]);

    auto r = macoro::sync_wait(macoro::when_all_ready(
        join0.join(Ls[0][lJoinColIndex], Rs[0][rJoinColIndex], lSelectColRefs, joinOut[0], prng0, ole0, sock[0]),
        join1.join(Ls[1][lJoinColIndex], Rs[1][rJoinColIndex], rSelectColRefs, joinOut[1], prng1, ole1, sock[1])
    ));
    std::get<0>(r).result();
    std::get<1>(r).result();

    auto res = reveal(joinOut[0], joinOut[1]);

    if (res != joinExp)
    {
        std::cout << "exp \n" << joinExp << std::endl;
        std::cout << "act \n" << res << std::endl;
        // std::cout << "ful \n" << reveal(out[0], out[1], false) << std::endl;
        throw RTE_LOC;
    }
    
    // Create a new mapping and store the new mapping in the cState
    std::unordered_map<u64, u64> map;
    createNewMapping(map, selectCols);
    if(printSteps)
    {
        std::cout << "Printing Map" << std::endl;
        for (auto i : map) 
            std::cout << i.first << " \t\t\t " << i.second << std::endl; 
    }
    Where wh0, wh1;
    
    auto r1 = macoro::sync_wait(macoro::when_all_ready(
        wh0.where(joinOut[0], gates, literals, literalsType, totalCol, whereOut[0], map, ole0, sock[0], printSteps),
        wh1.where(joinOut[1], gates, literals, literalsType, totalCol, whereOut[1], map, ole1, sock[1], printSteps)
    ));
    std::get<0>(r1).result();
    std::get<1>(r1).result();

    auto whAct = reveal(whereOut[0], whereOut[1]);

    Table whExp = where(joinExp, gates, literals, literalsType, totalCol, map, printSteps);

    if(whExp != whAct)
    {   
        std::cout << "exp \n" << whExp << std::endl;
        std::cout << "act \n" << whAct << std::endl;
        throw RTE_LOC;
    }

    Average avg1, avg2;

    avg1.mInsecurePrint = printSteps;
    avg2.mInsecurePrint = printSteps;

    avg1.mInsecureMockSubroutines = mock;
    avg2.mInsecureMockSubroutines = mock;

    std::vector<secJoin::ColRef> avgColRefs = getColRefFromMapping(map, avgCols, whExp);
    std::vector<secJoin::ColRef> lAvgColRefs = getColRefFromMapping(map, avgCols, whereOut[0]);
    std::vector<secJoin::ColRef> rAvgColRefs = getColRefFromMapping(map, avgCols, whereOut[1]);
    
    // Assuming we have only one groupby column
    oc::u64 groupByColIndex = getMapVal(map, groupByCols[0]);

    auto r2 = macoro::sync_wait(macoro::when_all_ready(
        avg1.avg(whereOut[0][groupByColIndex], lAvgColRefs, out[0], prng0, ole0, sock[0]),
        avg2.avg(whereOut[1][groupByColIndex], rAvgColRefs, out[1], prng1, ole1, sock[1])
    ));
    std::get<1>(r2).result();
    std::get<0>(r2).result();

    auto avgAct = reveal(out[0], out[1]);
    auto avgExp = average(whExp[groupByColIndex], avgColRefs);

    if (avgAct != avgExp)
    {
       std::cout << "exp \n" << avgExp << std::endl;
       std::cout << "act \n" << avgAct << std::endl;
       // std::cout << "ful \n" << reveal(out[0], out[1], false) << std::endl;
       throw RTE_LOC;
    }
}