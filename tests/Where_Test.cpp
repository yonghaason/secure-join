#include "Where_Test.h"
using namespace secJoin;


void evalWhGate(
    Table& T,
    const std::vector<ArrGate>& gates,
    const std::vector<std::string>& literals,
    const std::vector<std::string>& literalsType,
    const std::unordered_map<u64, u64>& map,
    const bool printSteps,
    const bool mock)
{
    auto sock = coproto::LocalAsyncSocket::makePair();

    PRNG prng0(oc::ZeroBlock);
    PRNG prng1(oc::OneBlock);

    std::array<Table, 2> Ts;
    share(T, Ts, prng0);

    u64 totalCol = T.cols();

    for (auto remDummies : { false, true })
    {
        CorGenerator ole0, ole1;
        ole0.init(sock[0].fork(), prng0, 0, 1 << 16, mock);
        ole1.init(sock[1].fork(), prng1, 1, 1 << 16, mock);

        Where wh0, wh1;
        SharedTable out0, out1;

        wh0.init(Ts[0], gates, literals, literalsType, totalCol, map, ole0, printSteps, remDummies, remDummies);
        wh1.init(Ts[1], gates, literals, literalsType, totalCol, map, ole1, printSteps, remDummies, remDummies);

        auto r = macoro::sync_wait(macoro::when_all_ready(
            ole0.start(),
            ole1.start(),
            wh0.where(Ts[0], out0, sock[0], prng0, remDummies),
            wh1.where(Ts[1], out1, sock[1], prng1, remDummies)
        ));

        std::get<0>(r).result();
        std::get<1>(r).result();
        std::get<2>(r).result();
        std::get<3>(r).result();

        auto act = reveal(out0, out1, false);

        Perm pi;
        if (remDummies)
        {
            ComposedPerm p0 = wh0.mRemDummies.mPermutation;
            ComposedPerm p1 = wh1.mRemDummies.mPermutation;
            pi = p1.permShare().compose(p0.permShare());
        }

        Table exp = where(T, gates, literals, literalsType, totalCol, map, printSteps, remDummies, pi);

        if (exp != act)
        {
            std::cout << "remove dummies flag = " << remDummies << std::endl;
            std::cout << "exp \n" << exp << std::endl;
            std::cout << "act \n" << act << std::endl;
            throw RTE_LOC;
        }

    }
}


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

    std::vector<std::string> literals = { "T1", "T2", "T3", "TestString", "10" };
    std::vector<std::string> literalsType = { WHBUNDLE_COL_TYPE, WHBUNDLE_COL_TYPE,
        WHBUNDLE_COL_TYPE, WHBUNDLE_STRING_TYPE, WHBUNDLE_NUM_TYPE };

    std::unordered_map<u64, u64> map;
    for (oc::u64 i = 0; i < totalCol; i++)
        map[i] = i;

    Where wh;

    wh.genWhBundle(literals, literalsType, totalCol, T, map, printSteps);

    for (u64 i = 0; i < wh.mWhBundle.size(); i++)
    {
        if (wh.mWhBundle[i].mType == WhType::Col)
        {
            if (i >= totalCol)
                throw RTE_LOC;
            u64 size = wh.getInputColSize(T, i, totalCol, map);
            if (wh.mWhBundle[i].mBundle.size() != size)
                throw RTE_LOC;
        }
        else if (wh.mWhBundle[i].mType == WhType::Number)
        {
            BitVector bitVector = wh.mWhBundle[i].mVal;
            oc::u64 exp = 0;
            memcpy(&exp, bitVector.data(), oc::divCeil(bitVector.size(), 8));
            oc::u64 act = stoll(literals[i]);

            if (act != exp)
                throw RTE_LOC;
        }
        else if (wh.mWhBundle[i].mType == WhType::String)
        {
            BitVector bitVector = wh.mWhBundle[i].mVal;
            std::string exp;
            exp.resize(bitVector.size() / 8);
            memcpy(exp.data(), bitVector.data(), bitVector.size() / 8);

            std::string act = literals[i];
            if (act.compare(exp) != 0)
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

    T.init(nT, { {
        {"T0", TypeID::IntID, 16},
        {"T1", TypeID::IntID, 16},
        {"T2", TypeID::IntID, 8},
        {"T3", TypeID::IntID, 8},
        {"T4", TypeID::StringID, 128},
        {"T5", TypeID::StringID, 96}
    } });

    T.mIsActive.resize(nT);
    for (u64 i = 0; i < nT; i++)
        T.mIsActive[i] = (u8)1;

    std::string comparisionString = "TestString";
    std::string comparisionString1 = "dfgdfggds";

    for (u64 i = 0; i < nT; ++i)
    {
        T.mColumns[0].mData.mData(i, 0) = -1 * (i % 3);
        T.mColumns[1].mData.mData(i, 0) = i % 4;
        T.mColumns[2].mData.mData(i, 0) = i % 4;
        T.mColumns[3].mData.mData(i, 0) = -1 * (i % 5);
        if (i % 3 == 0)
            memcpy(T.mColumns[4].mData.data(i), comparisionString.data(), comparisionString.size());
        else
            memcpy(T.mColumns[4].mData.data(i), comparisionString1.data(), comparisionString1.size());
        if (i % 4 == 0)
            memcpy(T.mColumns[5].mData.data(i), comparisionString.data(), comparisionString.size());
    }

    std::vector<std::string> literals = { "T0", "T1", "T2", "T3", "T4", "T5", comparisionString,
        "1", "-4" };
    std::vector<std::string> literalsType = { WHBUNDLE_COL_TYPE, WHBUNDLE_COL_TYPE, WHBUNDLE_COL_TYPE,
        WHBUNDLE_COL_TYPE, WHBUNDLE_COL_TYPE, WHBUNDLE_COL_TYPE, WHBUNDLE_STRING_TYPE,
        WHBUNDLE_NUM_TYPE, WHBUNDLE_NUM_TYPE };

    std::unordered_map<u64, u64> map;
    for (oc::u64 i = 0; i < T.cols(); i++)
        map[i] = i;

    std::vector<std::array<u64, 2>> inIdxs = { {2, 3}, {0, 1}, {0, 3}, {3, 0}, {4, 5}, {8, 3},
        {1, 7}, {4, 6} };

    for (u64 i = 0; i < inIdxs.size(); i++)
    {
        u64 inIdx1 = inIdxs[i][0], inIdx2 = inIdxs[i][1];
        ArrGate gate(ArrGateType::GREATER_THAN_EQUALS, inIdx1, inIdx2, literals.size());

        evalWhGate(T, {gate}, literals, literalsType, map, printSteps, mock);

    }
}

void Where_ArrType_Addition_Test(const oc::CLP& cmd)
{
    u64 nT = cmd.getOr("nT", 10);
    bool printSteps = cmd.isSet("print");
    bool mock = !cmd.isSet("noMock");
    Table T;

    T.init(nT, { {
        {"T0", TypeID::IntID, 16},
        {"T1", TypeID::IntID, 12},
        {"T2", TypeID::IntID, 8},
    } });

    T.mIsActive.resize(nT);
    for (u64 i = 0; i < nT; i++)
        T.mIsActive[i] = (u8)1;

    for (u64 i = 0; i < nT; ++i)
    {
        T.mColumns[0].mData.mData(i, 0) = -1 * (i % 3);
        T.mColumns[1].mData.mData(i, 0) = i % 4;
        T.mColumns[2].mData.mData(i, 0) = 5;
    }

    std::vector<std::string> literals = { "T0", "T1", "T2", "1", "-4" };
    std::vector<std::string> literalsType = { WHBUNDLE_COL_TYPE, WHBUNDLE_COL_TYPE,
        WHBUNDLE_COL_TYPE, WHBUNDLE_NUM_TYPE, WHBUNDLE_NUM_TYPE };

    std::unordered_map<u64, u64> map;
    for (oc::u64 i = 0; i < T.cols(); i++)
        map[i] = i;

    // Case 1: Adding a column
    std::vector<ArrGate> gates1 = {
        {ArrGateType::ADDITION, 0, 1, 5} ,
        {ArrGateType::LESS_THAN, 5, 2, 6} };

    // Case 2: Adding a constant
    std::vector<ArrGate> gates2 = {
        {ArrGateType::ADDITION, 4, 1, 5} ,
        {ArrGateType::LESS_THAN, 5, 2, 6} };


    std::vector<std::vector<ArrGate>> gates = { gates1, gates2 };

    for (u64 i = 0; i < gates.size(); i++)
        evalWhGate(T, gates[i], literals, literalsType, map, printSteps, mock);
}

void Where_ArrType_And_Or_Test(const oc::CLP& cmd)
{
    u64 nT = cmd.getOr("nT", 10);
    bool printSteps = cmd.isSet("print");
    bool mock = !cmd.isSet("noMock");
    Table T;


    T.init(nT, { {
        {"T0", TypeID::IntID, 16},
        {"T1", TypeID::IntID, 12},
    } });

    T.mIsActive.resize(nT);
    for (u64 i = 0; i < nT; i++)
        T.mIsActive[i] = (u8)1;


    for (u64 i = 0; i < nT; ++i)
    {
        T.mColumns[0].mData.mData(i, 0) = i % 3;
        T.mColumns[1].mData.mData(i, 0) = i % 4;
    }

    std::vector<std::string> literals = { "T0", "T1", "1", "-4" };
    std::vector<std::string> literalsType = { WHBUNDLE_COL_TYPE, WHBUNDLE_COL_TYPE,
        WHBUNDLE_NUM_TYPE, WHBUNDLE_NUM_TYPE };

    std::unordered_map<u64, u64> map;
    for (oc::u64 i = 0; i < T.cols(); i++)
        map[i] = i;

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


    std::vector<std::vector<ArrGate>> gates = { gates1, gates2 };

    for (u64 i = 0; i < gates.size(); i++)
        evalWhGate(T, gates[i], literals, literalsType, map, printSteps, mock);
    
}


void Where_ArrType_Less_Than_Test(const oc::CLP& cmd)
{
    u64 nT = cmd.getOr("nT", 10);
    bool printSteps = cmd.isSet("print");
    bool mock = !cmd.isSet("noMock");
    Table T;

    T.init(nT, { {
        {"T0", TypeID::IntID, 16},
        {"T1", TypeID::IntID, 16},
        {"T2", TypeID::IntID, 8},
        {"T3", TypeID::IntID, 8},
        {"T4", TypeID::StringID, 128},
        {"T5", TypeID::StringID, 96}
    } });

    T.mIsActive.resize(nT);
    for (u64 i = 0; i < nT; i++)
        T.mIsActive[i] = (u8)1;

    std::string comparisionString = "TestString";
    std::string comparisionString1 = "dfgdfggds";

    for (u64 i = 0; i < nT; ++i)
    {
        T.mColumns[0].mData.mData(i, 0) = -1 * (i % 3);
        T.mColumns[1].mData.mData(i, 0) = i % 4;
        T.mColumns[2].mData.mData(i, 0) = i % 4;
        T.mColumns[3].mData.mData(i, 0) = -1 * (i % 5);
        if (i % 3 == 0)
            memcpy(T.mColumns[4].mData.data(i), comparisionString.data(), comparisionString.size());
        else
            memcpy(T.mColumns[4].mData.data(i), comparisionString1.data(), comparisionString1.size());
        if (i % 4 == 0)
            memcpy(T.mColumns[5].mData.data(i), comparisionString.data(), comparisionString.size());
    }

    std::vector<std::string> literals = { "T0", "T1", "T2", "T3", "T4", "T5", comparisionString,
        "1", "-4" };
    std::vector<std::string> literalsType = { WHBUNDLE_COL_TYPE, WHBUNDLE_COL_TYPE, WHBUNDLE_COL_TYPE,
        WHBUNDLE_COL_TYPE, WHBUNDLE_COL_TYPE, WHBUNDLE_COL_TYPE, WHBUNDLE_STRING_TYPE,
        WHBUNDLE_NUM_TYPE, WHBUNDLE_NUM_TYPE };

    std::unordered_map<u64, u64> map;
    for (oc::u64 i = 0; i < T.cols(); i++)
        map[i] = i;

    std::vector<std::array<u64, 2>> inIdxs = { {2, 3}, {0, 1}, {0, 3}, {3, 0}, {4, 5},  //};
        {8, 3}, {1, 7}, {4, 6} };

    for (u64 i = 0; i < inIdxs.size(); i++)
    {
        u64 inIdx1 = inIdxs[i][0], inIdx2 = inIdxs[i][1];
        ArrGate gate(ArrGateType::LESS_THAN, inIdx1, inIdx2, literals.size());

        evalWhGate(T, {gate}, literals, literalsType, map, printSteps, mock);
    }
}

void Where_ArrType_Equals_Test(const oc::CLP& cmd)
{
    u64 nT = cmd.getOr("nT", 10);
    bool printSteps = cmd.isSet("print");
    bool mock = !cmd.isSet("noMock");
    Table T;

    T.init(nT, { {
        {"T0", TypeID::IntID, 16},
        {"T1", TypeID::IntID, 16},
        {"T2", TypeID::IntID, 8},
        {"T3", TypeID::IntID, 8},
        {"T4", TypeID::StringID, 128},
        {"T5", TypeID::StringID, 96}
    } });

    T.mIsActive.resize(nT);
    for (u64 i = 0; i < nT; i++)
        T.mIsActive[i] = (u8)1;

    std::string comparisionString = "TestString";
    std::string comparisionString1 = "ldetbjfejb";
    for (u64 i = 0; i < nT; ++i)
    {
        T.mColumns[0].mData.mData(i, 0) = -1 * (i % 3);
        T.mColumns[1].mData.mData(i, 0) = i % 4;
        T.mColumns[2].mData.mData(i, 0) = i % 4;
        T.mColumns[3].mData.mData(i, 0) = -1 * (i % 5);
        if (i % 3 == 0)
            memcpy(T.mColumns[4].mData.data(i), comparisionString.data(), comparisionString.size());
        else
            memcpy(T.mColumns[4].mData.data(i), comparisionString1.data(), comparisionString1.size());
        if (i % 4 == 0)
            memcpy(T.mColumns[5].mData.data(i), comparisionString.data(), comparisionString.size());
    }

    std::vector<std::string> literals = { "T0", "T1", "T2", "T3", "T4", "T5", comparisionString,
        "1", "-4" };
    std::vector<std::string> literalsType = { WHBUNDLE_COL_TYPE, WHBUNDLE_COL_TYPE, WHBUNDLE_COL_TYPE,
        WHBUNDLE_COL_TYPE, WHBUNDLE_COL_TYPE, WHBUNDLE_COL_TYPE, WHBUNDLE_STRING_TYPE,
        WHBUNDLE_NUM_TYPE, WHBUNDLE_NUM_TYPE };

    std::unordered_map<u64, u64> map;
    for (oc::u64 i = 0; i < T.cols(); i++)
        map[i] = i;

    // Test Case doesn't cover the InterInt comparision
    std::vector<std::array<u64, 2>> inIdxs = { {4, 5}, {1, 2}, {1, 3}, {1, 7}, {3, 8}, {4, 6} };

    for (u64 i = 0; i < inIdxs.size(); i++)
    {
        u64 inIdx1 = inIdxs[i][0], inIdx2 = inIdxs[i][1];
        ArrGate gate(ArrGateType::EQUALS, inIdx1, inIdx2, literals.size());
        evalWhGate(T, {gate}, literals, literalsType, map, printSteps, mock);
    }
}

void Where_ArrType_Not_Equals_Test(const oc::CLP& cmd)
{
    u64 nT = cmd.getOr("nT", 10);
    bool printSteps = cmd.isSet("print");
    bool mock = !cmd.isSet("noMock");
    Table T;

    T.init(nT, { {
        {"T0", TypeID::IntID, 16},
        {"T1", TypeID::IntID, 16},
        {"T2", TypeID::IntID, 8},
        {"T3", TypeID::IntID, 8},
        {"T4", TypeID::StringID, 128},
        {"T5", TypeID::StringID, 96}
    } });

    T.mIsActive.resize(nT);
    for (u64 i = 0; i < nT; i++)
        T.mIsActive[i] = (u8)1;

    std::string comparisionString = "TestString";
    std::string comparisionString1 = "ldetbjfejb";
    for (u64 i = 0; i < nT; ++i)
    {
        T.mColumns[0].mData.mData(i, 0) = -1 * (i % 3);
        T.mColumns[1].mData.mData(i, 0) = i % 4;
        T.mColumns[2].mData.mData(i, 0) = i % 4;
        T.mColumns[3].mData.mData(i, 0) = -1 * (i % 5);
        if (i % 3 == 0)
            memcpy(T.mColumns[4].mData.data(i), comparisionString.data(), comparisionString.size());
        else
            memcpy(T.mColumns[4].mData.data(i), comparisionString1.data(), comparisionString1.size());
        if (i % 4 == 0)
            memcpy(T.mColumns[5].mData.data(i), comparisionString.data(), comparisionString.size());
    }

    std::vector<std::string> literals = { "T0", "T1", "T2", "T3", "T4", "T5", comparisionString,
        "1", "-4" };
    std::vector<std::string> literalsType = { WHBUNDLE_COL_TYPE, WHBUNDLE_COL_TYPE, WHBUNDLE_COL_TYPE,
        WHBUNDLE_COL_TYPE, WHBUNDLE_COL_TYPE, WHBUNDLE_COL_TYPE, WHBUNDLE_STRING_TYPE,
        WHBUNDLE_NUM_TYPE, WHBUNDLE_NUM_TYPE };

    std::unordered_map<u64, u64> map;
    for (oc::u64 i = 0; i < T.cols(); i++)
        map[i] = i;

    // Test Case doesn't cover the InterInt comparision
    std::vector<std::array<u64, 2>> inIdxs = { {4, 5}, {1, 2}, {1, 3}, {1, 7}, {3, 8}, {4, 6} };

    for (u64 i = 0; i < inIdxs.size(); i++)
    {
        u64 inIdx1 = inIdxs[i][0], inIdx2 = inIdxs[i][1];
        ArrGate gate(ArrGateType::NOT_EQUALS, inIdx1, inIdx2, literals.size());

        evalWhGate(T, {gate}, literals, literalsType, map, printSteps, mock);
    }
}

void Where_Cross_ArrType_Test(const oc::CLP& cmd)
{
    u64 nT = cmd.getOr("nT", 10);
    bool printSteps = cmd.isSet("print");
    bool mock = !cmd.isSet("noMock");
    Table T;

    T.init(nT, { {
        {"T0", TypeID::IntID, 16},
        {"T1", TypeID::IntID, 16},
        {"T2", TypeID::IntID, 8},
        {"T3", TypeID::IntID, 8},
        {"T4", TypeID::StringID, 128},
        {"T5", TypeID::StringID, 96}
    } });

    T.mIsActive.resize(nT);
    for (u64 i = 0; i < nT; i++)
        T.mIsActive[i] = (u8)1;

    std::string comparisionString = "TestString";
    std::string comparisionString1 = "ldetbjfejb";
    for (u64 i = 0; i < nT; ++i)
    {
        T.mColumns[0].mData.mData(i, 0) = -1 * (i % 3);
        T.mColumns[1].mData.mData(i, 0) = i % 4;
        T.mColumns[2].mData.mData(i, 0) = i % 4;
        T.mColumns[3].mData.mData(i, 0) = -1 * (i % 5);
        if (i % 3 == 0)
            memcpy(T.mColumns[4].mData.data(i), comparisionString.data(), comparisionString.size());
        else
            memcpy(T.mColumns[4].mData.data(i), comparisionString1.data(), comparisionString1.size());
        if (i % 4 == 0)
            memcpy(T.mColumns[5].mData.data(i), comparisionString.data(), comparisionString.size());
    }

    std::vector<std::string> literals = { "T0", "T1", "T2", "T3", "T4", "T5", comparisionString,
        "1", "-4" };
    std::vector<std::string> literalsType = { WHBUNDLE_COL_TYPE, WHBUNDLE_COL_TYPE, WHBUNDLE_COL_TYPE,
        WHBUNDLE_COL_TYPE, WHBUNDLE_COL_TYPE, WHBUNDLE_COL_TYPE, WHBUNDLE_STRING_TYPE,
        WHBUNDLE_NUM_TYPE, WHBUNDLE_NUM_TYPE };

    std::unordered_map<u64, u64> map;
    for (oc::u64 i = 0; i < T.cols(); i++)
        map[i] = i;


    // Col1 < Col2 && Col3 == Const
    std::vector<ArrGate> gates1 = {
        {ArrGateType::LESS_THAN, 0, 1, 9} ,
        {ArrGateType::EQUALS, 0, 3, 10} ,
        {ArrGateType::AND, 9, 10, 11} };

    std::vector<std::vector<ArrGate>> gates = { gates1 };


    for (u64 i = 0; i < gates.size(); i++)
        evalWhGate(T, gates[i], literals, literalsType, map, printSteps, mock);
    
}
