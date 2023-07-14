#include "CWrapper.h"
// #include "nonstd/optional.hpp"

extern "C"
{
    struct State
    {
    std::vector<secJoin::ColumnInfo> mLColInfo, mRColInfo;
    secJoin::Table mLTable, mRTable, mShareTable, mOutTable;
    oc::PRNG mPrng;
    secJoin::OmJoin mJoin;
    secJoin::OleGenerator mOle;
    coproto::BufferingSocket mSock;
    macoro::eager_task<void> mProtocol;
    };

    void testApi(std::string& str)
    {
        std::cout << str << std::endl;
    }

    long initState(std::string& csvPath, std::string& visaMetaDataPath, std::string& clientMetaDataPath, 
                std::string& visaJoinCols, std::string& clientJoinCols, std::string& selectVisaCols,
                std::string& selectClientCols, bool isUnique)
    {
        State *cState = new State;
        oc::u64 lRowCount = 0, rRowCount = 0;


        // Current assumption are that Visa always provides table with unique keys 
        // Which means Visa always has to be left Table
        getFileInfo(visaMetaDataPath, cState->mLColInfo, lRowCount);
        getFileInfo(clientMetaDataPath, cState->mRColInfo, rRowCount);
        cState->mLTable.init(lRowCount, cState->mLColInfo);
        cState->mRTable.init(rRowCount, cState->mRColInfo);
        if(isUnique)
        populateTable(cState->mLTable, csvPath, lRowCount);
        else
        populateTable(cState->mRTable, csvPath, rRowCount);
        
        
        // Current Assumptions is that there is only one Join Columns
        auto lJoinCol = cState->mLTable[visaJoinCols];
        auto rJoinCol = cState->mRTable[clientJoinCols];

        // Constructing Select Cols
        std::vector<secJoin::ColRef> selectCols;
        std::string word;
        std::stringstream visaStr(std::move(selectVisaCols));
        while(getline(visaStr, word, ','))
        {
            selectCols.emplace_back(cState->mLTable[word]);
        }

        std::stringstream clientStr(std::move(selectClientCols));
        while(getline(clientStr, word, ','))
        {
            selectCols.emplace_back(cState->mRTable[word]);
        }
        
        // Initializing the join protocol
        cState->mPrng.SetSeed(oc::ZeroBlock); // Make Change
        cState->mJoin.mInsecurePrint = true;
        cState->mJoin.mInsecureMockSubroutines = true;

        // Current assumption are that Visa always provides table with unique keys 
        // Which means Visa always has to be left Table
        if(isUnique)
        cState->mOle.fakeInit(secJoin::OleGenerator::Role::Sender);
        else
        cState->mOle.fakeInit(secJoin::OleGenerator::Role::Receiver);


        cState->mProtocol = 
            cState->mJoin.join( lJoinCol, rJoinCol, selectCols, 
                    cState->mShareTable, cState->mPrng, cState->mOle, cState->mSock) | macoro::make_eager();

        return (long) cState;

    }

//  optional<std::vector<oc::u8>>
    std::vector<oc::u8> runJoin(long stateAddress, std::vector<oc::u8>& buff)
    {

        void *state = (void *) stateAddress;
        
        State* cState = (State*)state;

        cState->mSock.processInbound(buff);

        auto b = cState->mSock.getOutbound();

        std::cout << "In the C code, the size of byte array is " << b->size() << std::endl ;

        return b.value();
    
    }

    void releaseState(long memoryAddress)
    {
        std::cout << "Releasing Memory" << std::endl;
        void *state = (void *) memoryAddress;
        delete (State*) state;
    }

    bool isProtocolReady(long stateAddress)
    {
        void *state = (void *) stateAddress;
        State* cState = (State*)state;
        return cState->mProtocol.is_ready();
    }

    void getOtherShare(long stateAddress, bool isUnique)
    {
        void *state = (void *) stateAddress;
        State* cState = (State*)state;
        // Assuming Visa always receives the client's share
        if(isUnique)
        {
        cState->mProtocol = revealLocal(cState->mShareTable, cState->mSock, cState->mOutTable)
                            | macoro::make_eager();
        }
        else
        {
        cState->mProtocol =  revealRemote(cState->mShareTable, cState->mSock)
                            | macoro::make_eager();
        }
    }

    void getJoinTable(long stateAddress, std::string csvPath, std::string metaDataPath, bool isUnique)
    {
        void *state = (void *) stateAddress;
        State* cState = (State*)state;

        writeFileInfo(metaDataPath, cState->mOutTable);
        writeFileData(csvPath, cState->mOutTable);
    }
}