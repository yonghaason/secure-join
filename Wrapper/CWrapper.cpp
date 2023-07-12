#include "com_visa_secureml_wrapper_SecJoinWrapper.h"
#include "JNIExample.h"
#include "secure-join/Util/CSVParser.h"
#include "coproto/Socket/BufferingSocket.h"
#include "secure-join/Join/Table.h"
#include "secure-join/Join/OmJoin.h"

struct State
{
  std::vector<secJoin::ColumnInfo> mLColInfo, mRColInfo;
  secJoin::Table mLTable, mRTable, mShareTable, mOutTable;
  secJoin::ColRef* mLJoinCol, *mRJoinCol;
  std::vector<secJoin::ColRef> mSelectCols;
  oc::PRNG mPrng;
  secJoin::OmJoin mJoin;
  secJoin::OleGenerator mOle;
  coproto::BufferingSocket mSock;
  macoro::eager_task<void> mProtocol;
};



// JNIEXPORT void JNICALL Java_JNIExample_jointable
//   (JNIEnv *env, jobject obj, jstring csvPath, 
//    jstring metaDataPath, jstring joinCols, jstring selectCols, jint totalSelectCols)
//   {
//     std::string cppCSVPath = env->GetStringUTFChars(csvPath, NULL);
//     std::string cppMetaPath = env->GetStringUTFChars(metaDataPath, NULL);
//     std::string cppJoinCol = env->GetStringUTFChars(joinCols, NULL);

//     std::vector<secJoin::ColumnInfo> columnInfo;
//     oc::u64 rowCount = 0;
    
//     getFileInfo(cppMetaPath, columnInfo, rowCount);

//     secJoin::Table leftTable(rowCount, columnInfo);
//     populateTable(leftTable, cppCSVPath, rowCount);


//     secJoin::Table rightTable(rowCount, columnInfo);
//     // Need to check if the rightTable is initialized with 0(s)

//     // Constructing Select Cols
//     std::vector<secJoin::Table::ColRef> selects;
//     selects.reserve(totalSelectCols);

//     std::string word;
//     std::stringstream str(cppJoinCol);
//     while(getline(str, word, secJoin::CSV_COL_DELIM))
//     {
//         selects.emplace_back(leftTable[word]);
//     }



//     // Constructing Join Cols 
//     // Current Assumption is there is only one Join Columns
//     secJoin::Table::ColRef leftJoinCol = leftTable[cppJoinCol];
//     secJoin::Table::ColRef rightJoinCol = rightTable[cppJoinCol];

//     // Initialize a table with 0
    
    
//   }


JNIEXPORT jlong JNICALL Java_com_visa_secureml_wrapper_SecJoinWrapper_init
  (JNIEnv *env, jobject obj, jstring csvPath, jstring visaMetaDataPath, jstring clientMetaDataPath, 
  jstring joinVisaCols, jstring joinClientCols, jstring selectVisaCols, jstring selectClientCols, 
  jboolean isUnique)
{

    State *cState = new State;

    std::string cppCSVPath = env->GetStringUTFChars(csvPath, NULL);
    std::string cppVisaMetaDataPath = env->GetStringUTFChars(visaMetaDataPath, NULL);
    std::string cppClientMetaDataPath = env->GetStringUTFChars(clientMetaDataPath, NULL);
    std::string cppVisaJoinCols = env->GetStringUTFChars(joinVisaCols, NULL);
    std::string cppClientJoinCols = env->GetStringUTFChars(joinClientCols, NULL);
    std::string cppselectVisaCols = env->GetStringUTFChars(selectVisaCols, NULL);
    std::string cppselectClientCols = env->GetStringUTFChars(selectClientCols, NULL);

    oc::u64 lRowCount = 0, rRowCount = 0;


    // Current assumption are that Visa always provides table with unique keys 
    // Which means Visa always has to be left Table
    getFileInfo(cppVisaMetaDataPath, cState->mLColInfo, lRowCount);
    getFileInfo(cppClientMetaDataPath, cState->mRColInfo, rRowCount);
    cState->mLTable.init(lRowCount, cState->mLColInfo);
    cState->mRTable.init(rRowCount, cState->mRColInfo);
    if(isUnique)
      populateTable(cState->mLTable, cppCSVPath, lRowCount);
    else
      populateTable(cState->mRTable, cppCSVPath, rRowCount);
    
    
    // Current Assumptions is that there is only one Join Columns
    auto mLJoinCol = cState->mLTable[cppVisaJoinCols];
    auto mRJoinCol = cState->mRTable[cppClientJoinCols];
    cState->mLJoinCol = &mLJoinCol;
    cState->mRJoinCol = &mRJoinCol;

    // Constructing Select Cols
    std::string word;
    std::stringstream visaStr(std::move(cppselectVisaCols));
    while(getline(visaStr, word, ','))
    {
        cState->mSelectCols.emplace_back(cState->mLTable[word]);
    }

    std::stringstream clientStr(std::move(cppselectClientCols));
    while(getline(clientStr, word, ','))
    {
        cState->mSelectCols.emplace_back(cState->mRTable[word]);
    }
    
    // Initializing the join protocol
    cState->mPrng.SetSeed(oc::ZeroBlock);
    cState->mJoin.mDebug = false;
    cState->mJoin.mInsecureMock = false;

    // Current assumption are that Visa always provides table with unique keys 
    // Which means Visa always has to be left Table
    if(isUnique)
      cState->mOle.fakeInit(secJoin::OleGenerator::Role::Sender);
    else
      cState->mOle.fakeInit(secJoin::OleGenerator::Role::Receiver);


    cState->mProtocol = 
         cState->mJoin.join( *(cState->mLJoinCol), *(cState->mRJoinCol), cState->mSelectCols, 
                cState->mShareTable, cState->mPrng, cState->mOle, cState->mSock) | macoro::make_eager();

    return (long) cState;

}

  JNIEXPORT jbyteArray JNICALL Java_com_visa_secureml_wrapper_SecJoinWrapper_runJoin
  (JNIEnv *env, jobject obj, jlong stateAddress,jbyteArray data, jlong dataSize)
  {

    // Get elements of the array
    jbyte *elements = env->GetByteArrayElements(data, 0);

    std::vector<oc::u8> buff(dataSize);
    memcpy(buff.data(),elements,dataSize);
    
    void *state = (void *) stateAddress;
	
    State* cState = (State*)state;

    cState->mSock.processInbound(buff);

    auto b = cState->mSock.getOutbound();

    std::cout << "In the C code, the size of byte array is " << b->size() << "\n" ;

    jbyteArray byteArray = (*env).NewByteArray( b->size());
    (*env).SetByteArrayRegion(byteArray, 0,  b->size(), reinterpret_cast<const signed char*>(b->data()));

    return byteArray;
    
  }



JNIEXPORT void JNICALL Java_com_visa_secureml_wrapper_SecJoinWrapper_releaseState
  (JNIEnv *env, jobject obj, jlong memoryAddress)
  {
    std::cout << "Releasing Memory" << "\n" ;
    void *state = (void *) memoryAddress;
    delete (State*) state;
  }


  JNIEXPORT jboolean JNICALL Java_com_visa_secureml_wrapper_SecJoinWrapper_isProtocolReady
  (JNIEnv *env, jobject obj, jlong stateAddress)
  {
    void *state = (void *) stateAddress;

    State* cState = (State*)state;
    return cState->mProtocol.is_ready();
    
  }

JNIEXPORT void JNICALL Java_com_visa_secureml_wrapper_SecJoinWrapper_getOtherShare
  (JNIEnv *env, jobject obj, jlong stateAddress, jboolean isUnique)
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


// Need a method to print the share into a file 
JNIEXPORT void JNICALL Java_com_visa_secureml_wrapper_SecJoinWrapper_getJoinTable
  (JNIEnv *env, jobject obj, jlong stateAddress, jstring csvPath,
  jstring metaDataPath, jboolean isUnique)
  {

    void *state = (void *) stateAddress;
    State* cState = (State*)state;

    std::string cppCSVPath = env->GetStringUTFChars(csvPath, NULL);
    std::string cppMetaPath = env->GetStringUTFChars(metaDataPath, NULL);

    writeFileInfo(cppMetaPath, cState->mOutTable);
    writeFileData(cppCSVPath, cState->mOutTable);
  }