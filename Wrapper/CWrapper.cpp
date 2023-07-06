#include "com_visa_secureml_wrapper_SecJoinWrapper.h"
// #include "SecJoinWrapper.h"
#include "JNIExample.h"
#include "secure-join/CSVParser.h"
#include "coproto/Socket/BufferingSocket.h"
#include "secure-join/Table.h"

struct State
{
  secJoin::Table mleftTable; 
  secJoin::Table mrightTable; 
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
  (JNIEnv *env, jobject obj, jstring csvPath, 
   jstring metaDataPath, jstring joinCols, jstring selectCols, jint totalSelectCols)
{

    State *cState = new State;

    std::string cppCSVPath = env->GetStringUTFChars(csvPath, NULL);
    std::string cppMetaPath = env->GetStringUTFChars(metaDataPath, NULL);
    std::string cppJoinCol = env->GetStringUTFChars(joinCols, NULL);

    std::vector<secJoin::ColumnInfo> columnInfo;
    oc::u64 rowCount = 0;
    
    getFileInfo(cppMetaPath, columnInfo, rowCount);

    secJoin::Table leftTable(rowCount, columnInfo);
    populateTable(leftTable, cppCSVPath, rowCount);


    secJoin::Table rightTable(rowCount, columnInfo);

    // Constructing Select Cols
    std::vector<secJoin::Table::ColRef> selects;
    selects.reserve(totalSelectCols);

    std::string word;
    std::stringstream str(cppJoinCol);
    while(getline(str, word, secJoin::CSV_COL_DELIM))
    {
        selects.emplace_back(leftTable[word]);
    }


    // Constructing Join Cols 
    // Current Assumption is there is only one Join Columns
    secJoin::Table::ColRef leftJoinCol = leftTable[cppJoinCol];
    secJoin::Table::ColRef rightJoinCol = rightTable[cppJoinCol];
    

    // Call the join method

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

JNIEXPORT void JNICALL Java_com_visa_secureml_wrapper_SecJoinWrapper_getIntersection
  (JNIEnv *env, jobject obj, jlong stateAddress, jstring csvPath, 
    jstring metaDataPath)
{
    void *state = (void *) stateAddress;
    State* cState = (State*)state;

    std::string cppCSVPath = env->GetStringUTFChars(csvPath, NULL);
    std::string cppMetaPath = env->GetStringUTFChars(metaDataPath, NULL);
  

}
