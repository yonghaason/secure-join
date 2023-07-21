#include "com_visa_secureml_wrapper_SecJoinWrapper.h"
#include "CppWrapper.h"


// #ifndef SECUREJOIN_ENABLE_JNI
// static_assert(1, "SECUREJOIN_ENABLE_JNI not defined");
// #endif

JNIEXPORT void JNICALL Java_com_visa_secureml_wrapper_SecJoinWrapper_testApi
(JNIEnv* env, jobject obj)
{
  std::string temp("Hello Word");
  secJoin::testApi(temp);
}

JNIEXPORT jlong JNICALL Java_com_visa_secureml_wrapper_SecJoinWrapper_initState
(JNIEnv* env, jobject obj, jstring csvPath, jstring visaMetaDataPath, jstring clientMetaDataPath,
  jstring joinVisaCols, jstring joinClientCols, jstring selectVisaCols, jstring selectClientCols,
  jboolean isUnique, jboolean verbose, jboolean mock, jboolean debug)
{
  std::string cppCSVPath = env->GetStringUTFChars(csvPath, NULL);
  std::string cppVisaMetaDataPath = env->GetStringUTFChars(visaMetaDataPath, NULL);
  std::string cppClientMetaDataPath = env->GetStringUTFChars(clientMetaDataPath, NULL);
  std::string cppVisaJoinCols = env->GetStringUTFChars(joinVisaCols, NULL);
  std::string cppClientJoinCols = env->GetStringUTFChars(joinClientCols, NULL);
  std::string cppselectVisaCols = env->GetStringUTFChars(selectVisaCols, NULL);
  std::string cppselectClientCols = env->GetStringUTFChars(selectClientCols, NULL);

  static_assert(sizeof(jlong) == sizeof(secJoin::State*), "jlong must be pointer size");
  return (jlong)secJoin::initState(cppCSVPath, cppVisaMetaDataPath, cppClientMetaDataPath, cppVisaJoinCols,
    cppClientJoinCols, cppselectVisaCols, cppselectClientCols, isUnique, verbose, mock, debug);

}

JNIEXPORT jbyteArray JNICALL Java_com_visa_secureml_wrapper_SecJoinWrapper_runJoin
(JNIEnv* env, jobject obj, jlong stateAddress, jbyteArray data, jlong dataSize)
{

  // Get elements of the array
  jbyte* elements = env->GetByteArrayElements(data, 0);

  std::vector<oc::u8> buff(dataSize);
  memcpy(buff.data(), elements, dataSize);

  auto b = secJoin::runJoin((secJoin::State*)stateAddress, buff);

  jbyteArray byteArray = (*env).NewByteArray(b.size());
  (*env).SetByteArrayRegion(byteArray, 0, b.size(), reinterpret_cast<const signed char*>(b.data()));
  std::cout << "In the C code, the size of byte array is " << b.size() << std::endl;
  return byteArray;
}



JNIEXPORT void JNICALL Java_com_visa_secureml_wrapper_SecJoinWrapper_releaseState
(JNIEnv* env, jobject obj, jlong memoryAddress)
{
  secJoin::releaseState((secJoin::State*)memoryAddress);
}


JNIEXPORT jboolean JNICALL Java_com_visa_secureml_wrapper_SecJoinWrapper_isProtocolReady
(JNIEnv* env, jobject obj, jlong stateAddress)
{

  return secJoin::isProtocolReady((secJoin::State*)stateAddress);
}

JNIEXPORT void JNICALL Java_com_visa_secureml_wrapper_SecJoinWrapper_getOtherShare
(JNIEnv* env, jobject obj, jlong stateAddress, jboolean isUnique)
{
  secJoin::getOtherShare((secJoin::State*)stateAddress, isUnique);
}


// Need a method to print the share into a file 
JNIEXPORT void JNICALL Java_com_visa_secureml_wrapper_SecJoinWrapper_getJoinTable
(JNIEnv* env, jobject obj, jlong stateAddress, jstring csvPath,
  jstring metaDataPath, jboolean isUnique)
{

  std::string cppCSVPath = env->GetStringUTFChars(csvPath, NULL);
  std::string cppMetaPath = env->GetStringUTFChars(metaDataPath, NULL);

  secJoin::getJoinTable((secJoin::State*)stateAddress, cppCSVPath, cppMetaPath, isUnique);
}