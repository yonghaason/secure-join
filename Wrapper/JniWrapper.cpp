#include "com_visa_secureml_wrapper_SecJoinWrapper.h"
#include "CppWrapper.h"
// #include "state.h"

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
  jobjectArray jliterals, jobjectArray jlitTypes, jintArray jintArr, jboolean isUnique, 
  jboolean verbose, jboolean mock, jboolean remDummies)
{
  std::string cppCSVPath = env->GetStringUTFChars(csvPath, NULL);
  std::string cppVisaMetaDataPath = env->GetStringUTFChars(visaMetaDataPath, NULL);
  std::string cppClientMetaDataPath = env->GetStringUTFChars(clientMetaDataPath, NULL);

  // Getting Literals 
  // Code Reference https://stackoverflow.com/questions/19591873/get-an-array-of-strings-from-java-to-c-jni
  std::vector<std::string> literals, literalsType;

  // Get length
  int len1 = env->GetArrayLength(jliterals);
  int len2 = env->GetArrayLength(jlitTypes);

  assert(len1 == len2);

  for (int i=0; i<len1; i++) {
      // Cast array element to string
      jstring jstr1 = (jstring) (env->GetObjectArrayElement(jliterals, i));
      jstring jstr2 = (jstring) (env->GetObjectArrayElement(jlitTypes, i));

      // Convert Java string to std::string
      const jsize strLen1 = env->GetStringUTFLength(jstr1);
      const char *charBuffer1 = env->GetStringUTFChars(jstr1, (jboolean *) 0);
      std::string str1(charBuffer1, strLen1);
      const jsize strLen2 = env->GetStringUTFLength(jstr2);
      const char *charBuffer2 = env->GetStringUTFChars(jstr2, (jboolean *) 0);
      std::string str2(charBuffer2, strLen2);


      // Push back string to vector
      literals.push_back(str1);
      literalsType.push_back(str2);

      // Release memory
      env->ReleaseStringUTFChars(jstr1, charBuffer1);
      env->DeleteLocalRef(jstr1);
      env->ReleaseStringUTFChars(jstr2, charBuffer2);
      env->DeleteLocalRef(jstr2);
  }
  
  // Getting the opInfo
  int len = env->GetArrayLength(jintArr);
  jint *ptr = env->GetIntArrayElements(jintArr, 0);
  std::vector<oc::i64> opInfo(ptr, ptr + len);

  static_assert(sizeof(jlong) == sizeof(secJoin::WrapperState*), "jlong must be pointer size");
  return (jlong)secJoin::initState(cppCSVPath, cppVisaMetaDataPath, cppClientMetaDataPath, literals,
     literalsType, opInfo, isUnique, verbose, mock, remDummies);
}

JNIEXPORT jbyteArray JNICALL Java_com_visa_secureml_wrapper_SecJoinWrapper_runProtocol
(JNIEnv* env, jobject obj, jlong stateAddress, jbyteArray data, jlong dataSize)
{

  // Get elements of the array
  jbyte* elements = env->GetByteArrayElements(data, 0);

  std::vector<oc::u8> buff(dataSize);
  memcpy(buff.data(), elements, dataSize);

  auto b = secJoin::runProtocol((secJoin::WrapperState*)stateAddress, buff);

  jbyteArray byteArray = (*env).NewByteArray(b.size());
  (*env).SetByteArrayRegion(byteArray, 0, b.size(), reinterpret_cast<const signed char*>(b.data()));
  // std::cout << "In the C code, the size of byte array is " << b.size() << std::endl;
  return byteArray;
}



JNIEXPORT void JNICALL Java_com_visa_secureml_wrapper_SecJoinWrapper_releaseState
(JNIEnv* env, jobject obj, jlong memoryAddress)
{
  secJoin::releaseState((secJoin::WrapperState*)memoryAddress);
}


JNIEXPORT jboolean JNICALL Java_com_visa_secureml_wrapper_SecJoinWrapper_isProtocolReady
(JNIEnv* env, jobject obj, jlong stateAddress)
{

  return secJoin::isProtocolReady((secJoin::WrapperState*)stateAddress);
}

JNIEXPORT void JNICALL Java_com_visa_secureml_wrapper_SecJoinWrapper_getOtherShare
(JNIEnv* env, jobject obj, jlong stateAddress, jboolean isUnique)
{
  secJoin::getOtherShare((secJoin::WrapperState*)stateAddress, isUnique);
}



JNIEXPORT void JNICALL Java_com_visa_secureml_wrapper_SecJoinWrapper_getJoinTable
(JNIEnv* env, jobject obj, jlong stateAddress, jstring csvPath,
  jstring metaDataPath, jboolean isUnique)
{

  std::string cppCSVPath = env->GetStringUTFChars(csvPath, NULL);
  std::string cppMetaPath = env->GetStringUTFChars(metaDataPath, NULL);

  secJoin::getJoinTable((secJoin::WrapperState*)stateAddress, cppCSVPath, cppMetaPath, isUnique);
}


JNIEXPORT void JNICALL Java_com_visa_secureml_wrapper_SecJoinWrapper_aggFunc
(JNIEnv* env, jobject obj, jlong stateAddress)
{
  secJoin::aggFunc((secJoin::WrapperState*)stateAddress);
}

JNIEXPORT void JNICALL Java_com_visa_secureml_wrapper_SecJoinWrapper_whereFunc
  (JNIEnv* env, jobject obj, jlong stateAddress)
  {
    secJoin::whereFunc((secJoin::WrapperState*)stateAddress);
  }