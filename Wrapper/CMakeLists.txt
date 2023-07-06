file(GLOB_RECURSE SRCS *.cpp)

add_library(WrapperSecJoin SHARED ${SRCS})

target_include_directories(WrapperSecJoin PUBLIC $ENV{JAVA_HOME}/include $ENV{JAVA_HOME}/include/darwin)

target_link_libraries(WrapperSecJoin secureJoin)