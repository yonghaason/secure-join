
#############################################
#               Build secureJoin_wrapper    #
#############################################

set(SRCS
	CWrapper.cpp
	JniWrapper.cpp
	)

add_library(WrapperSecJoin SHARED ${SRCS})

target_include_directories(WrapperSecJoin PUBLIC $ENV{JAVA_HOME}/include $ENV{JAVA_HOME}/include/darwin)
target_link_libraries(WrapperSecJoin secureJoin)