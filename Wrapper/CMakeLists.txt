
#############################################
#               Build secureJoin_wrapper    #
#############################################

set(SRCS
	CppWrapper.cpp
	)
if(SECUREJOIN_ENABLE_JNI)
	set(SRCS
		JniWrapper.cpp
		${SRCS}
	)
endif()

add_library(WrapperSecJoin SHARED ${SRCS})

configure_file(config.h.in "config.h" )

target_include_directories(WrapperSecJoin PUBLIC $ENV{JAVA_HOME}/include $ENV{JAVA_HOME}/include/darwin)
target_link_libraries(WrapperSecJoin secureJoin)