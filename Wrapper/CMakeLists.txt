
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

if(SECUREJOIN_STATIC_WRAPPER)
	add_library(WrapperSecJoin STATIC ${SRCS})
else()
	add_library(WrapperSecJoin SHARED ${SRCS})
endif()

configure_file(config.h.in "config.h" )

if(SECUREJOIN_ENABLE_JNI)
	target_include_directories(WrapperSecJoin PUBLIC $ENV{JAVA_HOME}/include $ENV{JAVA_HOME}/include/darwin)
endif()
target_link_libraries(WrapperSecJoin secureJoin)