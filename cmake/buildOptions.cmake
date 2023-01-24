
macro(EVAL var)
     if(${ARGN})
         set(${var} ON)
     else()
         set(${var} OFF)
     endif()
endmacro()

option(FETCH_AUTO      "automaticly download and build dependancies" OFF)
option(VERBOSE_FETCH    "Verbose fetch" ON)
option(ENABLE_ASAN    "Enable Asan" OFF)


#option(FETCH_LIBOTE		"download and build libOTe" OFF))
EVAL(FETCH_LIBOTE_AUTO 
	(DEFINED FETCH_LIBOTE AND FETCH_LIBOTE) OR
	((NOT DEFINED FETCH_LIBOTE) AND (FETCH_AUTO)))


message(STATUS "secure-join options\n=======================================================")

message(STATUS "Option: FETCH_AUTO        = ${FETCH_AUTO}")
message(STATUS "Option: FETCH_LIBOTE      = ${FETCH_LIBOTE}")
message(STATUS "Option: VERBOSE_FETCH     = ${VERBOSE_FETCH}")
message(STATUS "Option: ENABLE_ASAN       = ${ENABLE_ASAN}")



set(SECUREJOIN_CPP_VER 17)