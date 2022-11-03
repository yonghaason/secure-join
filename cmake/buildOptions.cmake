
macro(EVAL var)
     if(${ARGN})
         set(${var} ON)
     else()
         set(${var} OFF)
     endif()
endmacro()

option(FETCH_AUTO      "automaticly download and build dependancies" OFF)
option(VERBOSE_FETCH    "Verbose fetch" ON)


#option(FETCH_LIBOTE		"download and build libOTe" OFF))
EVAL(FETCH_LIBOTE_AUTO 
	(DEFINED FETCH_LIBOTE AND FETCH_LIBOTE) OR
	((NOT DEFINED FETCH_LIBOTE) AND (FETCH_AUTO)))


message(STATUS "vole-psi options\n=======================================================")

message(STATUS "Option: FETCH_AUTO        = ${FETCH_AUTO}")
message(STATUS "Option: FETCH_LIBOTE      = ${FETCH_LIBOTE}")
message(STATUS "Option: VERBOSE_FETCH     = ${VERBOSE_FETCH}")



set(SECUREJOIN_CPP_VER 17)