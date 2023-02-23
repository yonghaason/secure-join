

#############################################
#               Build secureJoin_Tests            #
#############################################

file(GLOB_RECURSE SRCS *.cpp)

#[[
file(GLOB_RECURSE SRCS *.cpp)
set(SRCS *.h) 
set(SRCS
	UnitTests.cpp
	PaillierPerm_Test.cpp
	LowMCPerm_Test.cpp
	)
]]
	

add_library(secureJoin_Tests ${SRCS})

target_link_libraries(secureJoin_Tests secureJoin)
