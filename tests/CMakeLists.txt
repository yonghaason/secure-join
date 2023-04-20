

#############################################
#               Build secureJoin_Tests            #
#############################################

set(SRCS
	UnitTests.cpp
	LowMCPerm_Test.cpp
	SharedPerm_Test.cpp
	PaillierPerm_Test.cpp
	VectorPerm_Test.cpp
	DarkMatterPrf_Test.cpp
	OleGenerator_Test.cpp
	GMW_Test.cpp
	RadixSort_Test.cpp
	)

	
add_library(secureJoin_Tests ${SRCS})

target_link_libraries(secureJoin_Tests secureJoin)
