

#############################################
#               Build secureJoin_Tests            #
#############################################

set(SRCS
	UnitTests.cpp
	LowMCPerm_Test.cpp
	ComposedPerm_Test.cpp
	PaillierPerm_Test.cpp
	AdditivePerm_Test.cpp
	DarkMatterPrf_Test.cpp
	OleGenerator_Test.cpp
	GMW_Test.cpp
	RadixSort_Test.cpp
	AggTree_Tests.cpp
	)

	
add_library(secureJoin_Tests ${SRCS})

target_link_libraries(secureJoin_Tests secureJoin)
