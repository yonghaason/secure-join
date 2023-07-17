

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
	DlpnPerm_Test.cpp
	CSVParser_Test.cpp
	OmJoin_Test.cpp
	CWrapper_Test.cpp
	)

	
add_library(secureJoin_Tests ${SRCS})

if(SECUREJOIN_ENABLE_WRAPPER)
	target_link_libraries(secureJoin_Tests WrapperSecJoin)
endif()

target_link_libraries(secureJoin_Tests secureJoin)
