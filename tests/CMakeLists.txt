

#############################################
#               Build secureJoin_Tests            #
#############################################

set(SRCS
	UnitTests.cpp
	LowMCPerm_Test.cpp
	SharePerm_Test.cpp
	PaillierPerm_Test.cpp
	DarkMatterPrf_Test.cpp
	)

	
add_library(secureJoin_Tests ${SRCS})

target_link_libraries(secureJoin_Tests secureJoin)
