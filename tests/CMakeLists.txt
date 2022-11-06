

#############################################
#               Build secureJoin_Tests            #
#############################################


set(SRCS
	UnitTests.cpp
	PaillierPerm_Test.cpp
	)
	

add_library(secureJoin_Tests ${SRCS})

target_link_libraries(secureJoin_Tests secureJoin)
