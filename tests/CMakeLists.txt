

#############################################
#               Build secureJoin_Tests            #
#############################################


set(SRCS
	UnitTests.cpp
	)
	

add_library(secureJoin_Tests ${SRCS})

target_link_libraries(secureJoin_Tests secureJoin)
