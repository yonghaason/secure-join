

#############################################
#               Build secureJoin_Tests            #
#############################################


set(SRCS

	)
	

add_library(secureJoin_Tests ${SRCS})

target_link_libraries(secureJoin_Tests secureJoin)
