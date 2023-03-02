cmake_minimum_required (VERSION 3.15)

project(secureJoin VERSION 0.1.0)

set(SECUREJOIN_BUILD ON)

# sets some variables
include(cmake/preamble.cmake)

# sets build option
include(cmake/buildOptions.cmake)

# find all the dependancies.
include(cmake/findDependancies.cmake)

if(SECUREJOIN_ENABLE_PAILLIER)
	add_subdirectory(Paillier)
endif()

# build volePSI
add_subdirectory(secure-join)


# build the tests.
add_subdirectory(tests)

# link the executable.
add_subdirectory(frontend)

# setup the install
include(cmake/install.cmake)