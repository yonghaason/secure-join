cmake_minimum_required (VERSION 3.15)

project(volePSI VERSION 0.1.0)

set(SECUREJOIN_BUILD ON)

# sets some variables
include(cmake/preamble.cmake)

# sets build option
include(cmake/buildOptions.cmake)

# find all the dependancies.
include(cmake/findDependancies.cmake)

add_subdirectory(Paillier)

# build volePSI
add_subdirectory(secure-join)


# build the tests.
add_subdirectory(tests)

# link the executable.
add_subdirectory(frontend)

# setup the install
include(cmake/install.cmake)