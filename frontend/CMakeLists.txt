
set( SRCS main.cpp)

add_executable(frontend  ${SRCS})

target_link_libraries(frontend secureJoin_Tests)
