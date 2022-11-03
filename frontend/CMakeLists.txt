
file(GLOB_RECURSE SRCS *.cpp)

add_executable(frontend  ${SRCS})

target_link_libraries(frontend secureJoin_Tests)


if(VOLE_PSI_NO_LTO)
    target_link_options(frontend PUBLIC "-fno-lto")
endif()