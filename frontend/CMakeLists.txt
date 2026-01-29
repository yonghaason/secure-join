set(SRCS
  main.cpp
  benchmark.cpp
)

add_executable(secJoinfrontend ${SRCS})

# OpenSSL
find_package(OpenSSL REQUIRED)
target_link_libraries(secJoinfrontend PRIVATE OpenSSL::Crypto)

# OpenMP
find_package(OpenMP REQUIRED)
target_link_libraries(secJoinfrontend PRIVATE OpenMP::OpenMP_CXX)

# ⬇️ 키워드 방식으로 통일
target_link_libraries(secJoinfrontend PRIVATE secureJoin_Tests tests_cryptoTools)

# (선택) 메시지는 이렇게
# message(STATUS "done with libOTe")
# 또는
# # done with libOTe
