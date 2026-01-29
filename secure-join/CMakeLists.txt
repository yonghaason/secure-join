


set(SRCS
    "Prf/mod3.cpp"
    "Prf/ConvertToF3.cpp"
    "Prf/AltModPrf.cpp"
    "Prf/AltModKeyMult.cpp"
    "Prf/AltModPrfProto.cpp"
    "Prf/F2LinearCode.cpp"
    "Prf/F3LinearCode.cpp"

    
    "CorGenerator/CorGenerator.cpp"
    "CorGenerator/Request.cpp"
    "CorGenerator/Batch.cpp"
    "CorGenerator/OtBatch.cpp"
    "CorGenerator/BinOleBatch.cpp"
    "CorGenerator/TritOtBatch.cpp"
    "CorGenerator/F4BitOtBatch.cpp"

    
    "Perm/Permutation.cpp"
    "Perm/PermCorrelation.cpp"
    "Perm/ComposedPerm.cpp"
    "Perm/LowMCPerm.cpp"
    
    "Perm/AltModComposedPerm.cpp"
    "Perm/AltModPerm.cpp"
    
    "Perm/PprfPermGen.cpp"

    "GMW/Circuit.cpp"
    "GMW/Gmw.cpp"

    "Sort/BitInjection.cpp"
    "Sort/RadixSort.cpp"
    
    "AggTree/AggTree.cpp"
    "AggTree/Level.cpp"
    "AggTree/PlainAggTree.cpp"
    "TableOps/GroupBy.cpp"
    "TableOps/Where.cpp"
    "TableOps/WhereParser.cpp"
    "TableOps/Extract.cpp"
    
    "Util/Trim.cpp"
    
    "Join/Table.cpp"
    "Join/OmJoin.cpp"
    "Join/OoJoin.cpp"

    "AltPsu/AltPsu.cpp"
    "AltPsu/RB_OKVS/band_okvs.cc"
    "AltPsu/RB_OKVS/band.cc"

    "PID/AltModPID.cpp"
    "volePSI/RsOprf.cpp"
    "volePSI/SimpleIndex.cpp"
    )



# add_library(secureJoin STATIC ${SRCS})
# target_link_libraries(secureJoin libOTe)

# add Kunlun

# --- Kunlun 가져오기 (이미 사용 중인 절대경로 방식 유지) ---
add_subdirectory(${CMAKE_SOURCE_DIR}/secure-join/Kunlun ${CMAKE_BINARY_DIR}/Kunlun-build)

# Kunlun 타깃 존재 확인 후 변수에 담기
if (TARGET Kunlun::kunlun)
  set(KUNLUN_TARGET Kunlun::kunlun)
elseif (TARGET Kunlun)
  set(KUNLUN_TARGET Kunlun)
else()
  message(FATAL_ERROR "Kunlun target not found (Kunlun::kunlun or Kunlun). Check Kunlun/CMakeLists.txt")
endif()

# (중복 안전) 종속성
find_package(OpenMP REQUIRED)
# OpenSSL은 Kunlun 인터페이스가 이미 정적 lib 경로를 전파하므로 굳이 다시 가져오지 않아도 됩니다.
# 만약 secure-join 코드 자체가 OpenSSL imported target을 필요로 한다면 그때만 find_package(OpenSSL REQUIRED)

add_library(secureJoin STATIC ${SRCS})

target_link_libraries(secureJoin
  PUBLIC
    libOTe
  PRIVATE
    ${KUNLUN_TARGET}
    OpenMP::OpenMP_CXX
)

# (중복 제거) 아래의 이중 탐색/이중 에러 메시지/이중 ALIAS 생성 코드는 삭제하세요.


configure_file(config.h.in "config.h" )
if(APPLE)
    target_compile_options(secureJoin PUBLIC
        "-std=c++${SECUREJOIN_CPP_VER}"
    )    
    target_compile_options(secureJoin PRIVATE
        "-Wno-pessimizing-move"
        "-Wno-delete-non-abstract-non-virtual-dtor"
    )
elseif(MSVC)
    message("SECUREJOIN_CPP_VER=${SECUREJOIN_CPP_VER}")
    target_compile_options(secureJoin PUBLIC "/std:c++${SECUREJOIN_CPP_VER}" "/Zc:__cplusplus")

    if(SECUREJOIN_ENABLE_ASAN)
        target_compile_options(secureJoin PUBLIC "/fsanitize=address")
        target_link_options(secureJoin PUBLIC "/fsanitize=address")

    endif()
else()
    target_compile_options(secureJoin PUBLIC
        "-std=c++${SECUREJOIN_CPP_VER}"
    )    

    if(SECUREJOIN_ENABLE_ASAN)
        target_compile_options(secureJoin PUBLIC "-fsanitize=address")# "-ftime-report")
        target_link_options(secureJoin PUBLIC "-fsanitize=address")
    endif()
endif()

if(MSVC)
    target_compile_definitions(secureJoin PUBLIC "_ENABLE_EXTENDED_ALIGNED_STORAGE")
else()
endif()

#target_compile_features(secureJoin PUBLIC cxx_std_17)
# make projects that include secureJoin use this as an include folder
target_include_directories(secureJoin PUBLIC 
                    $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}/..>
                    $<INSTALL_INTERFACE:include>) 
target_include_directories(secureJoin PUBLIC 
                    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/..>
                    $<INSTALL_INTERFACE:include>) 

