
#configure_file(config.h.in "config.h" )


set(SRCS
    "PaillierPerm.cpp"
    )

add_library(secureJoin STATIC ${SRCS})
target_link_libraries(secureJoin oc::libOTe Paillier)

if(APPLE)
    target_compile_options(secureJoin PUBLIC
        "-std=c++${SECUREJOIN_CPP_VER}"
    )    
    target_compile_options(secureJoin PRIVATE
        "-Wno-pessimizing-move"
        "-Wno-delete-non-abstract-non-virtual-dtor"
    )
elseif(MSVC)
    set_target_properties(secureJoin
        PROPERTIES
            CXX_STANDARD ${SECUREJOIN_CPP_VER}
            CXX_STANDARD_REQUIRED YES
            CXX_EXTENSIONS NO
    )

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
    target_compile_options(secureJoin PUBLIC -mavx)
endif()

#target_compile_features(secureJoin PUBLIC cxx_std_17)
# make projects that include secureJoin use this as an include folder
target_include_directories(secureJoin PUBLIC 
                    $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}/..>
                    $<INSTALL_INTERFACE:include>) 
target_include_directories(secureJoin PUBLIC 
                    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/..>
                    $<INSTALL_INTERFACE:include>) 

