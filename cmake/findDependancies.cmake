include(${CMAKE_CURRENT_LIST_DIR}/preamble.cmake)

message(STATUS "SECUREJOIN_THIRDPARTY_DIR=${SECUREJOIN_THIRDPARTY_DIR}")


set(PUSHED_CMAKE_PREFIX_PATH ${CMAKE_PREFIX_PATH})
set(CMAKE_PREFIX_PATH "${SECUREJOIN_THIRDPARTY_DIR};${CMAKE_PREFIX_PATH}")


#######################################
# libOTe

macro(FIND_LIBOTE)
    set(ARGS ${ARGN})
    set(COMPS)
    
    if(SECUREJOIN_ENABLE_ASAN)
        set(COMPS ${COMPS}  asan)
    else()
        set(COMPS ${COMPS}  no_asan)
    endif()

    if(SECUREJOIN_ENABLE_BOOST)
        set(COMPS ${COMPS}  boost)
    else()
        #set(COMPS ${COMPS}  no_boost)
    endif()



    #explicitly asked to fetch libOTe
    if(FETCH_LIBOTE)
        list(APPEND ARGS NO_DEFAULT_PATH PATHS ${SECUREJOIN_THIRDPARTY_DIR})
    elseif(${NO_CMAKE_SYSTEM_PATH})
        list(APPEND ARGS NO_DEFAULT_PATH PATHS ${CMAKE_PREFIX_PATH})
    endif()
    
    find_package(libOTe ${ARGS} COMPONENTS ${COMPS})

    if(TARGET oc::libOTe)
        set(libOTe_FOUND ON)
    else()
        set(libOTe_FOUND  OFF)
    endif()
endmacro()

if(FETCH_LIBOTE_AUTO)
    FIND_LIBOTE(QUIET)
    include(${CMAKE_CURRENT_LIST_DIR}/../thirdparty/getLibOTe.cmake)
endif()

FIND_LIBOTE(REQUIRED)




# resort the previous prefix path
set(CMAKE_PREFIX_PATH ${PUSHED_CMAKE_PREFIX_PATH})
