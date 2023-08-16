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
    if(SECUREJOIN_ENABLE_SSE)
        set(COMPS ${COMPS}  sse)
    else()
        set(COMPS ${COMPS}  no_sse)
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

#######################################
# nlohmann json

macro(FIND_JSON)
    if(NOT TARGET json)
        find_path(JSON_INCLUDE_DIR "nlohmann/json.hpp" PATH_SUFFIXES "/include/" ${ARGN})

        if(EXISTS ${JSON_INCLUDE_DIR})
            add_library(json INTERFACE IMPORTED)
            target_include_directories(json INTERFACE 
                            $<BUILD_INTERFACE:${JSON_INCLUDE_DIR}>
                            $<INSTALL_INTERFACE:>)

            set(json_FOUND true)
        else()
            set(json_FOUND false)
        endif()
    endif()
    message(STATUS "json include:  ${JSON_INCLUDE_DIR}\n")
endmacro()

if(FETCH_JSON_AUTO)
    FIND_JSON(QUIET)
    include(${CMAKE_CURRENT_LIST_DIR}/../thirdparty/getJson.cmake)
endif()
FIND_JSON(REQUIRED)


# resort the previous prefix path
set(CMAKE_PREFIX_PATH ${PUSHED_CMAKE_PREFIX_PATH})
