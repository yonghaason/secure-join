
set(DEP_NAME            json)          
set(GIT_REPOSITORY      "https://github.com/nlohmann/json")
set(GIT_TAG             "5d2754306d67d1e654a1a34e1d2e74439a9d53b3" )
# Can I not pull the latest version instead of a specific version?

set(CLONE_DIR "${SECUREJOIN_THIRDPARTY_CLONE_DIR}/${DEP_NAME}")
set(BUILD_DIR "${CLONE_DIR}/out/build/${SECUREJOIN_CONFIG}")
set(LOG_FILE  "${CMAKE_CURRENT_LIST_DIR}/log-${DEP_NAME}.txt")

include("${CMAKE_CURRENT_LIST_DIR}/fetch.cmake") 

if(NOT ${DEP_NAME}_FOUND)

    find_program(GIT git REQUIRED)
    set(DOWNLOAD_CMD  ${GIT} clone --recursive ${GIT_REPOSITORY})
    set(CHECKOUT_CMD  ${GIT} checkout ${GIT_TAG})
    set(CONFIGURE_CMD ${CMAKE_COMMAND} -S ${CLONE_DIR} -B ${BUILD_DIR} 
                    -DCMAKE_INSTALL_PREFIX=${CMAKE_INSTALL_PREFIX}
                    -DCMAKE_PREFIX_PATH=${CMAKE_PREFIX_PATH_STR}
                    -DCMAKE_BUILD_TYPE:STRING=${CMAKE_BUILD_TYPE} 
                    -DNO_CMAKE_SYSTEM_PATH=${NO_CMAKE_SYSTEM_PATH}
                    -DJSON_BuildTests=OFF)

    set(BUILD_CMD     ${CMAKE_COMMAND} --build ${BUILD_DIR} --config ${CMAKE_BUILD_TYPE})
    set(INSTALL_CMD   ${CMAKE_COMMAND} --install ${BUILD_DIR} --config 
                    ${CMAKE_BUILD_TYPE} --prefix ${SECUREJOIN_THIRDPARTY_DIR})

    message("============= Building ${DEP_NAME} =============")
    if(NOT EXISTS ${CLONE_DIR})
        run(NAME "Cloning ${GIT_REPOSITORY}" CMD ${DOWNLOAD_CMD} WD ${SECUREJOIN_THIRDPARTY_CLONE_DIR})
    endif()

    run(NAME "Checkout ${GIT_TAG} " CMD ${CHECKOUT_CMD}  WD ${CLONE_DIR})
    
    run(NAME "${DEP_NAME} Configure"       CMD ${CONFIGURE_CMD} WD ${CLONE_DIR})
    run(NAME "${DEP_NAME} Build"           CMD ${BUILD_CMD}     WD ${CLONE_DIR})
    run(NAME "${DEP_NAME} Install"         CMD ${INSTALL_CMD}   WD ${CLONE_DIR})

    message("log ${LOG_FILE}\n==========================================")
else()
    message("${DEP_NAME} already fetched.")
endif()

install(CODE "
    if(NOT CMAKE_INSTALL_PREFIX STREQUAL \"${SECUREJOIN_THIRDPARTY_CLONE_DIR}\")
        execute_process(
            COMMAND ${SUDO} \${CMAKE_COMMAND} --install \"${BUILD_DIR}\" --config ${CMAKE_BUILD_TYPE} --prefix \${CMAKE_INSTALL_PREFIX}
            WORKING_DIRECTORY ${CLONE_DIR}
            RESULT_VARIABLE RESULT
            COMMAND_ECHO STDOUT
        )
    endif()
")
