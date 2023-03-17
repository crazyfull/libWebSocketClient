cmake_minimum_required(VERSION 3.14)

project(libWebSocketClient
    VERSION 1.1.27
    DESCRIPTION "WebSocket Client Library"
    LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_INCLUDE_CURRENT_DIR ON)
#add_definitions(-D USE_OPENSSL)
option(BUILD_SHARED_LIBS "Build shared librarie" ON)


if(UNIX)
    set(CMAKE_CXX_FLAGS_DEBUG_INIT "-Wall")
    set(CMAKE_CXX_FLAGS_RELEASE_INIT "-Wall -O2")

    if (CMAKE_INSTALL_PREFIX_INITIALIZED_TO_DEFAULT)
        set(CMAKE_INSTALL_PREFIX "/usr/lib")
    endif()

    set(INSTALL_LIB_DIR "${CMAKE_INSTALL_PREFIX}" CACHE PATH "Installation directory for libraries")
    set(INSTALL_INC_DIR "/usr/include/WebSocketClient" CACHE PATH "Installation directory for headers")
endif()

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE "Release")
endif()

#for static build on MSVC
IF(WIN32)
    if(BUILD_SHARED_LIBS)
        link_libraries(libucrt.lib libucrtd.lib libvcruntime.lib)
        set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} /MT")
        set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} /MTd")
    endif()
ENDIF()


# maybe need for win32
# include_directories("${PROJECT_SOURCE_DIR}/src")

set(SOURCES ${SOURCES}
    WebSocketClient.cpp
    src/network/TCP/TCPSocket.cpp
    src/network/SSL/openssl_hostname_validation.cpp
    src/network/SSL/hostcheck.cpp
    src/network/HTTP/WSocketHeader.cpp
    src/network/HTTP/WebSocket.cpp
    src/network/HTTP/HTTPHeaderFields.cpp
    src/network/HTTP/HTTPClient.cpp
    src/network/HTTP/HTTPBuilder.cpp
    src/base64/base64.cpp
)

set(HEADERS ${HEADERS}
    WebSocketClient.h
    src/log.h
    src/network/SocketHeader.h
    src/network/TCP/TCPSocket.h
    src/network/SSL/openssl_hostname_validation.h
    src/network/SSL/hostcheck.h
    src/network/HTTP/WSocketHeader.h
    src/network/HTTP/WebSocket.h
    src/network/HTTP/HTTPHeaderFields.h
    src/network/HTTP/HTTPClient.h
    src/network/HTTP/HTTPBuilder.h
    src/base64/base64.h
)

#
if(BUILD_SHARED_LIBS)
    add_library(libWebSocketClient SHARED ${SOURCES} ${HEADERS})
else()
    add_library(libWebSocketClient STATIC ${SOURCES} ${HEADERS})
endif()

if (${CMAKE_BUILD_TYPE} STREQUAL "Release")
    #message("Release mode")
endif()

set_target_properties(libWebSocketClient PROPERTIES OUTPUT_NAME "WebSocketClient")


# Install headers
#install(FILES ${HEADERS}
#    DESTINATION "${INSTALL_INC_DIR}"
#)

# Install headers
if(UNIX)
install(FILES WebSocketClient.h DESTINATION "${INSTALL_INC_DIR}")
install(FILES src/log.h DESTINATION "${INSTALL_INC_DIR}/src")
install(FILES
    src/network/SocketHeader.h
    DESTINATION "${INSTALL_INC_DIR}/src/network")
install(FILES src/network/TCP/TCPSocket.h DESTINATION "${INSTALL_INC_DIR}/src/network/TCP")
install(FILES
    src/network/SSL/openssl_hostname_validation.h
    src/network/SSL/hostcheck.h
    DESTINATION "${INSTALL_INC_DIR}/src/network/SSL")
install(FILES
    src/network/HTTP/WSocketHeader.h
    src/network/HTTP/WebSocket.h
    src/network/HTTP/HTTPHeaderFields.h
    src/network/HTTP/HTTPClient.h
    src/network/HTTP/HTTPBuilder.h
    DESTINATION "${INSTALL_INC_DIR}/src/network/HTTP")
install(FILES src/base64/base64.h DESTINATION "${INSTALL_INC_DIR}/src/base64")


# Install lib
install(TARGETS libWebSocketClient libWebSocketClient
    ARCHIVE DESTINATION "${INSTALL_LIB_DIR}"
    LIBRARY DESTINATION "${INSTALL_LIB_DIR}"
)
endif()

target_compile_definitions(libWebSocketClient PRIVATE LIBWEBSOCKETCLIENT_LIBRARY)

message(STATUS "Project:
    Build shared:               ${BUILD_SHARED_LIBS}
    library name:               ${PROJECT_NAME}
    library description:        ${PROJECT_DESCRIPTION}
    library version:            ${PROJECT_VERSION}
    library installing path:    ${INSTALL_LIB_DIR}
    ")

message(STATUS "build options:
    Install prefix:  ${CMAKE_INSTALL_PREFIX}
    Target system:   ${CMAKE_SYSTEM_NAME}
    C compiler:    ${CMAKE_C_COMPILER}
    ")

if (USE_OPENSSL)
    message(STATUS "Using OpenSSL: YES")
    #using openssl
    add_definitions(-D USE_OPENSSL)
else()
    message(STATUS "Using OpenSSL: NO")
endif()



## for disable log messages
#NO_NEED_DEBUG
#NO_NEED_LOG
