cmake_minimum_required(VERSION 3.5)

project(WebSocketClient.run LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
#set(OPENSSL_USE_STATIC_LIBS TRUE)

add_executable(WebSocketClient.run main.cpp)
set(CMAKE_EXE_LINKER_FLAGS "-static")


IF(UNIX)
    #link websocket client library
    target_link_libraries(WebSocketClient.run -lWebSocketClient)

    #link openssl library
    target_link_libraries(WebSocketClient.run -lpthread -lssl -lcrypto)
ENDIF()

IF(WIN32)
    link_libraries(ws2_32.lib)

    #link websocket client library
    target_link_libraries(WebSocketClient.run ${CMAKE_SOURCE_DIR}/libs/libWebSocketClient/WebSocketClient.lib)

    #include headers of websocket client
    include_directories("${PROJECT_SOURCE_DIR}/libs/libWebSocketClient/include")

    link_libraries(libucrt.lib libucrtd.lib libvcruntime.lib)
    set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} /MT")
    set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} /MTd")
    #LIBS += bcrypt.lib libcmt.lib Shell32.lib Shlwapi.lib User32.lib kernel32.lib Ws2_32.lib advapi32.lib crypt32.lib iphlpapi.lib psapi.lib gdi32.lib

ENDIF()

install(TARGETS WebSocketClient.run LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR})
