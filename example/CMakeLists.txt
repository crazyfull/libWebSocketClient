cmake_minimum_required(VERSION 3.5)

project(WebSocketClient.run LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
#  set(OPENSSL_USE_STATIC_LIBS TRUE)

add_executable(WebSocketClient.run main.cpp)
set(CMAKE_EXE_LINKER_FLAGS "-static")


#target_link_libraries(WebSocketClient.run -L/usr/lib/WebSocketClient)

target_link_libraries(WebSocketClient.run -lWebSocketClient)
target_link_libraries(WebSocketClient.run -lpthread -lssl -lcrypto)
target_link_libraries(WebSocketClient.run -levent -levent_pthreads -levent_openssl)
#target_link_libraries(WebSocketClient.run -L/home/crow/programing/libWebSocketClient/WebSocketClient.run/lib/libEvent/include)

#target_link_libraries(WebSocketClient.run /home/crow/programing/libWebSocketClient/sample/lib/libEvent/linux64/libevent_openssl.a)
#target_link_libraries(WebSocketClient.run /home/crow/programing/libWebSocketClient/sample/lib/libEvent/linux64/libevent.a)
#target_link_libraries(WebSocketClient.run /home/crow/programing/libWebSocketClient/sample/lib/libEvent/linux64/libevent_pthreads.a)
#target_link_libraries(main ${CMAKE_SOURCE_DIR}/libbingitup.a)

#link_libraries(opengl32.lib glew32.lib glfw3.lib)

# include_directories(
#     "/usr/include"
#     "/usr/lib/WebSocketClient/include"
#     "/usr/include/glm"
#     "/usr/include/glm/gtc"
#    "${PROJECT_SOURCE_DIR}/src"
# )

install(TARGETS WebSocketClient.run LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR})
