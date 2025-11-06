cmake_minimum_required(VERSION 3.16)
project(chat_server LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_executable(chat_server
  server.cpp
)

target_link_libraries(chat_server PRIVATE)

if (WIN32)
  target_link_libraries(chat_server PRIVATE ws2_32)
endif()

# 运行时从后端可执行文件路径相对挂载 ../frontend
add_custom_command(TARGET chat_server POST_BUILD
  COMMAND ${CMAKE_COMMAND} -E echo "chat_server built. Run and open http://localhost:8080"
)


