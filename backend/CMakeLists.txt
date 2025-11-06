cmake_minimum_required(VERSION 3.16)
project(chat_server LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include(FetchContent)

# 拉取 nlohmann/json（JSON 解析）
FetchContent_Declare(
  nlohmann_json
  GIT_REPOSITORY https://github.com/nlohmann/json.git
  GIT_TAG v3.11.3
)
FetchContent_MakeAvailable(nlohmann_json)

add_executable(chat_server
  server.cpp
)

target_link_libraries(chat_server PRIVATE nlohmann_json::nlohmann_json)

if (WIN32)
  target_link_libraries(chat_server PRIVATE ws2_32)
endif()

# 运行时从后端可执行文件路径相对挂载 ../frontend
add_custom_command(TARGET chat_server POST_BUILD
  COMMAND ${CMAKE_COMMAND} -E echo "chat_server built. Run and open http://localhost:8080"
)


