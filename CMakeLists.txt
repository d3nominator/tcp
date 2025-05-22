cmake_minimum_required(VERSION 3.10)
project(tcp-cpp)

set(CMAKE_CXX_STANDARD 17)


file(GLOB_RECURSE SRC_FILES "src/*.cpp")
add_subdirectory(dependencies/libviface)
add_subdirectory(dependencies/libtuntap)
set(ENABLE_CXX on)
add_executable(tcp-cpp ${SRC_FILES})


target_include_directories(tcp-cpp PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/dependencies/libviface/include)
target_include_directories(tcp-cpp PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/dependencies/libtuntap/bindings/cpp)
target_include_directories(tcp-cpp PRIVATE include)

target_link_libraries(tcp-cpp PRIVATE viface)
target_link_libraries(tcp-cpp PRIVATE tuntap++)

