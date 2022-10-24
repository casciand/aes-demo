cmake_policy(SET CMP0091 NEW)

project(cpp)

cmake_minimum_required(VERSION 3.0)
add_executable(cpp main.cpp)
target_compile_features(cpp PRIVATE cxx_std_17)
set(EXTERNAL_LIB_HEADERS lib/cryptopp)
target_include_directories(cpp PRIVATE ${EXTERNAL_LIB_HEADERS})

If(WIN32)
  set_property(TARGET cpp PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
  target_link_libraries(cpp PRIVATE ${CMAKE_SOURCE_DIR}/lib/cryptopp/x64/Output/Debug/cryptlib.lib)
elseif(APPLE)
  target_link_libraries(cpp PRIVATE ${CMAKE_SOURCE_DIR}/lib/cryptopp/libcryptopp.dylib)
elseif(UNIX NOT APPLE)
  target_link_libraries(cpp PRIVATE ${CMAKE_SOURCE_DIR}/lib/cryptopp/libcryptopp.a)
endif()