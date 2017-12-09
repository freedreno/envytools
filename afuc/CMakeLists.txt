project(ENVYTOOLS C)
cmake_minimum_required(VERSION 2.6)

find_package(FLEX REQUIRED)
find_package(BISON REQUIRED)

flex_target(lexer lexer.l ${CMAKE_CURRENT_BINARY_DIR}/lexer.c)
bison_target(parser parser.y ${CMAKE_CURRENT_BINARY_DIR}/parser.c)

include_directories(${PROJECT_BINARY_DIR})

add_executable(disasm disasm.c)
target_link_libraries(disasm rnn)

add_executable(asm asm.c lexer.c parser.c)
target_link_libraries(asm rnn)
