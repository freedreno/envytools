project(ENVYTOOLS C)
cmake_minimum_required(VERSION 2.6)

include_directories(${PROJECT_BINARY_DIR})

find_package(PkgConfig)
pkg_check_modules(LUA lua52)
if (NOT "${LUA_FOUND}")
  pkg_check_modules(LUA lua)
endif()
pkg_check_modules(LIBARCHIVE REQUIRED libarchive)

include_directories(${LUA_INCLUDE_DIRS} ${LIBARCHIVE_INCLUDE_DIRS})

add_library(util disasm-a2xx.c disasm-a3xx.c io.c rnnutil.c pager.c cffdec.c buffers.c)

add_executable(cffdump cffdump.c script.c)
target_link_libraries(cffdump util rnn ${LUA_LIBRARIES} ${LIBARCHIVE_LIBRARIES})

add_executable(pgmdump pgmdump.c)
target_link_libraries(pgmdump util rnn ${LIBARCHIVE_LIBRARIES})

add_executable(pgmdump2 pgmdump2.c)
target_link_libraries(pgmdump2 util rnn ${LIBARCHIVE_LIBRARIES})
