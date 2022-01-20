cmake_minimum_required(VERSION 2.8.12)

# A C project
project(C)

set(CMAKE_VERBOSE_MAKEFILE ON)

if(ANDROID)
  ADD_LIBRARY(zdtun STATIC zdtun.c utils.c)

  TARGET_LINK_LIBRARIES(zdtun)
  add_definitions(-DANDROID)

  find_library(log-lib log)

  TARGET_LINK_LIBRARIES(zdtun ${log-lib})
else()
  ADD_LIBRARY(zdtun STATIC zdtun.c utils.c)
  ADD_LIBRARY(zdtun_dbg STATIC zdtun.c utils.c)

  add_executable(zdtun_pivot zdtun_pivot.c)
  add_executable(zdtun_client zdtun_client.c utils.c)

  if(NOT WIN32)
    add_executable(zdtun_gateway zdtun_gateway.c)
    TARGET_LINK_LIBRARIES(zdtun_gateway zdtun_dbg)
  endif()

  TARGET_LINK_LIBRARIES(zdtun_pivot zdtun_dbg)

  set_target_properties(zdtun PROPERTIES COMPILE_FLAGS -DNO_DEBUG)
endif()

if(WIN32)
  target_link_libraries(zdtun_pivot ws2_32)
  add_definitions(-DWIN32)

  # assume LITTLE_ENDIAN on Windows
else()
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wno-unused-variable -Wno-unused-function -g -fPIC")

  include (TestBigEndian)
  TEST_BIG_ENDIAN(IS_BIG_ENDIAN)
endif()

if(IS_BIG_ENDIAN)
 message(STATUS "BIG_ENDIAN")
 add_definitions(-D_BIG_ENDIAN)
else()
 message(STATUS "LITTLE_ENDIAN")
 add_definitions(-D_LITTLE_ENDIAN)
endif()

# Force static linking on Windows
set(CompilerFlags
        CMAKE_CXX_FLAGS
        CMAKE_CXX_FLAGS_DEBUG
        CMAKE_CXX_FLAGS_RELEASE
        CMAKE_C_FLAGS
        CMAKE_C_FLAGS_DEBUG
        CMAKE_C_FLAGS_RELEASE
        )
foreach(CompilerFlag ${CompilerFlags})
  string(REPLACE "/MD" "/MT" ${CompilerFlag} "${${CompilerFlag}}")
endforeach()
