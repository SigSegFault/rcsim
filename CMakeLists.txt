project(cs_sim)
cmake_minimum_required(VERSION 2.8)

set(SOURCE_DIR .)

set(SRC_LIST
    ${SOURCE_DIR}/simulator_p.cpp
)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -g2")
include_directories(SYSTEM /usr/local/include /usr/include)

# Static lib target
add_library(rcsim_static STATIC
    ${SRC_LIST}
)
set_target_properties(rcsim_static PROPERTIES
    OUTPUT_NAME "rcsim"
    CLEAN_DIRECT_OUTPUT 1
    VERSION 0.1
)

# Shared lib target
add_library(rcsim_shared SHARED
    ${SRC_LIST}
)
set_target_properties(rcsim_shared PROPERTIES
    OUTPUT_NAME "rcsim"
    CLEAN_DIRECT_OUTPUT 1
    VERSION 0.1
)

# EXAMPLE 01
add_executable(rcsim-example01 rcsim-example01.cpp)
target_link_libraries(rcsim-example01 rcsim_static)

# EXAMPLE 02
add_executable(rcsim-example02 rcsim-example02.cpp)
target_link_libraries(rcsim-example02 rcsim_static)
