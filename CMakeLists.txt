project(cs_sim)
cmake_minimum_required(VERSION 2.8)

set(SOURCE_DIR .)

set(SRC_LIST
    ${SOURCE_DIR}/simulator_p.cpp
)

#aux_source_directory(. SRC_LIST)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -g2")
include_directories(SYSTEM /usr/local/include /usr/include)

# Static lib target
add_library(rc_sim_static STATIC
    ${SRC_LIST}
)
set_target_properties(rc_sim_static PROPERTIES
    OUTPUT_NAME "rcsim"
    CLEAN_DIRECT_OUTPUT 1
    VERSION 0.1
)

add_executable(rcsim-test rcsim-test.cpp)
target_link_libraries(rcsim-test rc_sim_static)
