cmake_minimum_required(VERSION 3.18)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

project(
    crappasswd
    VERSION 0.1
    DESCRIPTION "crappasswd pw management tool"
    LANGUAGES C
    )

set_property(
    TARGET ${PROJECT}
    PROPERTY C_STANDARD 99
)

# Main sources:
add_executable(
    ${PROJECT_NAME}
    # Main sources:
    src/main.c
)

# Link math library:
target_link_libraries(
    ${PROJECT_NAME}
    m
)

# Link libldap:
target_link_libraries(
    ${PROJECT_NAME}
    ldap
)

target_include_directories(
    ${PROJECT_NAME}
    PUBLIC
    include
)

target_compile_options(${PROJECT_NAME} PUBLIC -Wall -Wextra -Wpedantic)
