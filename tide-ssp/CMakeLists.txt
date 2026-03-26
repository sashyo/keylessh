cmake_minimum_required(VERSION 3.15)
project(TideSSP C)

set(CMAKE_C_STANDARD 11)

# Static CRT so DLLs work on Server Core without VC++ Redistributable
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

add_library(TideSSP SHARED
    src/main.c
    src/ssp.c
    src/ed25519.c
    src/logon.c
)

target_include_directories(TideSSP PRIVATE src)

target_link_libraries(TideSSP PRIVATE
    secur32
    ntdll
    advapi32
    bcrypt
    netapi32
)

# SSP DLLs must export SpLsaModeInitialize
target_compile_definitions(TideSSP PRIVATE
    SECURITY_WIN32
    UNICODE
    _UNICODE
)

if(MSVC)
    target_compile_options(TideSSP PRIVATE /W4)
    # Generate .def file for exports
    set_target_properties(TideSSP PROPERTIES
        LINK_FLAGS "/DEF:${CMAKE_CURRENT_SOURCE_DIR}/src/TideSSP.def"
    )
endif()

add_library(TideSubAuth SHARED
    src/subauth.c
)

target_include_directories(TideSubAuth PRIVATE src)

target_link_libraries(TideSubAuth PRIVATE
    advapi32
    ntdll
    netapi32
)

target_compile_definitions(TideSubAuth PRIVATE
    SECURITY_WIN32
    UNICODE
    _UNICODE
)

if(MSVC)
    target_compile_options(TideSubAuth PRIVATE /W4)
    set_target_properties(TideSubAuth PROPERTIES
        LINK_FLAGS "/DEF:${CMAKE_CURRENT_SOURCE_DIR}/src/TideSubAuth.def"
    )
endif()

# Installer custom action DLL
add_library(TideCA SHARED
    installer/CustomActions.c
)

target_compile_definitions(TideCA PRIVATE
    UNICODE
    _UNICODE
)

target_link_libraries(TideCA PRIVATE
    msi
    advapi32
    netapi32
)

if(MSVC)
    target_compile_options(TideCA PRIVATE /W4)
    set_target_properties(TideCA PROPERTIES
        LINK_FLAGS "/DEF:${CMAKE_CURRENT_SOURCE_DIR}/installer/CustomActions.def"
    )
endif()

install(TARGETS TideSSP TideSubAuth RUNTIME DESTINATION bin)
