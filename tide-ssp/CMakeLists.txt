cmake_minimum_required(VERSION 3.15)
project(TideSSP C)

set(CMAKE_C_STANDARD 11)

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

# ── SubAuth DLL ──────────────────────────────────────────────────
add_library(TideSubAuth SHARED
    src/subauth.c
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

install(TARGETS TideSSP TideSubAuth RUNTIME DESTINATION bin)
