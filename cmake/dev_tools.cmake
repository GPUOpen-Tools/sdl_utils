#######################################################################################################################
### Copyright (c) 2024-2026 Advanced Micro Devices, Inc. All rights reserved.
### @author AMD Developer Tools Team
#######################################################################################################################

if (CMAKE_CXX_COMPILER_ID STREQUAL "MSVC")
    string(REPLACE " /W3" "" CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS}")
endif ()

# Apply options to a developer tools target.
# These options are hard requirements to build. If they cannot be applied, we
# will need to fix the offending target to ensure it complies.
function(devtools_target_options name)

    set_target_properties(${name} PROPERTIES
            CXX_STANDARD 20 
            CXX_STANDARD_REQUIRED ON)

    get_target_property(target_type ${name} TYPE)
    if ("${target_type}" STREQUAL "INTERFACE_LIBRARY")
        return()
    endif ()

    if (CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang|AppleClang")

        target_compile_options(${name}
                PRIVATE
                -Wall
                -Werror
                -Wextra
                )
    elseif (CMAKE_CXX_COMPILER_ID STREQUAL "MSVC")
        target_compile_options(${name}
                PRIVATE
                /W4
                /WX
                /MP
                )
    else ()

        message(FATAL_ERROR "Compiler ${CMAKE_CXX_COMPILER_ID} is not supported!")

    endif ()

    # GNU specific flags
    if (CMAKE_CXX_COMPILER_ID MATCHES "GNU")
        target_compile_options(${name} PRIVATE -Wno-maybe-uninitialized)
    endif ()

    if (UNIX AND NOT APPLE)
        target_compile_definitions(${name}
                PRIVATE
                _LINUX

                # Use _DEBUG on Unix for Debug Builds (defined automatically on Windows)
                $<$<CONFIG:Debug>:_DEBUG>
                )
    endif ()

endfunction()
