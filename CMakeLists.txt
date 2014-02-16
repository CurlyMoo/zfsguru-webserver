cmake_minimum_required(VERSION 2.8.8)

project(zfsguru C)

set(USE_SOFT_FLOAT OFF CACHE BOOL "Compile for soft float abi kernels")

if(${CMAKE_SYSTEM_PROCESSOR} MATCHES "armv6")
	if(${USE_SOFT_FLOAT} MATCHES "OFF")
		set(CMAKE_C_FLAGS "-Ofast -mfloat-abi=hard -mfpu=vfp -march=armv6 -ffast-math -Wfloat-equal -Wshadow -Wpointer-arith -Wcast-align -Wstrict-overflow=5 -Wwrite-strings -Waggregate-return -Wcast-qual -Wswitch-default -Wswitch-enum -Wformat=2 -g -Wall -Wconversion -Wunreachable-code -Wstrict-prototypes")
		file(GLOB CMAKE_ZLIB_LIBS_INIT "/usr/lib/arm-linux-gnueabihf/libz.so")
	else()
		set(CMAKE_C_FLAGS "-Ofast -mfloat-abi=soft -msoft-float -mfpu=vfp -march=armv6 -ffast-math -Wfloat-equal -Wshadow -Wpointer-arith -Wcast-align -Wstrict-overflow=5 -Wwrite-strings -Waggregate-return -Wcast-qual -Wswitch-default -Wswitch-enum -Wformat=2 -g -Wall -Wconversion -Wunreachable-code -Wstrict-prototypes")
		file(GLOB CMAKE_ZLIB_LIBS_INIT "/usr/lib/arm-linux-gnueabi/libz.so")
	endif()
endif()

if(${CMAKE_SYSTEM_PROCESSOR} MATCHES "x86_64")
	set(CMAKE_C_FLAGS "-Ofast -fPIC -march=native -mtune=native -ffast-math -Wconversion -Wunreachable-code -Wstrict-prototypes -Wfloat-equal -Wshadow -Wpointer-arith -Wcast-align -Wstrict-overflow=5 -Wwrite-strings -Waggregate-return -Wcast-qual -Wswitch-default -Wswitch-enum -Wformat=2 -g -Wall")
	file(GLOB CMAKE_ZLIB_LIBS_INIT "/usr/lib/x86_64-linux-gnu/libz.so")
endif()
if(${CMAKE_SYSTEM_PROCESSOR} MATCHES "amd64")
	set(CMAKE_C_FLAGS "-O2 -fPIC -march=native -mtune=native -ffast-math -Wformat=2 -g -Wformat-nonliteral")
	file(GLOB CMAKE_ZLIB_LIBS_INIT "/usr/lib32/libz.so")
endif()

# Start uninstaller generator
function(WRITE_UNINSTALL_TARGET_SCRIPT)
    # Create uninstall target template file, if it doesn't exist...
    if(NOT EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/cmake_uninstall.cmake.in)
        set(__uninstall_filename ${CMAKE_CURRENT_BINARY_DIR}/cmake_uninstall.cmake.in)
        # BEGIN actual write to file...
        file(WRITE ${__uninstall_filename} "\# - uninstall target template\n\#")
        file(APPEND ${__uninstall_filename} "
if (NOT EXISTS \"\@CMAKE_CURRENT_BINARY_DIR\@/install_manifest.txt\")
    message(FATAL_ERROR \"Cannot find install manifest: \\\"\@CMAKE_CURRENT_BINARY_DIR\@/install_manifest.txt\\\"\")
endif(NOT EXISTS \"\@CMAKE_CURRENT_BINARY_DIR\@/install_manifest.txt\")

file(READ \"\@CMAKE_CURRENT_BINARY_DIR\@/install_manifest.txt\" files)
string(REGEX REPLACE \"\\n\" \";\" files \"\${files}\")

foreach (file \${files})
    message(STATUS \"Uninstalling \\\"\$ENV{DESTDIR}\${file}\\\"\")
    if (EXISTS \"\$ENV{DESTDIR}\${file}\")
        execute_process(
            COMMAND \@CMAKE_COMMAND\@ -E remove \"\$ENV{DESTDIR}\${file}\"
            OUTPUT_VARIABLE rm_out
            RESULT_VARIABLE rm_retval
        )
        if(NOT \${rm_retval} EQUAL 0)
            message(FATAL_ERROR \"Problem when removing \\\"\$ENV{DESTDIR}\${file}\\\"\")
        endif (NOT \${rm_retval} EQUAL 0)
    else (EXISTS \"\$ENV{DESTDIR}\${file}\")
        message(STATUS \"File \\\"\$ENV{DESTDIR}\${file}\\\" does not exist.\")
    endif (EXISTS \"\$ENV{DESTDIR}\${file}\")
endforeach(file)

") # END of appending to file...
    endif()
endfunction()
# End of the uninstaller generator

execute_process(COMMAND git describe --always
	WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}
	RESULT_VARIABLE git_result
	OUTPUT_VARIABLE git_ver)

STRING(REGEX REPLACE "\n" "" git_ver "${git_ver}")
add_definitions(-DHASH="${git_ver}")

include_directories("${PROJECT_SOURCE_DIR}/libs/zfsguru/")

file(GLOB zfsguru_headers
	"${PROJECT_SOURCE_DIR}/libs/zfsguru/*.h")

file(GLOB zfsguru
	"${PROJECT_SOURCE_DIR}/libs/zfsguru/*.c")

find_package(Threads REQUIRED)

configure_file(zfsguru.h.in zfsguru.h)

add_library(zfsguru OBJECT ${zfsguru})
add_library(zfsguru_static STATIC $<TARGET_OBJECTS:zfsguru>)
target_link_libraries(zfsguru_static ${CMAKE_THREAD_LIBS_INIT})

set_target_properties(zfsguru_static PROPERTIES OUTPUT_NAME zfsguru)

set_source_files_properties(${PROJECT_SOURCE_DIR}/libs/zfsguru/json.c PROPERTIES COMPILE_FLAGS " -w ")
set_source_files_properties(${PROJECT_SOURCE_DIR}/libs/zfsguru/mongoose.c PROPERTIES COMPILE_FLAGS " -w ")

if(NOT EXISTS "/etc/zfsguru/settings.json")
	install(FILES settings.json-default DESTINATION /etc/zfsguru/ RENAME settings.json)
endif()

add_executable(zfsguru-webserver daemon.c)

target_link_libraries(zfsguru-webserver zfsguru_static)
target_link_libraries(zfsguru-webserver ${CMAKE_DL_LIBS})
target_link_libraries(zfsguru-webserver ${CMAKE_THREAD_LIBS_INIT})

install(PROGRAMS zfsguru-webserver DESTINATION sbin)

WRITE_UNINSTALL_TARGET_SCRIPT()
configure_file("${CMAKE_CURRENT_BINARY_DIR}/cmake_uninstall.cmake.in"
	"${CMAKE_CURRENT_BINARY_DIR}/cmake_uninstall.cmake"
    IMMEDIATE @ONLY)
add_custom_target(uninstall COMMAND ${CMAKE_COMMAND} -P ${CMAKE_CURRENT_BINARY_DIR}/cmake_uninstall.cmake)
