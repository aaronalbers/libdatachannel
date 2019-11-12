cmake_minimum_required (VERSION 3.7)
project (libdatachannel
	DESCRIPTION "WebRTC Data Channels Library"
	VERSION 0.2.1
	LANGUAGES CXX)

set(CMAKE_POSITION_INDEPENDENT_CODE ON)
set(CMAKE_MODULE_PATH ${PROJECT_SOURCE_DIR}/cmake/Modules)

set(LIBDATACHANNEL_SOURCES
	candidate.cpp
	certificate.cpp
	channel.cpp
	configuration.cpp
	datachannel.cpp
	description.cpp
	dtlstransport.cpp
	icetransport.cpp
	peerconnection.cpp
	rtc.cpp
	sctptransport.cpp
)

set(TESTS_SOURCES
    main.cpp
)

list(TRANSFORM LIBDATACHANNEL_SOURCES PREPEND ${CMAKE_CURRENT_SOURCE_DIR}/src/)
list(TRANSFORM TESTS_SOURCES PREPEND ${CMAKE_CURRENT_SOURCE_DIR}/test/)

# Hack because usrsctp uses CMAKE_SOURCE_DIR instead of CMAKE_CURRENT_SOURCE_DIR
set(CMAKE_REQUIRED_FLAGS "-I${CMAKE_CURRENT_SOURCE_DIR}/usrsctp/usrsctplib")

add_subdirectory(usrsctp EXCLUDE_FROM_ALL)

# Set include directory and custom options to make usrsctp compile with recent g++
target_include_directories(usrsctp-static PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/usrsctp/usrsctplib)

if (CMAKE_CXX_COMPILER_ID MATCHES "Clang")
  # using regular Clang or AppleClang since it doesn't have -Wno-error=format-truncation
  target_compile_options(usrsctp-static PRIVATE -Wno-error=address-of-packed-member)
else()
  # all other compilers
  target_compile_options(usrsctp-static PRIVATE -Wno-error=address-of-packed-member -Wno-error=format-truncation)
endif()

if (OPENSSL_ROOT_DIR)
  add_definitions(-DUSE_OPENSSL)
  find_package(OpenSSL REQUIRED)
else()
  find_package(GnuTLS REQUIRED)
endif()
find_package(LibNice REQUIRED)

if (NOT TARGET GnuTLS::GnuTLS AND NOT OPENSSL_ROOT_DIR)
    add_library(GnuTLS::GnuTLS UNKNOWN IMPORTED)
    set_target_properties(GnuTLS::GnuTLS PROPERTIES
        INTERFACE_INCLUDE_DIRECTORIES "${GNUTLS_INCLUDE_DIRS}"
        INTERFACE_COMPILE_DEFINITIONS "${GNUTLS_DEFINITIONS}"
        IMPORTED_LINK_INTERFACE_LANGUAGES "C"
		IMPORTED_LOCATION "${GNUTLS_LIBRARIES}")
endif()

add_library(datachannel SHARED ${LIBDATACHANNEL_SOURCES})
set_target_properties(datachannel PROPERTIES
	VERSION ${PROJECT_VERSION}
	CXX_STANDARD 17)

target_include_directories(datachannel PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_include_directories(datachannel PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include/rtc)
target_include_directories(datachannel PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)

if (OPENSSL_ROOT_DIR)
  target_include_directories(datachannel PRIVATE ${OPENSSL_ROOT_DIR}/include)
  target_link_libraries(datachannel usrsctp-static OpenSSL::SSL LibNice::LibNice)
else()
  target_link_libraries(datachannel usrsctp-static GnuTLS::GnuTLS LibNice::LibNice)
endif()

add_library(datachannel-static STATIC EXCLUDE_FROM_ALL ${LIBDATACHANNEL_SOURCES})
set_target_properties(datachannel-static PROPERTIES
	VERSION ${PROJECT_VERSION}
	CXX_STANDARD 17)

target_include_directories(datachannel-static PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_include_directories(datachannel-static PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include/rtc)
target_include_directories(datachannel-static PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)

if (OPENSSL_ROOT_DIR)
  target_include_directories(datachannel-static PRIVATE ${OPENSSL_ROOT_DIR}/include)
  target_link_libraries(datachannel-static usrsctp-static OpenSSL::SSL LibNice::LibNice)
else()
  target_link_libraries(datachannel-static usrsctp-static GnuTLS::GnuTLS LibNice::LibNice)
endif()

add_library(LibDataChannel::LibDataChannel ALIAS datachannel)
add_library(LibDataChannel::LibDataChannelStatic ALIAS datachannel-static)

add_executable(tests ${TESTS_SOURCES})
set_target_properties(tests PROPERTIES
	VERSION ${PROJECT_VERSION}
	CXX_STANDARD 17)

target_link_libraries(tests datachannel)

