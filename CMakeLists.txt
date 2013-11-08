cmake_minimum_required(VERSION 2.8)

project(masquerade C)

set(MASQUERADE_BLOCK_MAJOR_VERSION 0)
set(MASQUERADE_BLOCK_MINOR_VERSION 1)
set(FOOBAR_VERSION ${FOOBAR_MAJOR_VERSION}.${FOOBAR_MINOR_VERSION})

set(INSTALL_LIB_DIR lib/dnscrypt-proxy CACHE PATH "Installation directory for libraries")

find_library(LDNS_LIBRARY NAMES ldns libldns)

add_library(masquerade SHARED masquerade.c)

target_link_libraries(masquerade ldns)

install(TARGETS masquerade DESTINATION ${INSTALL_LIB_DIR})

