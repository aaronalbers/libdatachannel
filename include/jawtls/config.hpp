#pragma once

#define GNU_TLS_TARGET_PREFIX gnutls
#define OPEN_SSL_TARGET_PREFIX openssl

#ifndef JAW_TARGET_PREFIX
#  if __has_include(<gnutls/gnutls.h>)
#    define JAW_TARGET_PREFIX GNU_TLS_TARGET_PREFIX
#  elif __has_include(<openssl/ssl.h>)
#    define JAW_TARGET_PREFIX OPEN_SSL_TARGET_PREFIX
#  else
#    error No supported TLS library detected!
#  endif
#endif

// Macro for adding quotes
#define JAW_STRINGIFY(X) JAW_STRINGIFY2(X)
#define JAW_STRINGIFY2(X) #X

// Macros for concatenating tokens
#define JAW_CAT(X,Y) JAW_CAT2(X,Y)
#define JAW_CAT2(X,Y) X##Y
#define JAW_CAT_2 JAW_CAT
#define JAW_CAT_3(X,Y,Z) JAW_CAT(X,JAW_CAT(Y,Z))
#define JAW_CAT_4(A,X,Y,Z) JAW_CAT(A,JAW_CAT_3(X,Y,Z))

#define JAW_SELECT(FILE) JAW_STRINGIFY(JAW_CAT_3(JAW_TARGET_PREFIX, _, FILE))
