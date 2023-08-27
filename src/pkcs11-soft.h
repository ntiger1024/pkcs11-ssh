#ifndef PKCS11_H_
#define PKCS11_H_

/* Cryptoki macros. */
#define CK_PTR *
#define CK_DECLARE_FUNCTION(returnType, name) \
    returnType name
#define CK_DECLARE_FUNCTION_POINTER(returnType, name) \
    returnType (* name)
#define CK_CALLBACK_FUNCTION(returnType, name) \
    returnType (* name)
#ifndef NULL_PTR
#define NULL_PTR 0
#endif /* NULL_PTR */

#include "cryptoki/pkcs11.h"

/* Debug */
#define error(fmt, ...) fprintf(stderr, "%s %d: " fmt, __FILE__,\
    __LINE__, ##__VA_ARGS__)

#ifdef DEBUG
#define debug error
#else
#define debug(...)
#endif

/* Library informations. */
#define MANUFACTURER_ID "ntiger1024"
#define LIB_DESCRIPTION "Soft pkcs11 token lib"
#define LIB_VERSION_MAJOR 0
#define LIB_VERSION_MINOR 1

#define SLOT_ID_SIGNER 0
#define NUM_SLOT_ID 1
#define SLOT_DESCRIPTION "Soft pkcs11 mock slot"
#define SLOT_HW_VERSION_MAJOR 0
#define SLOT_HW_VERSION_MINOR 1
#define SLOT_FW_VERSION_MAJOR 0
#define SLOT_FW_VERSION_MINOR 1

#define LABEL "Soft pkcs11 mock token"
#define MODEL "Soft HSM"
#define SERIAL_NUMBER "0000000000000001"

#define SESSION_ID 0
#define RSA_PUB_HANDLE 1
#define RSA_PRIV_HANDLE 2

#endif /* PKCS11_H_ */
