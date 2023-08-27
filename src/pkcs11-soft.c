#include "pkcs11-soft.h"

#define OPENSSL_API_COMPAT 0x10101000L
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/evp.h>

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define CHECK_INIT() do {\
    if (!g_initialized) {\
        error("Not initialzied\n");\
        return CKR_CRYPTOKI_NOT_INITIALIZED;\
    }\
} while(0)

#define CHECK_NOT_NULL(ptr) do {\
    if (ptr == NULL_PTR) {\
        error(#ptr " is NULL_PTR\n");\
        return CKR_ARGUMENTS_BAD;\
    }\
} while (0)

#define CHECK_NULL(ptr) do {\
    if (ptr != NULL_PTR) {\
        error(#ptr " is not NULL_PTR\n");\
        return CKR_ARGUMENTS_BAD;\
    }\
} while (0)

#define NUM_ARRAY_ELEMENTS(arr) (sizeof(arr) / sizeof(arr[0]))

const char PUBLIC_KEY[] =
    "-----BEGIN PUBLIC KEY-----\n"
    "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAt+FLUje1BIeKT3xdUpae\n"
    "szQSyqZPtmgki0BdhTaZXSGYlZhWE7qF0VbWCVwtRAbCNLfaOubmE34vsiT62F34\n"
    "UV5iZxQTfrxp0BO7/F3wyh/Vi/vsduyi/raSlkVLhfWrCsQWDnAFDA40BeaF3nNK\n"
    "9CXunHszKED5GIwhw0c3W0LAxFIkVs2VSkJ84ZBnQzRsUL01CSKPHvx7qlDT2hbB\n"
    "B2tIOmBAzhg/sHDUuf9Y5OgCGAOOM2g/8563nitlxiS9azsyt2gbQjpy3xZk+WQB\n"
    "qsB1Loc6TpoXxZNwbj3aowqGPO7YsOagq7oLZFEcmIK6aX/ZUrvXCjP/CvQfVKcH\n"
    "AQIDAQAB\n"
    "-----END PUBLIC KEY-----";
const char PRIVATE_KEY[] =
    "-----BEGIN PRIVATE KEY-----\n"
    "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC34UtSN7UEh4pP\n"
    "fF1Slp6zNBLKpk+2aCSLQF2FNpldIZiVmFYTuoXRVtYJXC1EBsI0t9o65uYTfi+y\n"
    "JPrYXfhRXmJnFBN+vGnQE7v8XfDKH9WL++x27KL+tpKWRUuF9asKxBYOcAUMDjQF\n"
    "5oXec0r0Je6cezMoQPkYjCHDRzdbQsDEUiRWzZVKQnzhkGdDNGxQvTUJIo8e/Huq\n"
    "UNPaFsEHa0g6YEDOGD+wcNS5/1jk6AIYA44zaD/znreeK2XGJL1rOzK3aBtCOnLf\n"
    "FmT5ZAGqwHUuhzpOmhfFk3BuPdqjCoY87tiw5qCrugtkURyYgrppf9lSu9cKM/8K\n"
    "9B9UpwcBAgMBAAECggEAFD3IcxE/S7OY6dWMl1gNubfYfrbOjQuLREnuUYj4Wmxl\n"
    "lcgaZ5sPeoMW1hpvwC6HR9LaQsQinRA1s2RHObSkbl6XsfWfjMK0Wiul9KqppDJb\n"
    "aUiu18uGSMgzvDd+EA3CSZHaxLWXlKNmniSpZVqnLFeVm+Oi9sIqOYXJfKvU/+ZZ\n"
    "ufiUkQC2LO3OXcIVk8zBLSNB7UsSmBYb1pW4NzsYCbrYO7agW8gM1yzhWWerFixx\n"
    "n1ZP6Wh3wPsVBh5cEFZXLzNmKot7WAYNQRZFh983ymP+IRWwAaXM8J1UQ6XBfJck\n"
    "5KZabIKQe85dhTgA2iYECq7siuJNjWqbWbFg91LK8QKBgQC7v8BxTfkDvJAKCBLA\n"
    "J2v6d5xdKfm+E6UMbNQ91cvHICP7xrbmpDAVUHALn8fTiMQhQkQ6R0D6Y0R/psdl\n"
    "JxFAA2wYVjfCCbwIv8unhQRnGOxsUA6pn9qIbILzosR0sThQZjgCbkdni6rcZi2s\n"
    "/HIz9Htk0yyF7aL3u1oqBiNROQKBgQD6uX0yReZLyMxsGuaiEJop8ONYSpLS+P0J\n"
    "0PYst0CK9v5pwHKoa8VZn+U69vYqiC9rESJnI4qZKQZkq7akKpA/ItupI5uSRaLN\n"
    "wpXrn/DLi15mbF/YredKojLwbLEz+A/ZUWwunVu9OVSJc2GPNDQlTxf7Up1BhpdM\n"
    "zF5Ymu6MCQKBgEIwF2faVS88Cot+zR1wyGBESpuNcL3Rrx3yP+CMvoo0inr4UwJ8\n"
    "X3ckJFv0uD2auYoAEo15ES80T7Gw2hqO60Xl7vWlb4K4a9Gpy+ICwsqVvsNwdbrW\n"
    "3/O4TXIWr6tzzqaJYrV4qzOVyWZpnzCczqYCSn4A9HFClXFAW0j1YP4BAoGAKt3t\n"
    "5tuGnWxubwlGZ20ZPpR9+kl9wu5pLPV6MXj/YwMJyoDp2ZvbeRBae/NfcTQpj0+1\n"
    "pxavirI18p5dMsJIOVM3ZTq+TYr0Y+OiCFAnNlXUxQRAeuZ4xgznUq3yuiTuaMSA\n"
    "D5Q97CNSLdH5Wyecxsg4HHMqidp+IdZLRzDuGikCgYEAk13eCZVpJ+nuoJ7FAT2K\n"
    "xtbqJ4lVfNX2+xtq0GwI5JIL9m0+yfB7ZsokDJ0UHQ4Yjozho0lu3xpcIlrPqEdW\n"
    "pbUI4HUlGjy216A4YZurzz726f7a3M0q9O7y1jWoHvqQ0hN51/shPhCVPzBFoXeE\n"
    "q51HGwJf+ptYa48oMfIZnDM=\n"
    "-----END PRIVATE KEY-----";

static int g_initialized = 0;
static CK_FUNCTION_LIST g_function_list = {
    {CRYPTOKI_VERSION_MAJOR, CRYPTOKI_VERSION_MINOR},
    C_Initialize,
    C_Finalize,
    C_GetInfo,
    C_GetFunctionList,
    C_GetSlotList,
    C_GetSlotInfo,
    C_GetTokenInfo,
    C_GetMechanismList,
    C_GetMechanismInfo,
    NULL_PTR,
    NULL_PTR,
    NULL_PTR,
    C_OpenSession,
    C_CloseSession,
    C_CloseAllSessions,
    C_GetSessionInfo,
    NULL_PTR,
    NULL_PTR,
    NULL_PTR,
    NULL_PTR,
    NULL_PTR,
    NULL_PTR,
    NULL_PTR,
    NULL_PTR,
    C_GetAttributeValue,
    NULL_PTR,
    C_FindObjectsInit,
    C_FindObjects,
    C_FindObjectsFinal,
    NULL_PTR,
    NULL_PTR,
    NULL_PTR,
    NULL_PTR,
    NULL_PTR,
    NULL_PTR,
    NULL_PTR,
    NULL_PTR,
    NULL_PTR,
    NULL_PTR,
    NULL_PTR,
    NULL_PTR,
    NULL_PTR,
    C_SignInit,
    C_Sign,
};

static CK_MECHANISM_TYPE g_machanism_type_list[] = {
    CKM_RSA_PKCS,
};

static CK_OBJECT_HANDLE g_object_handle = CK_INVALID_HANDLE;
static CK_OBJECT_HANDLE g_signing_key = CK_INVALID_HANDLE;

static void copy_string(CK_UTF8CHAR_PTR buf, unsigned long size,
        const char *content)
{
    memset(buf, ' ', size);
    if (content) {
        memcpy(buf, content, strlen(content));
    }
}

CK_DECLARE_FUNCTION(CK_RV, C_Initialize)(CK_VOID_PTR pInitArgs)
{
    CK_C_INITIALIZE_ARGS_PTR argp;

    debug("C_Initialize\n");

    if (g_initialized) {
        error("Already initialzied\n");
        return CKR_CRYPTOKI_ALREADY_INITIALIZED;
    }

    /* We don't support multithread.*/
    if (pInitArgs != NULL_PTR) {
        argp = (CK_C_INITIALIZE_ARGS_PTR) pInitArgs;
        if (argp->pReserved != NULL_PTR) {
            error("pReserved is not NULL_PTR\n");
            return CKR_ARGUMENTS_BAD;
        } else if ((argp->flags & CKF_OS_LOCKING_OK)
                || argp->CreateMutex) {
            error("Cannot support multithread\n");
            return CKR_CANT_LOCK;
        }
    }

    g_initialized = 1;
    return CKR_OK;
}

CK_DECLARE_FUNCTION(CK_RV, C_Finalize)(CK_VOID_PTR pReserved)
{
    debug("C_Finalize\n");
    CHECK_INIT();
    CHECK_NULL(pReserved);

    g_initialized = 0;
    return CKR_OK;
}

CK_DECLARE_FUNCTION(CK_RV, C_GetInfo)(CK_INFO_PTR pInfo)
{
    debug("C_GetInfo\n");
    CHECK_INIT();
    CHECK_NOT_NULL(pInfo);

    pInfo->cryptokiVersion.major = CRYPTOKI_VERSION_MAJOR;
    pInfo->cryptokiVersion.minor = CRYPTOKI_VERSION_MINOR;
    copy_string(pInfo->manufacturerID, sizeof(pInfo->manufacturerID),
            MANUFACTURER_ID);
    pInfo->flags = 0;
    copy_string(pInfo->libraryDescription, sizeof(pInfo->libraryDescription),
            LIB_DESCRIPTION);
    pInfo->libraryVersion.major = LIB_VERSION_MAJOR;
    pInfo->libraryVersion.minor = LIB_VERSION_MINOR;
    return CKR_OK;
}

CK_DECLARE_FUNCTION(CK_RV, C_GetFunctionList)(
        CK_FUNCTION_LIST_PTR_PTR ppFunctionList)
{
    debug("C_GetFunctionList\n");
    CHECK_NOT_NULL(ppFunctionList);

    *ppFunctionList = &g_function_list;
    return CKR_OK;
}

CK_DECLARE_FUNCTION(CK_RV, C_GetSlotList)(CK_BBOOL tokenPresent,
        CK_SLOT_ID_PTR pSlotList, CK_ULONG_PTR pulCount)
{
    debug("C_GetSlotList\n");
    CHECK_INIT();
    CHECK_NOT_NULL(pulCount);

    if (pSlotList) {
        if (*pulCount < NUM_SLOT_ID) {
            error("pulCount too small\n");
            return CKR_BUFFER_TOO_SMALL;
        }
        pSlotList[0] = SLOT_ID_SIGNER;
    }
    *pulCount = NUM_SLOT_ID;
    return CKR_OK;
}

CK_DECLARE_FUNCTION(CK_RV, C_GetSlotInfo)(CK_SLOT_ID slotId,
        CK_SLOT_INFO_PTR pInfo)
{
    debug("C_GetSlotInfo\n");
    CHECK_INIT();
    CHECK_NOT_NULL(pInfo);

    if (slotId >= NUM_SLOT_ID) {
        error("Invalid slot id: %ld\n", slotId);
        return CKR_ARGUMENTS_BAD;
    }

    copy_string(pInfo->slotDescription, sizeof(pInfo->slotDescription),
            SLOT_DESCRIPTION);
    copy_string(pInfo->manufacturerID, sizeof(pInfo->manufacturerID),
            MANUFACTURER_ID);
    pInfo->hardwareVersion.major = SLOT_HW_VERSION_MAJOR;
    pInfo->hardwareVersion.minor = SLOT_HW_VERSION_MINOR;
    pInfo->firmwareVersion.major = SLOT_FW_VERSION_MAJOR;
    pInfo->firmwareVersion.minor = SLOT_FW_VERSION_MINOR;
    pInfo->flags = CKF_TOKEN_PRESENT;

    return CKR_OK;
}

CK_DECLARE_FUNCTION(CK_RV, C_GetTokenInfo)(CK_SLOT_ID slotId,
        CK_TOKEN_INFO_PTR pInfo)
{
    debug("C_GetTokenInfo\n");
    CHECK_INIT();
    CHECK_NOT_NULL(pInfo);
    if (slotId >= NUM_SLOT_ID) {
        error("Invalid slot ID: %ld\n", slotId);
        return CKR_ARGUMENTS_BAD;
    }

    copy_string(pInfo->label, sizeof(pInfo->label), LABEL);
    copy_string(pInfo->manufacturerID, sizeof(pInfo->manufacturerID),
                MANUFACTURER_ID);
    copy_string(pInfo->model, sizeof(pInfo->model), MODEL);
    copy_string(pInfo->serialNumber, sizeof(pInfo->serialNumber),
            SERIAL_NUMBER);
    pInfo->flags = CKF_WRITE_PROTECTED | CKF_TOKEN_INITIALIZED
        | CKF_USER_PIN_INITIALIZED;
    pInfo->ulMaxSessionCount = CK_UNAVAILABLE_INFORMATION;
    pInfo->ulSessionCount = CK_UNAVAILABLE_INFORMATION;
    pInfo->ulMaxRwSessionCount = CK_UNAVAILABLE_INFORMATION;
    pInfo->ulRwSessionCount = CK_UNAVAILABLE_INFORMATION;
    pInfo->ulMaxPinLen = 0;
    pInfo->ulMinPinLen = 0;
    pInfo->ulTotalPublicMemory = CK_UNAVAILABLE_INFORMATION;
    pInfo->ulFreePublicMemory = CK_UNAVAILABLE_INFORMATION;
    pInfo->ulTotalPrivateMemory = CK_UNAVAILABLE_INFORMATION;
    pInfo->ulFreePrivateMemory = CK_UNAVAILABLE_INFORMATION;
    pInfo->hardwareVersion.major = SLOT_HW_VERSION_MAJOR;
    pInfo->hardwareVersion.minor = SLOT_HW_VERSION_MINOR;
    pInfo->firmwareVersion.major = SLOT_FW_VERSION_MAJOR;
    pInfo->firmwareVersion.minor = SLOT_FW_VERSION_MINOR;
    copy_string(pInfo->utcTime, sizeof(pInfo->utcTime), NULL_PTR);

    return CKR_OK;
}

CK_DECLARE_FUNCTION(CK_RV, C_GetMechanismList)(CK_SLOT_ID slotId,
        CK_MECHANISM_TYPE_PTR pMechanismList,
        CK_ULONG_PTR pulCount)
{
    CK_RV rv = CKR_OK;
    unsigned long count = NUM_ARRAY_ELEMENTS(g_machanism_type_list);

    debug("C_GetMechanismList\n");
    CHECK_INIT();
    CHECK_NOT_NULL(pulCount);
    if (slotId >= NUM_SLOT_ID) {
        error("Invalid slot id: %ld\n", slotId);
        return CKR_ARGUMENTS_BAD;
    }

    if (pMechanismList) {
        if (*pulCount < count) {
            error("pulCount too small\n");
            rv = CKR_BUFFER_TOO_SMALL;
        } else {
            memcpy(pMechanismList, g_machanism_type_list,
                    sizeof(g_machanism_type_list));
        }
    }
    *pulCount = count;
    return rv;
}

CK_DECLARE_FUNCTION(CK_RV, C_GetMechanismInfo)(CK_SLOT_ID slotId,
        CK_MECHANISM_TYPE type, CK_MECHANISM_INFO_PTR pInfo)
{
    debug("C_GetMechanismInfo\n");
    CHECK_INIT();
    CHECK_NOT_NULL(pInfo);
    if (slotId >= NUM_SLOT_ID) {
        error("Invalid slot id: %ld\n", slotId);
        return CKR_ARGUMENTS_BAD;
    }

    switch (type) {
        case CKM_RSA_PKCS:
            pInfo->ulMaxKeySize = 2048;
            pInfo->ulMinKeySize = 2048;
            pInfo->flags = CKF_HW | CKF_SIGN;
            break;
        default:
            error("Invalid type: %ld\n", type);
            return CKR_ARGUMENTS_BAD;
    }
    return CKR_OK;
}

CK_DECLARE_FUNCTION(CK_RV, C_OpenSession)(CK_SLOT_ID slotId,
        CK_FLAGS flags, CK_VOID_PTR pApplication, CK_NOTIFY notify,
        CK_SESSION_HANDLE_PTR phSession)
{
    debug("C_OpenSession\n");
    CHECK_INIT();
    CHECK_NOT_NULL(phSession);
    if (slotId >= NUM_SLOT_ID) {
        error("Invalid slot id: %ld\n", slotId);
        return CKR_ARGUMENTS_BAD;
    }
    *phSession = SESSION_ID;
    return CKR_OK;
}

CK_DECLARE_FUNCTION(CK_RV, C_CloseSession)(CK_SESSION_HANDLE hSession)
{
    debug("C_CloseSession\n");
    CHECK_INIT();
    if (hSession != SESSION_ID) {
        error("Invalid session id: %ld\n", hSession);
        return CKR_SESSION_HANDLE_INVALID;
    }
    return CKR_OK;
}

CK_DECLARE_FUNCTION(CK_RV, C_CloseAllSessions)(CK_SLOT_ID slotId)
{
    debug("C_CloseAllSessions\n");
    CHECK_INIT();
    if (slotId >= NUM_SLOT_ID) {
        error("Invalid slot id: %ld\n", slotId);
        return CKR_ARGUMENTS_BAD;
    }
    return CKR_OK;
}

CK_DECLARE_FUNCTION(CK_RV, C_GetSessionInfo)(CK_SESSION_HANDLE hSession,
        CK_SESSION_INFO_PTR pInfo)
{
    debug("C_GetSessionInfo\n");
    CHECK_INIT();
    if (hSession != SESSION_ID) {
        error("Invalid session id: %ld\n", hSession);
        return CKR_SESSION_HANDLE_INVALID;
    }
    CHECK_NOT_NULL(pInfo);

    pInfo->slotID = SLOT_ID_SIGNER;
    pInfo->state = CKS_RO_PUBLIC_SESSION;
    pInfo->flags = CKF_SERIAL_SESSION;
    pInfo->ulDeviceError = 0;

    return CKR_OK;
}

CK_DECLARE_FUNCTION(CK_RV, C_FindObjectsInit)(CK_SESSION_HANDLE hSession,
        CK_ATTRIBUTE_PTR pTemplate,
        CK_ULONG ulCount)
{
    unsigned long i;

    debug("C_FindObjectInit\n");
    g_object_handle = CK_INVALID_HANDLE;

    CHECK_INIT();
    CHECK_NOT_NULL(pTemplate);
    if (hSession != SESSION_ID) {
        error("Invalid session id: %ld\n", hSession);
        return CKR_SESSION_HANDLE_INVALID;
    }
    for (i = 0; i < ulCount; ++i) {
        if (pTemplate[i].type == CKA_CLASS) {
            if (pTemplate[i].pValue == NULL_PTR ||
                    pTemplate[i].ulValueLen < sizeof(CK_OBJECT_CLASS)) {
                error("Invalid pValue\n");
                return CKR_ATTRIBUTE_VALUE_INVALID;
            }
           CK_OBJECT_CLASS class = *(CK_OBJECT_CLASS_PTR)pTemplate[i].pValue;
           switch (class) {
               case CKO_PUBLIC_KEY:
                   g_object_handle = RSA_PUB_HANDLE;
                   break;
               case CKO_PRIVATE_KEY:
                   g_object_handle = RSA_PRIV_HANDLE;
                   break;
           }
        }
    }
    return CKR_OK;
}

CK_DECLARE_FUNCTION(CK_RV, C_FindObjects)(CK_SESSION_HANDLE hSession,
        CK_OBJECT_HANDLE_PTR phObject, CK_ULONG ulMaxObjectCount,
        CK_ULONG_PTR pulObjectCount)
{
    debug("C_FindObjects\n");
    CHECK_INIT();
    if (hSession != SESSION_ID) {
        error("Invalid session id: %ld\n", hSession);
        return CKR_SESSION_HANDLE_INVALID;
    }
    CHECK_NOT_NULL(phObject);
    CHECK_NOT_NULL(pulObjectCount);
    if (ulMaxObjectCount == 0) {
        error("Invalid ulMaxObjectCount\n");
        return CKR_ARGUMENTS_BAD;
    }
    if (g_object_handle == CK_INVALID_HANDLE) {
        *pulObjectCount = 0;
    } else {
        *pulObjectCount = 1;
        *phObject = g_object_handle;
        g_object_handle = CK_INVALID_HANDLE;
    }

    return CKR_OK;
}

CK_DECLARE_FUNCTION(CK_RV, C_FindObjectsFinal)(CK_SESSION_HANDLE hSession)
{
    debug("C_FindObjectsFinal\n");
    CHECK_INIT();
    if (hSession != SESSION_ID) {
        error("Invalid session id: %ld\n", hSession);
        return CKR_SESSION_HANDLE_INVALID;
    }
    g_object_handle = CK_INVALID_HANDLE;

    return CKR_OK;
}

static CK_RV get_privkey_attributes(CK_ATTRIBUTE_PTR template, CK_ULONG count)
{
    CK_ULONG i;
    CK_RV rv = CKR_OK;
    static CK_UTF8CHAR label[] = "Soft RSA 2048 Private Key";
    static CK_BYTE id[] = {1};
    CK_BBOOL sign = CK_TRUE;
    CK_BBOOL auth = CK_FALSE;

    for (i = 0; i < count; ++i) {
        debug("template[i].type: %lx\n", template[i].type);
        if (template[i].type == CKA_CLASS) {
            if (template[i].pValue == NULL_PTR) {
                template[i].ulValueLen = sizeof(CK_OBJECT_CLASS);
            } else if (template[i].ulValueLen >= sizeof(CK_OBJECT_CLASS)) {
                *(CK_OBJECT_CLASS_PTR)template[i].pValue = CKO_PRIVATE_KEY;
                template[i].ulValueLen = sizeof(CK_OBJECT_CLASS);
            } else {
                template[i].ulValueLen = CK_UNAVAILABLE_INFORMATION;
                rv = CKR_BUFFER_TOO_SMALL;
            }
        } else if (template[i].type == CKA_LABEL) {
            if (template[i].pValue == NULL_PTR) {
                template[i].ulValueLen = sizeof(label);
            } else if (template[i].ulValueLen >= sizeof(label)) {
                memcpy(template[i].pValue, label, sizeof(label));
                template[i].ulValueLen = sizeof(label);
            } else {
                template[i].ulValueLen = CK_UNAVAILABLE_INFORMATION;
                rv = CKR_BUFFER_TOO_SMALL;
            }
        } else if (template[i].type == CKA_KEY_TYPE) {
            if (template[i].pValue == NULL_PTR) {
                template[i].ulValueLen = sizeof(CK_KEY_TYPE);
            } else if (template[i].ulValueLen >= sizeof(CK_KEY_TYPE)) {
                *(CK_KEY_TYPE *)template[i].pValue = CKK_RSA;
                template[i].ulValueLen = sizeof(CK_KEY_TYPE);
            } else {
                template[i].ulValueLen = CK_UNAVAILABLE_INFORMATION;
                rv = CKR_BUFFER_TOO_SMALL;
            }
        } else if (template[i].type == CKA_ID) {
            if (template[i].pValue == NULL_PTR) {
                template[i].ulValueLen = sizeof(id);
            } else if (template[i].ulValueLen >= sizeof(id)) {
                memcpy(template[i].pValue, id, sizeof(id));
                template[i].ulValueLen = sizeof(id);
            } else {
                template[i].ulValueLen = CK_UNAVAILABLE_INFORMATION;
                rv = CKR_BUFFER_TOO_SMALL;
            }
        } else if (template[i].type == CKA_SIGN) {
            if (template[i].pValue == NULL_PTR) {
                template[i].ulValueLen = sizeof(sign);
            } else if (template[i].ulValueLen >= sizeof(sign)) {
                memcpy(template[i].pValue, &sign, sizeof(sign));
                template[i].ulValueLen = sizeof(sign);
            } else {
                template[i].ulValueLen = CK_UNAVAILABLE_INFORMATION;
                rv = CKR_BUFFER_TOO_SMALL;
            }
        } else if (template[i].type == CKA_ALWAYS_AUTHENTICATE) {
            if (template[i].pValue == NULL_PTR) {
                template[i].ulValueLen = sizeof(auth);
            } else if (template[i].ulValueLen >= sizeof(auth)) {
                memcpy(template[i].pValue, &auth, sizeof(auth));
                template[i].ulValueLen = sizeof(auth);
            } else {
                template[i].ulValueLen = CK_UNAVAILABLE_INFORMATION;
                rv = CKR_BUFFER_TOO_SMALL;
            }
        } else {
            template[i].ulValueLen = CK_UNAVAILABLE_INFORMATION;
            rv = CKR_ATTRIBUTE_TYPE_INVALID;
        }
    }
    return rv;
}

static CK_RV get_pubkey_attributes(CK_ATTRIBUTE_PTR template, CK_ULONG count)
{
    CK_ULONG i;
    CK_RV rv = CKR_OK;
    EVP_PKEY *pkey = NULL;
    const RSA *rsa = NULL;
    BIO *bio = NULL;
    const BIGNUM *bnn = NULL, *bne = NULL;
    static unsigned char *n = NULL;
    static unsigned char *e = NULL;
    static unsigned key_size = 0;
    static unsigned n_size = 0;
    static unsigned e_size = 0;
    static CK_BYTE id[] = {1};
    static CK_UTF8CHAR label[] = "Soft RSA 2048 Public Key";

    bio = BIO_new_mem_buf(PUBLIC_KEY, sizeof(PUBLIC_KEY));
    if (!bio) {
        error("BIO error\n");
        rv = CKR_DEVICE_ERROR;
        goto out;
    }
    pkey = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
    if (!pkey) {
        error("PEM error\n");
        rv = CKR_DEVICE_ERROR;
        goto out;
    }
    rsa = EVP_PKEY_get0_RSA(pkey);
    if (!rsa) {
        error("No RSA key\n");
        rv = CKR_DEVICE_ERROR;
        goto out;
    }
    bnn = RSA_get0_n(rsa);
    bne = RSA_get0_e(rsa);
    if (bnn == NULL || bne == NULL) {
        error("RSA error\n");
        rv = CKR_DEVICE_ERROR;
    }
    if (key_size == 0) {
        key_size = RSA_size(rsa);
        n_size = BN_num_bytes(bnn);
        e_size = BN_num_bytes(bne);
        n = malloc(n_size);
        if (!n) goto out;
        e = malloc(e_size);
        if (!e) goto out;
        if (BN_bn2bin(bnn, n) == -1) {
            goto err;
        }
        if (BN_bn2bin(bne, e) == -1) {
            goto err;
        }
    }

    for (i = 0; i < count; ++i) {
        debug("template[i].type: %lx\n", template[i].type);
        if (template[i].type == CKA_CLASS) {
            if (template[i].pValue == NULL_PTR) {
                template[i].ulValueLen = sizeof(CK_OBJECT_CLASS);
            } else if (template[i].ulValueLen >= sizeof(CK_OBJECT_CLASS)) {
                *(CK_OBJECT_CLASS_PTR)template[i].pValue = CKO_PUBLIC_KEY;
                template[i].ulValueLen = sizeof(CK_OBJECT_CLASS);
            } else {
                template[i].ulValueLen = CK_UNAVAILABLE_INFORMATION;
                rv = CKR_BUFFER_TOO_SMALL;
            }
        } else if (template[i].type == CKA_LABEL) {
            if (template[i].pValue == NULL_PTR) {
                template[i].ulValueLen = sizeof(label);
            } else if (template[i].ulValueLen >= sizeof(label)) {
                memcpy(template[i].pValue, label, sizeof(label));
                template[i].ulValueLen = sizeof(label);
            } else {
                template[i].ulValueLen = CK_UNAVAILABLE_INFORMATION;
                rv = CKR_BUFFER_TOO_SMALL;
            }
        } else if (template[i].type == CKA_ID) {
            if (template[i].pValue == NULL_PTR) {
                template[i].ulValueLen = sizeof(id);
            } else if (template[i].ulValueLen >= sizeof(id)) {
                memcpy(template[i].pValue, id, sizeof(id));
                template[i].ulValueLen = sizeof(id);
            } else {
                template[i].ulValueLen = CK_UNAVAILABLE_INFORMATION;
                rv = CKR_BUFFER_TOO_SMALL;
            }
        } else if (template[i].type == CKA_KEY_TYPE) {
            if (template[i].pValue == NULL_PTR) {
                template[i].ulValueLen = sizeof(CK_KEY_TYPE);
            } else if (template[i].ulValueLen >= sizeof(CK_KEY_TYPE)) {
                *(CK_KEY_TYPE *)template[i].pValue = CKK_RSA;
                template[i].ulValueLen = sizeof(CK_KEY_TYPE);
            } else {
                template[i].ulValueLen = CK_UNAVAILABLE_INFORMATION;
                rv = CKR_BUFFER_TOO_SMALL;
            }
        } else if (template[i].type == CKA_MODULUS) {
            if (template[i].pValue == NULL_PTR) {
                template[i].ulValueLen = n_size;
            } else if (template[i].ulValueLen >= n_size) {
                memcpy(template[i].pValue, n, n_size);
                template[i].ulValueLen = n_size;
            } else {
                template[i].ulValueLen = CK_UNAVAILABLE_INFORMATION;
                rv = CKR_BUFFER_TOO_SMALL;
            }
        } else if (template[i].type == CKA_PUBLIC_EXPONENT) {
            if (template[i].pValue == NULL_PTR) {
                template[i].ulValueLen = n_size;
            } else if (template[i].ulValueLen >= e_size) {
                memcpy(template[i].pValue, e, e_size);
                template[i].ulValueLen = e_size;
            } else {
                template[i].ulValueLen = CK_UNAVAILABLE_INFORMATION;
                rv = CKR_BUFFER_TOO_SMALL;
            }
        } else {
            template[i].ulValueLen = CK_UNAVAILABLE_INFORMATION;
            rv = CKR_ATTRIBUTE_TYPE_INVALID;
        }
    }
    goto out;

err:
    key_size = 0;
    n_size = 0;
    e_size = 0;
    if (n) {
        free(n);
        n = NULL;
    }
    if (e) {
        free(e);
        e = NULL;
    }
out:
    // if (rsa) RSA_free(rsa);
    if (pkey) EVP_PKEY_free(pkey);
    if (bio) BIO_free(bio);
    debug("C_GetAttributeValue return: %lx\n", rv);
    return rv;
}

CK_DECLARE_FUNCTION(CK_RV, C_GetAttributeValue)(CK_SESSION_HANDLE hSession,
        CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate,
        CK_ULONG ulCount)
{
    debug("C_GetAttributeValue: hObject=%lx\n", hObject);
    CHECK_INIT();
    CHECK_NOT_NULL(pTemplate);
    if (hSession != SESSION_ID) {
        error("Invalid session id: %ld\n", hSession);
        return CKR_SESSION_HANDLE_INVALID;
    }
    if (hObject == RSA_PUB_HANDLE) {
        return get_pubkey_attributes(pTemplate, ulCount);
    } else if (hObject == RSA_PRIV_HANDLE) {
        return get_privkey_attributes(pTemplate, ulCount);
    } else {
        error("Invalid object handle\n");
        return CKR_OBJECT_HANDLE_INVALID;
    }

    return CKR_OK;
}

CK_DECLARE_FUNCTION(CK_RV, C_SignInit)(CK_SESSION_HANDLE hSession,
        CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
    CHECK_INIT();
    CHECK_NOT_NULL(pMechanism);
    if (hSession != SESSION_ID) {
        error("Invalid session id: %ld\n", hSession);
        return CKR_SESSION_HANDLE_INVALID;
    }
    if (pMechanism->mechanism != CKM_RSA_PKCS) {
        error("Invalid mechanism: %ld\n", pMechanism->mechanism);
        return CKR_MECHANISM_INVALID;
    }
    if (hKey != RSA_PRIV_HANDLE) {
        return CKR_KEY_HANDLE_INVALID;
    }
    g_signing_key = hKey;
    return CKR_OK;
}

static CK_RV rsa_sign(CK_BYTE_PTR tbs, CK_ULONG tbs_len,
        CK_BYTE_PTR signature, CK_ULONG_PTR signature_len)
{
    CK_RV rv = CKR_OK;
    BIO *bio = NULL;
    EVP_PKEY *pkey = NULL;
    RSA *rsa = NULL;

    bio = BIO_new_mem_buf(PRIVATE_KEY, sizeof(PRIVATE_KEY));
    if (!bio) {
        error("BIO error\n");
        rv = CKR_DEVICE_ERROR;
        goto out;
    }
    pkey = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
    if (!pkey) {
        error("PEM error\n");
        rv = CKR_DEVICE_ERROR;
        goto out;
    }
    rsa = (RSA*)EVP_PKEY_get0_RSA(pkey);
    if (!rsa) {
        error("PEM error\n");
        rv = CKR_DEVICE_ERROR;
        goto out;
    }
    *signature_len = RSA_private_encrypt(tbs_len, tbs, signature,
            rsa, RSA_PKCS1_PADDING);
    if (*signature_len == -1) {
        error("RSA error\n");
        rv = CKR_DEVICE_ERROR;
    }
out:
    if (bio) BIO_free(bio);
    if (rsa) RSA_free(rsa);
    return rv;
}

CK_DECLARE_FUNCTION(CK_RV, C_Sign)(CK_SESSION_HANDLE hSession,
        CK_BYTE_PTR pData, CK_ULONG ulDataLen,
        CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSigatureLen)
{
    debug("C_Sign\n");
    CHECK_INIT();
    if (hSession != SESSION_ID) {
        error("Invalid session id: %ld\n", hSession);
        return CKR_SESSION_HANDLE_INVALID;
    }

    return rsa_sign(pData, ulDataLen, pSignature, pulSigatureLen);
}
