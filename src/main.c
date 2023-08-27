#include "pkcs11-soft.h"
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <stdio.h>

int main()
{
    CK_INFO info;
    CK_RV rv;
    CK_C_INITIALIZE_ARGS init_args;
    CK_FUNCTION_LIST_PTR p_function_list;
    CK_C_Initialize p_c_initialize;
    CK_C_Finalize p_c_finalize;

    memset(&init_args, 0, sizeof(init_args));
    rv = C_Initialize((CK_VOID_PTR)&init_args);
    assert(rv == CKR_OK);

    rv = C_GetInfo(&info);
    assert(rv == CKR_OK);
    printf("Cryptoki version    : %d.%d\n", info.cryptokiVersion.major,
            info.cryptokiVersion.minor);
    printf("Manufacture ID      : %*s\n", (int)sizeof(info.manufacturerID),
            info.manufacturerID);
    printf("Library description : %*s\n",
            (int)sizeof(info.libraryDescription), info.libraryDescription);
    printf("Library version     : %d.%d\n", info.libraryVersion.major,
            info.libraryVersion.minor);

    rv = C_Finalize(NULL_PTR);
    assert(rv == CKR_OK);

    rv = C_GetFunctionList(&p_function_list);
    assert(rv == CKR_OK);
    p_c_initialize = p_function_list->C_Initialize;
    rv = p_c_initialize(NULL_PTR);
    assert(rv == CKR_OK);

    p_c_finalize = p_function_list->C_Finalize;
    rv = p_c_finalize(NULL_PTR);
    assert(rv == CKR_OK);

    return 0;
}
