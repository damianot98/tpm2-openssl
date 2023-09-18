/* SPDX-License-Identifier: BSD-3-Clause */

/* Partially based on openssl/providers/common/bio_prov.c */

#ifdef WITH_TSS2_RC
#include <tss2/tss2_rc.h>
#endif
#include "tpm2-provider.h"

static OSSL_FUNC_core_gettable_params_fn *c_gettable_params = NULL;
static OSSL_FUNC_core_get_params_fn *c_get_params = NULL;

static OSSL_FUNC_core_new_error_fn *c_new_error = NULL;
static OSSL_FUNC_core_set_error_debug_fn *c_set_error_debug = NULL;
static OSSL_FUNC_core_vset_error_fn *c_vset_error = NULL;

int
init_core_func_from_dispatch(const OSSL_DISPATCH *fns)
{
    ///////////////////////////////////////////////////////////////////////////////////////

    DBG("\ntpm2-provider-core.c init_core_funct_from_dispatch\n\n");

    ///////////////////////////////////////////////////////////////////////////////////////

    for (; fns->function_id != 0; fns++) {
        switch (fns->function_id) {
        case OSSL_FUNC_CORE_GETTABLE_PARAMS:
            if (c_gettable_params == NULL)
                c_gettable_params = OSSL_FUNC_core_gettable_params(fns);
            break;
        case OSSL_FUNC_CORE_GET_PARAMS:
            if (c_get_params == NULL)
                c_get_params = OSSL_FUNC_core_get_params(fns);
            break;

        case OSSL_FUNC_CORE_NEW_ERROR:
            if (c_new_error == NULL)
                c_new_error = OSSL_FUNC_core_new_error(fns);
            break;
        case OSSL_FUNC_CORE_SET_ERROR_DEBUG:
            if (c_set_error_debug == NULL)
                c_set_error_debug = OSSL_FUNC_core_set_error_debug(fns);
            break;
        case OSSL_FUNC_CORE_VSET_ERROR:
            if (c_vset_error == NULL)
                c_vset_error = OSSL_FUNC_core_vset_error(fns);
            break;
        }
    }

    return 1;
}

int
tpm2_core_get_params(const OSSL_CORE_HANDLE *prov, OSSL_PARAM params[])
{
    ///////////////////////////////////////////////////////////////////////////////////////

    DBG("\ntpm2-provider-core.c tpm2_core_get_params\n\n");

    ///////////////////////////////////////////////////////////////////////////////////////

    if (c_get_params == NULL)
        return 1;
    return c_get_params(prov, params);
}

void
tpm2_new_error(const OSSL_CORE_HANDLE *handle,
               uint32_t reason, const char *fmt, ...)
{
    ///////////////////////////////////////////////////////////////////////////////////////

    DBG("\ntpm2-provider-core.c tpm2_new_error\n\n");

    ///////////////////////////////////////////////////////////////////////////////////////

    if (c_new_error != NULL && c_vset_error != NULL) {
        va_list args;

        va_start(args, fmt);
        c_new_error(handle);
        c_vset_error(handle, reason, fmt, args);
        va_end(args);
    }
}

void
tpm2_new_error_rc(const OSSL_CORE_HANDLE *handle,
                  uint32_t reason, TSS2_RC rc)
{
#ifdef WITH_TSS2_RC

    ///////////////////////////////////////////////////////////////////////////////////////

    DBG("\ntpm2-provider-core.c tpm2_new_error_rc\n\n");

    ///////////////////////////////////////////////////////////////////////////////////////
    tpm2_new_error(handle, reason, "%i %s", rc, Tss2_RC_Decode(rc));
#else
    tpm2_new_error(handle, reason, "%i", rc);
#endif
}

void
tpm2_set_error_debug(const OSSL_CORE_HANDLE *handle,
                     const char *file, int line, const char *func)
{
    ///////////////////////////////////////////////////////////////////////////////////////

    DBG("\ntpm2-provider-core.c tpm2_set_error_debug\n\n");

    ///////////////////////////////////////////////////////////////////////////////////////

    if (c_set_error_debug != NULL)
        c_set_error_debug(handle, file, line, func);
}

void
tpm2_list_params(const char *text, const OSSL_PARAM params[])
{
    ///////////////////////////////////////////////////////////////////////////////////////

    DBG("\ntpm2-provider-core.c tpm2_list_params\n\n");

    ///////////////////////////////////////////////////////////////////////////////////////

    fprintf(stderr, "%s [", text);

    while (params->key != NULL) {
        fprintf(stderr, " %s", params->key);
        params++;
    }

    fprintf(stderr, " ]\n");
}

int
tpm2_supports_algorithm(const TPMS_CAPABILITY_DATA *caps, TPM2_ALG_ID algorithm)
{
    UINT32 index;

    ///////////////////////////////////////////////////////////////////////////////////////

    DBG("\ntpm2-provider-core.c tpm2_supports_algorithm\n\n");

    ///////////////////////////////////////////////////////////////////////////////////////

    for (index = 0; index < caps->data.algorithms.count; index++) {
        if (caps->data.algorithms.algProperties[index].alg == algorithm)
            return 1;
    }

    return 0;
}

int
tpm2_supports_command(const TPMS_CAPABILITY_DATA *caps, TPM2_CC command)
{
    UINT32 index;

    ///////////////////////////////////////////////////////////////////////////////////////

    DBG("\ntpm2-provider-core.c tpm2_supports_command\n\n");

    ///////////////////////////////////////////////////////////////////////////////////////

    for (index = 0; index < caps->data.command.count; index++) {
        if ((caps->data.command.commandAttributes[index] & TPMA_CC_COMMANDINDEX_MASK) == command)
            return 1;
    }

    return 0;
}

uint16_t
tpm2_max_nvindex_buffer(const TPMS_CAPABILITY_DATA *caps)
{
    UINT32 index;
    uint16_t max_nv_size = TPM2_MAX_NV_BUFFER_SIZE;

    ///////////////////////////////////////////////////////////////////////////////////////

    DBG("\ntpm2-provider-core.c tpm2_max_nvindex_buffer\n\n");

    ///////////////////////////////////////////////////////////////////////////////////////

    for (index = 0; index < caps->data.tpmProperties.count; index++) {
        if (caps->data.tpmProperties.tpmProperty[index].property == TPM2_PT_NV_BUFFER_MAX)
            return caps->data.tpmProperties.tpmProperty[index].value;
    }

    return max_nv_size;
}
