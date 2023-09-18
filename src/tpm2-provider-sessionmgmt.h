#ifndef TPM2_PROVIDER_SESSIONMGMT_H
#define TPM2_PROVIDER_SESSIONMGMT_H

#include <openssl/asn1t.h>
#include <openssl/asn1.h>
#include <openssl/pem.h>

#include "tpm2-provider.h"

#define TSSPRIVKEY_PEM_STRING "TSS2 PRIVATE KEY"

#define ENGINE_HASH_ALG TPM2_ALG_SHA256

TSS2_RC tpm2_start_auth_session(unsigned int session_type, 
                                ESYS_CONTEXT *esys_context,
                                unsigned int is_symmetric,
                                ESYS_TR *handle);

TSS2_RC tpm2_create_policy_digest(unsigned int pcr_number, 
                                ESYS_CONTEXT *esys_context,
                                ESYS_TR session_handle,
                                TPM2B_DIGEST *policy_digest);

TPM2B_NAME* tpm2_get_key_name(ESYS_CONTEXT *esys_context, ESYS_TR handle, ESYS_TR session_handle);


#endif /* TPM2_PROVIDER_SESSIONMGMT_H */