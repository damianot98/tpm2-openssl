#include <string.h>

#include <tss2/tss2_mu.h>

#include "tpm2-provider-sessionmgmt.h"


TSS2_RC tpm2_start_auth_session(unsigned int session_type, 
                                ESYS_CONTEXT *esys_context,
                                unsigned int is_symmetric,
                                ESYS_TR *handle){
    
    TSS2_RC rc;
    ESYS_TR session = ESYS_TR_NONE;

    TPM2B_NONCE nonce_caller = {
            .size = TPM2_SHA256_DIGEST_SIZE,
            .buffer = {0},
    };

    TPMT_SYM_DEF symmetric = {
            .algorithm = TPM2_ALG_NULL,
            .keyBits.aes = 0,
            .mode.aes = 0,
    };

    if (is_symmetric){
        symmetric.algorithm = TPM2_ALG_AES;
        symmetric.keyBits.aes = 128;
        symmetric.mode.aes = TPM2_ALG_CFB;
    }

    TPMA_SESSION sessionAttributes = (TPMA_SESSION_DECRYPT|TPMA_SESSION_ENCRYPT|TPMA_SESSION_CONTINUESESSION);
    TPM2_SE sessionType;

    switch(session_type){
        case 1:
            sessionType = TPM2_SE_TRIAL;
            break;
        case 2:
            sessionType = TPM2_SE_POLICY;
            break;
        default:
            sessionType = TPM2_SE_HMAC;
            break;
    }

    TPMI_ALG_HASH authHash = TPM2_ALG_SHA256;

    rc = Esys_StartAuthSession(esys_context, ESYS_TR_NONE, ESYS_TR_NONE,
                                ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, &nonce_caller,
                                sessionType, &symmetric, authHash, &session);

    DBG("HANDLE_0: %u\n", session);

    if (rc != TPM2_RC_SUCCESS){
        DBG("Error with StartAuthSession\n");
        exit(-1);
    }else{
        *handle = session;
    }

    DBG("HANDLE_1: %u\n", *handle);

    rc = Esys_TRSess_SetAttributes(esys_context, session, sessionAttributes, 0xff);

    if (rc != TPM2_RC_SUCCESS) {
        DBG("Error with TRSess_SetAttributes\n");
        exit(-11);
    }
    
    return rc;
}

TSS2_RC tpm2_create_policy_digest(unsigned int pcr_number, 
                                ESYS_CONTEXT *esys_context,
                                ESYS_TR session_handle,
                                TPM2B_DIGEST *policy_digest){

    TPML_PCR_SELECTION pcr_selection;
    pcr_selection.count = 1;
    pcr_selection.pcrSelections[0].hash = TPM2_ALG_SHA256;
    pcr_selection.pcrSelections[0].sizeofSelect = 3;
    pcr_selection.pcrSelections[0].pcrSelect[2] = 0x00;
    pcr_selection.pcrSelections[0].pcrSelect[1] = 0x00;
    pcr_selection.pcrSelections[0].pcrSelect[0] = 0x00;
    pcr_selection.pcrSelections[0].pcrSelect[2] |= (1 << 7);


    TPM2B_DIGEST *policyDigest;

    TSS2_RC rc =  Esys_PolicyPCR(esys_context, session_handle, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                                 policy_digest, &pcr_selection);

    if (rc!=TPM2_RC_SUCCESS){
        fprintf(stderr, "Couldnt execute the policyPCR function\n");
        exit(-1);
    }

    TSS2_RC r = Esys_PolicyGetDigest(esys_context,
                             session_handle,
                             ESYS_TR_NONE,
                             ESYS_TR_NONE, ESYS_TR_NONE, &policyDigest);

    if (r!=TPM2_RC_SUCCESS){
        fprintf(stderr, "Couldnt get the policy digest\n");
        exit(-1);
    }

    policy_digest->size = policyDigest->size;
    memcpy(policy_digest->buffer, policyDigest->buffer, policyDigest->size);

    DBG("PolicyDigest after PolicyPCR: %s\n", OPENSSL_buf2hexstr(policyDigest->buffer, policyDigest->size));

    DBG("Size_0: %d\n", policyDigest->size);

    return rc;
}

