#ifndef OSSL_SDF_BIND_STATIC_INC
#define OSSL_SDF_BIND_STATIC_INC

#define OSSL_SDF_BIND_STATIC(METH_VAR)   \
    do {                                 \
        (METH_VAR).OpenDevice = SDF_OpenDevice; \
        (METH_VAR).CloseDevice = SDF_CloseDevice; \
        (METH_VAR).OpenSession = SDF_OpenSession; \
        (METH_VAR).CloseSession = SDF_CloseSession; \
        (METH_VAR).GenerateRandom = SDF_GenerateRandom; \
        (METH_VAR).GetPrivateKeyAccessRight = SDF_GetPrivateKeyAccessRight; \
        (METH_VAR).ReleasePrivateKeyAccessRight = SDF_ReleasePrivateKeyAccessRight; \
        (METH_VAR).ImportKeyWithISK_ECC = SDF_ImportKeyWithISK_ECC; \
        (METH_VAR).ImportKeyWithKEK = SDF_ImportKeyWithKEK; \
        (METH_VAR).ExportSignPublicKey_ECC = SDF_ExportSignPublicKey_ECC; \
        (METH_VAR).ExportEncPublicKey_ECC = SDF_ExportEncPublicKey_ECC; \
        (METH_VAR).DestroyKey = SDF_DestroyKey; \
        (METH_VAR).InternalEncrypt_ECC = SDF_InternalEncrypt_ECC; \
        (METH_VAR).InternalDecrypt_ECC = SDF_InternalDecrypt_ECC; \
        (METH_VAR).InternalSign_ECC = SDF_InternalSign_ECC; \
        (METH_VAR).Encrypt = SDF_Encrypt; \
        (METH_VAR).Decrypt = SDF_Decrypt; \
        (METH_VAR).CalculateMAC = SDF_CalculateMAC; \
        (METH_VAR).GenerateKey = SDFE_GenerateKey; \
    } while (0)

#endif /* OSSL_SDF_BIND_STATIC_INC */
