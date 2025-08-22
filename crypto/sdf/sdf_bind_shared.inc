static void sdf_bind_static(void){
#ifndef OSSL_SDF_BIND_SHARED_INC
#define OSSL_SDF_BIND_SHARED_INC

/* Define a macro that binds all shared SDF symbols. Using a macro avoids
 * IntelliSense errors in editors when opening this file standalone. */
#define OSSL_SDF_BIND_SHARED(DSO_VAR, METH_VAR)                           \
        do {                                                                  \
                (METH_VAR).OpenDevice =                                           \
                        (SDF_OpenDevice_fn)DSO_bind_func((DSO_VAR), "SDF_OpenDevice"); \
                (METH_VAR).CloseDevice =                                          \
                        (SDF_CloseDevice_fn)DSO_bind_func((DSO_VAR), "SDF_CloseDevice"); \
                (METH_VAR).OpenSession =                                          \
                        (SDF_OpenSession_fn)DSO_bind_func((DSO_VAR), "SDF_OpenSession"); \
                (METH_VAR).CloseSession =                                         \
                        (SDF_CloseSession_fn)DSO_bind_func((DSO_VAR), "SDF_CloseSession"); \
                (METH_VAR).GenerateRandom =                                       \
                        (SDF_GenerateRandom_fn)DSO_bind_func((DSO_VAR), "SDF_GenerateRandom"); \
                (METH_VAR).GetPrivateKeyAccessRight =                             \
                        (SDF_GetPrivateKeyAccessRight_fn)DSO_bind_func((DSO_VAR), "SDF_GetPrivateKeyAccessRight"); \
                (METH_VAR).ReleasePrivateKeyAccessRight =                         \
                        (SDF_ReleasePrivateKeyAccessRight_fn)DSO_bind_func((DSO_VAR), "SDF_ReleasePrivateKeyAccessRight"); \
                (METH_VAR).ImportKeyWithISK_ECC =                                 \
                        (SDF_ImportKeyWithISK_ECC_fn)DSO_bind_func((DSO_VAR), "SDF_ImportKeyWithISK_ECC"); \
                (METH_VAR).ImportKeyWithKEK =                                     \
                        (SDF_ImportKeyWithKEK_fn)DSO_bind_func((DSO_VAR), "SDF_ImportKeyWithKEK"); \
                (METH_VAR).ExportSignPublicKey_ECC =                              \
                        (SDF_ExportSignPublicKey_ECC_fn)DSO_bind_func((DSO_VAR), "SDF_ExportSignPublicKey_ECC"); \
                (METH_VAR).ExportEncPublicKey_ECC =                               \
                        (SDF_ExportEncPublicKey_ECC_fn)DSO_bind_func((DSO_VAR), "SDF_ExportEncPublicKey_ECC"); \
                (METH_VAR).DestroyKey =                                           \
                        (SDF_DestroyKey_fn)DSO_bind_func((DSO_VAR), "SDF_DestroyKey"); \
                (METH_VAR).InternalEncrypt_ECC =                                  \
                        (SDF_InternalEncrypt_ECC_fn)DSO_bind_func((DSO_VAR), "SDF_InternalEncrypt_ECC"); \
                (METH_VAR).InternalDecrypt_ECC =                                  \
                        (SDF_InternalDecrypt_ECC_fn)DSO_bind_func((DSO_VAR), "SDF_InternalDecrypt_ECC"); \
                (METH_VAR).InternalSign_ECC =                                     \
                        (SDF_InternalSign_ECC_fn)DSO_bind_func((DSO_VAR), "SDF_InternalSign_ECC"); \
                (METH_VAR).Encrypt =                                              \
                        (SDF_Encrypt_fn)DSO_bind_func((DSO_VAR), "SDF_Encrypt");     \
                (METH_VAR).Decrypt =                                              \
                        (SDF_Decrypt_fn)DSO_bind_func((DSO_VAR), "SDF_Decrypt");     \
                (METH_VAR).CalculateMAC =                                         \
                        (SDF_CalculateMAC_fn)DSO_bind_func((DSO_VAR), "SDF_CalculateMAC"); \
                (METH_VAR).GenerateKey =                                          \
                        (SDF_GenerateKey_fn)DSO_bind_func((DSO_VAR), "SDFE_GenerateKey"); \
        } while (0)

#endif /* OSSL_SDF_BIND_SHARED_INC */
    
}
