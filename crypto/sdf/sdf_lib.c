/*
 * Copyright 2024 The Tongsuo Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/Tongsuo-Project/Tongsuo/blob/master/LICENSE.txt
 */

#include <openssl/crypto.h>
#include <openssl/types.h>
#include <openssl/sdf.h>
#include "internal/thread_once.h"
#include "internal/dso.h"
#include "internal/sdf.h"
#include "sdf_local.h"

#ifdef SDF_LIB
# ifdef SDF_LIB_SHARED
static DSO *sdf_dso = NULL;
# else
/* Weak declarations for direct-linked SDF symbols are split out
 * to make extension (e.g., 69+ items) easier to maintain. */
#  include "sdf_sym_weak.h"
# endif

static CRYPTO_ONCE sdf_lib_once = CRYPTO_ONCE_STATIC_INIT;
static SDF_METHOD sdfm;

DEFINE_RUN_ONCE_STATIC(ossl_sdf_lib_init)
{
# ifdef SDF_LIB_SHARED
#  ifndef LIBSDF
#   define LIBSDF "sdf"
#  endif

    sdf_dso = DSO_load(NULL, LIBSDF, NULL, 0);
    if (sdf_dso != NULL) {
        /* Bindings for shared SDF are split out to allow easy expansion */
#  include "sdf_bind_shared.inc"
        OSSL_SDF_BIND_SHARED(sdf_dso, sdfm);
    }
# else
    /* Direct-link assignments are split out to allow easy expansion */
#  include "sdf_bind_static.inc"
    OSSL_SDF_BIND_STATIC(sdfm);
# endif
    return 1;
}
#endif

void ossl_sdf_lib_cleanup(void)
{
#ifdef SDF_LIB_SHARED
    DSO_free(sdf_dso);
    sdf_dso = NULL;
#endif
}

static const SDF_METHOD *sdf_get_method(void)
{
    const SDF_METHOD *meth = &ts_sdf_meth;

#ifdef SDF_LIB
    if (RUN_ONCE(&sdf_lib_once, ossl_sdf_lib_init))
        meth = &sdfm;
#endif

    return meth;
}

int TSAPI_SDF_OpenDevice(void **phDeviceHandle)
{
    const SDF_METHOD *meth = sdf_get_method();

    if (meth == NULL || meth->OpenDevice == NULL)
        return OSSL_SDR_NOTSUPPORT;

    return meth->OpenDevice(phDeviceHandle);
}

int TSAPI_SDF_CloseDevice(void *hDeviceHandle)
{
    const SDF_METHOD *meth = sdf_get_method();

    if (hDeviceHandle == NULL)
        return OSSL_SDR_OK;

    if (meth == NULL || meth->CloseDevice == NULL)
        return OSSL_SDR_NOTSUPPORT;

    return meth->CloseDevice(hDeviceHandle);
}

int TSAPI_SDF_OpenSession(void *hDeviceHandle, void **phSessionHandle)
{
    const SDF_METHOD *meth = sdf_get_method();

    if (meth == NULL || meth->OpenSession == NULL)
        return OSSL_SDR_NOTSUPPORT;

    return meth->OpenSession(hDeviceHandle, phSessionHandle);
}

int TSAPI_SDF_CloseSession(void *hSessionHandle)
{
    const SDF_METHOD *meth = sdf_get_method();

    if (hSessionHandle == NULL)
        return OSSL_SDR_OK;

    if (meth == NULL || meth->CloseSession == NULL)
        return OSSL_SDR_NOTSUPPORT;

    return meth->CloseSession(hSessionHandle);
}

int TSAPI_SDF_GenerateRandom(void *hSessionHandle, unsigned int uiLength,
                             unsigned char *pucRandom)
{
#define MAX_RANDOM_LEN (2048)
    int ret;
    unsigned int len;
    const SDF_METHOD *meth = sdf_get_method();

    if (meth == NULL || meth->GenerateRandom == NULL)
        return OSSL_SDR_NOTSUPPORT;

    do {
        if (uiLength > MAX_RANDOM_LEN)
            len = MAX_RANDOM_LEN;
        else
            len = uiLength;

        if ((ret = meth->GenerateRandom(hSessionHandle, len, pucRandom)) != 0)
            return ret;

        uiLength -= len;
        pucRandom += len;
    } while (uiLength > 0);

    return OSSL_SDR_OK;
}

int TSAPI_SDF_GetPrivateKeyAccessRight(void *hSessionHandle,
                                      unsigned int uiKeyIndex,
                                      unsigned char *pucPassword,
                                      unsigned int uiPwdLength)
{
    const SDF_METHOD *meth = sdf_get_method();

    if (meth == NULL || meth->GetPrivateKeyAccessRight == NULL)
        return OSSL_SDR_NOTSUPPORT;

    return meth->GetPrivateKeyAccessRight(hSessionHandle, uiKeyIndex,
                                         pucPassword, uiPwdLength);
}

int TSAPI_SDF_ReleasePrivateKeyAccessRight(void *hSessionHandle,
                                           unsigned int uiKeyIndex)
{
    const SDF_METHOD *meth = sdf_get_method();

    if (meth == NULL || meth->ReleasePrivateKeyAccessRight == NULL)
        return OSSL_SDR_NOTSUPPORT;

    return meth->ReleasePrivateKeyAccessRight(hSessionHandle, uiKeyIndex);
}

int TSAPI_SDF_ImportKeyWithISK_ECC(void *hSessionHandle,
                                   unsigned int uiISKIndex,
                                   OSSL_ECCCipher *pucKey,
                                   void **phKeyHandle)
{
    const SDF_METHOD *meth = sdf_get_method();

    if (meth == NULL || meth->ImportKeyWithISK_ECC == NULL)
        return OSSL_SDR_NOTSUPPORT;

    return meth->ImportKeyWithISK_ECC(hSessionHandle, uiISKIndex, pucKey,
                                      phKeyHandle);
}

int TSAPI_SDF_ImportKeyWithKEK(void *hSessionHandle, unsigned int uiAlgID,
                               unsigned int uiKEKIndex, unsigned char *pucKey,
                               unsigned int puiKeyLength, void **phKeyHandle)
{
    const SDF_METHOD *meth = sdf_get_method();

    if (meth == NULL || meth->ImportKeyWithKEK == NULL)
        return OSSL_SDR_NOTSUPPORT;

    return meth->ImportKeyWithKEK(hSessionHandle, uiAlgID, uiKEKIndex, pucKey,
                                   puiKeyLength, phKeyHandle);
}

int TSAPI_SDF_Encrypt(void *hSessionHandle, void *hKeyHandle,
                      unsigned int uiAlgID, unsigned char *pucIV,
                      unsigned char *pucData, unsigned int uiDataLength,
                      unsigned char *pucEncData, unsigned int *puiEncDataLength)
{
    const SDF_METHOD *meth = sdf_get_method();

    if (meth == NULL || meth->Encrypt == NULL)
        return OSSL_SDR_NOTSUPPORT;

    return meth->Encrypt(hSessionHandle, hKeyHandle, uiAlgID, pucIV, pucData,
                         uiDataLength, pucEncData, puiEncDataLength);
}

int TSAPI_SDF_Decrypt(void *hSessionHandle, void *hKeyHandle,
                      unsigned int uiAlgID, unsigned char *pucIV,
                      unsigned char *pucEncData, unsigned int uiEncDataLength,
                      unsigned char *pucData, unsigned int *puiDataLength)
{
    const SDF_METHOD *meth = sdf_get_method();

    if (meth == NULL || meth->Decrypt == NULL)
        return OSSL_SDR_NOTSUPPORT;

    return meth->Decrypt(hSessionHandle, hKeyHandle, uiAlgID, pucIV,
                         pucEncData, uiEncDataLength, pucData, puiDataLength);
}

int TSAPI_SDF_CalculateMAC(void *hSessionHandle, void *hKeyHandle,
                           unsigned int uiAlgID, unsigned char *pucIV,
                           unsigned char *pucData, unsigned int uiDataLength,
                           unsigned char *pucMac, unsigned int *puiMACLength)
{
    const SDF_METHOD *meth = sdf_get_method();

    if (meth == NULL || meth->CalculateMAC == NULL)
        return OSSL_SDR_NOTSUPPORT;

    return meth->CalculateMAC(hSessionHandle, hKeyHandle, uiAlgID, pucIV,
                              pucData, uiDataLength, pucMac, puiMACLength);
}

int TSAPI_SDF_GenerateKey(void *hSessionHandle, uint8_t type, uint8_t no_kek,
                          uint32_t len, void **pkey_handle)
{
    const SDF_METHOD *meth = sdf_get_method();

    if (meth == NULL || meth->GenerateKey == NULL)
        return OSSL_SDR_NOTSUPPORT;

    return meth->GenerateKey(hSessionHandle, type, no_kek, len, pkey_handle);
}

int TSAPI_SDF_DestroyKey(void *hSessionHandle, void *hKeyHandle)
{
    const SDF_METHOD *meth = sdf_get_method();

    if (meth == NULL || meth->DestroyKey == NULL)
        return OSSL_SDR_NOTSUPPORT;

    return meth->DestroyKey(hSessionHandle, hKeyHandle);
}

int TSAPI_SDF_ExportSignPublicKey_ECC(void *hSessionHandle,
                                      unsigned int uiKeyIndex,
                                      OSSL_ECCrefPublicKey *pucPublicKey)
{
    const SDF_METHOD *meth = sdf_get_method();

    if (meth == NULL || meth->ExportSignPublicKey_ECC == NULL)
        return OSSL_SDR_NOTSUPPORT;

    return meth->ExportSignPublicKey_ECC(hSessionHandle, uiKeyIndex, pucPublicKey);
}

int TSAPI_SDF_ExportEncPublicKey_ECC(void *hSessionHandle,
                                      unsigned int uiKeyIndex,
                                      OSSL_ECCrefPublicKey *pucPublicKey)
{
    const SDF_METHOD *meth = sdf_get_method();

    if (meth == NULL || meth->ExportEncPublicKey_ECC == NULL)
        return OSSL_SDR_NOTSUPPORT;

    return meth->ExportEncPublicKey_ECC(hSessionHandle, uiKeyIndex, pucPublicKey);
}

int TSAPI_SDF_InternalEncrypt_ECC(void *hSessionHandle, unsigned int uiISKIndex,
                                  unsigned char *pucData,
                                  unsigned int uiDataLength,
                                  OSSL_ECCCipher *pucEncData)
{
    const SDF_METHOD *meth = sdf_get_method();

    if (meth == NULL || meth->InternalEncrypt_ECC == NULL)
        return OSSL_SDR_NOTSUPPORT;

    return meth->InternalEncrypt_ECC(hSessionHandle, uiISKIndex, pucData,
                                     uiDataLength, pucEncData);
}

int TSAPI_SDF_InternalDecrypt_ECC(void *hSessionHandle, unsigned int uiISKIndex,
                                  OSSL_ECCCipher *pucEncData,
                                  unsigned char *pucData,
                                  unsigned int *puiDataLength)
{
    const SDF_METHOD *meth = sdf_get_method();

    if (meth == NULL || meth->InternalDecrypt_ECC == NULL)
        return OSSL_SDR_NOTSUPPORT;

    return meth->InternalDecrypt_ECC(hSessionHandle, uiISKIndex, pucEncData,
                                     pucData, puiDataLength);
}

int TSAPI_SDF_InternalSign_ECC(void *hSessionHandle, unsigned int uiISKIndex,
                               unsigned char *pucData,
                               unsigned int uiDataLength,
                               OSSL_ECCSignature *pucSignature)
{
    const SDF_METHOD *meth = sdf_get_method();

    if (meth == NULL || meth->InternalSign_ECC == NULL)
        return OSSL_SDR_NOTSUPPORT;

    return meth->InternalSign_ECC(hSessionHandle, uiISKIndex, pucData,
                                  uiDataLength, pucSignature);
}
