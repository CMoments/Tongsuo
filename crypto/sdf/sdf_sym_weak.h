/* Weak declarations for direct-linked SDF symbols.*/
#ifndef OSSL_CRYPTO_SDF_SYM_WEAK_H
#define OSSL_CRYPTO_SDF_SYM_WEAK_H

#include <stdint.h>
#include <openssl/sdf.h>
extern int SDF_OpenDevice(void **phDeviceHandle) __attribute__((weak));
extern int SDF_CloseDevice(void *hDeviceHandle) __attribute__((weak));
extern int SDF_OpenSession(void *hDeviceHandle, void **phSessionHandle) __attribute__((weak));
extern int SDF_CloseSession(void *hSessionHandle) __attribute__((weak));

extern int SDF_GenerateRandom(void *hSessionHandle, unsigned int uiLength,
    unsigned char *pucRandom) __attribute__((weak));

extern int SDF_GetPrivateKeyAccessRight(void *hSessionHandle,
    unsigned int uiKeyIndex, unsigned char *pucPassword,
    unsigned int uiPwdLength) __attribute__((weak));

extern int SDF_ReleasePrivateKeyAccessRight(void *hSessionHandle,
    unsigned int uiKeyIndex) __attribute__((weak));

extern int SDF_ImportKeyWithISK_ECC(void *hSessionHandle,
    unsigned int uiISKIndex, OSSL_ECCCipher *pucKey,
    void **phKeyHandle) __attribute__((weak));

extern int SDF_ImportKeyWithKEK(void *hSessionHandle,
    unsigned int uiAlgID, unsigned int uiKEKIndex, unsigned char *pucKey,
    unsigned int puiKeyLength, void **phKeyHandle) __attribute__((weak));

extern int SDF_ExportSignPublicKey_ECC(void *hSessionHandle,
    unsigned int uiKeyIndex, OSSL_ECCrefPublicKey *pucPublicKey)
    __attribute__((weak));

extern int SDF_ExportEncPublicKey_ECC(void *hSessionHandle,
    unsigned int uiKeyIndex, OSSL_ECCrefPublicKey *pucPublicKey)
    __attribute__((weak));

extern int SDF_DestroyKey(void *hSessionHandle, void *hKeyHandle)
    __attribute__((weak));

extern int SDF_InternalEncrypt_ECC(void *hSessionHandle,
    unsigned int uiISKIndex, unsigned char *pucData, unsigned int uiDataLength,
    OSSL_ECCCipher * pucEncData) __attribute__((weak));

extern int SDF_InternalDecrypt_ECC(void *hSessionHandle,
    unsigned int uiISKIndex, OSSL_ECCCipher *pucEncData,
    unsigned char *pucData, unsigned int *puiDataLength) __attribute__((weak));

extern int SDF_InternalSign_ECC(void * hSessionHandle, unsigned int uiISKIndex,
    unsigned char * pucData, unsigned int uiDataLength,
    OSSL_ECCSignature * pucSignature) __attribute__((weak));

extern int SDF_Encrypt(void *hSessionHandle, void *hKeyHandle,
    unsigned int uiAlgID, unsigned char *pucIV, unsigned char *pucData,
    unsigned int uiDataLength, unsigned char *pucEncData,
    unsigned int *puiEncDataLength) __attribute__((weak));

extern int SDF_Decrypt(void *hSessionHandle, void *hKeyHandle,
    unsigned int uiAlgID, unsigned char *pucIV, unsigned char *pucEncData,
    unsigned int uiEncDataLength, unsigned char *pucData,
    unsigned int *puiDataLength) __attribute__((weak));

extern int SDF_CalculateMAC(void *hSessionHandle, void *hKeyHandle,
    unsigned int uiAlgID, unsigned char *pucIV, unsigned char *pucData,
    unsigned int uiDataLength, unsigned char *pucMac,
    unsigned int *puiMACLength) __attribute__((weak));

extern int SDFE_GenerateKey(void *hSessionHandle, uint8_t type, uint8_t no_kek,
    uint32_t len, void **pkey_handle) __attribute__((weak));

#endif /* OSSL_CRYPTO_SDF_SYM_WEAK_H */
