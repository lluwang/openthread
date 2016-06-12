/*
 *    Copyright 2016 Nest Labs Inc. All Rights Reserved.
 *
 *    Licensed under the Apache License, Version 2.0 (the "License");
 *    you may not use this file except in compliance with the License.
 *    You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the License is distributed on an "AS IS" BASIS,
 *    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *    See the License for the specific language governing permissions and
 *    limitations under the License.
 */

#include <assert.h>
#include <stdbool.h>
#include <string.h>

#include <openthread-types.h>
#include <openthread-config.h>

#include <mbedtls/memory_buffer_alloc.h>
#include <mbedtls/aes.h>
#include <mbedtls/md.h>
#include <mbedtls/sha256.h>

#include <crypto/aes_ecb.h>
#include <crypto/crypto.h>
#include <crypto/hmac_sha256.h>
#include <crypto/sha256.h>

/**
 * @def MBED_MEMORY_BUF_SIZE
 *
 * The size of the memory buffer used by mbedtls.
 *
 */
#if OPENTHREAD_ENABLE_DTLS
#define MBED_MEMORY_BUF_SIZE  (2048 * sizeof(void*))
#else
#define MBED_MEMORY_BUF_SIZE  2048
#endif

static unsigned char sMemoryBuf[MBED_MEMORY_BUF_SIZE];

static mbedtls_aes_context sAesContext;
static mbedtls_md_context_t sHmacSha256Context;
static mbedtls_sha256_context sSha256Context;

void otCryptoEnable(void)
{
    mbedtls_memory_buffer_alloc_init(sMemoryBuf, sizeof(sMemoryBuf));
}

void otCryptoSha256Start(void)
{
    mbedtls_sha256_init(&sSha256Context);
    mbedtls_sha256_starts(&sSha256Context, 0);
}

void otCryptoSha256Update(const void *aBuf, uint16_t aBufLength)
{
    mbedtls_sha256_update(&sSha256Context, aBuf, aBufLength);
}

void otCryptoSha256Finish(uint8_t aHash[otCryptoSha256Size])
{
    mbedtls_sha256_finish(&sSha256Context, aHash);
    mbedtls_sha256_free(&sSha256Context);
}

void otCryptoHmacSha256Start(const void *aKey, uint16_t aKeyLength)
{
    const mbedtls_md_info_t *mdInfo = NULL;

    mbedtls_md_init(&sHmacSha256Context);
    mdInfo = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    mbedtls_md_setup(&sHmacSha256Context, mdInfo, 1);
    mbedtls_md_hmac_starts(&sHmacSha256Context, aKey, aKeyLength);
}

void otCryptoHmacSha256Update(const void *aBuf, uint16_t aBufLength)
{
    mbedtls_md_hmac_update(&sHmacSha256Context, aBuf, aBufLength);
}

void otCryptoHmacSha256Finish(uint8_t aHash[otCryptoSha256Size])
{
    mbedtls_md_hmac_finish(&sHmacSha256Context, aHash);
    mbedtls_md_free(&sHmacSha256Context);
}

void otCryptoAesEcbSetKey(const void *aKey, uint16_t aKeyLength)
{
    mbedtls_aes_init(&sAesContext);
    mbedtls_aes_setkey_enc(&sAesContext, aKey, aKeyLength);
}

void otCryptoAesEcbEncrypt(const uint8_t aInput[otAesBlockSize], uint8_t aOutput[otAesBlockSize])
{
    mbedtls_aes_crypt_ecb(&sAesContext, MBEDTLS_AES_ENCRYPT, aInput, aOutput);
}
