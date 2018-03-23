/*
 *  FIPS-197 compliant AES implementation
 *
 *  Copyright (C) 2006-2015, ARM Limited, All Rights Reserved
 *  Portions Copyright (c) 2016 - 2017 Analog Devices, Inc.
 *  SPDX-License-Identifier: Apache-2.0
 *
 *  Licensed under the Apache License, Version 2.0 (the "License"); you may
 *  not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 *  This file is part of mbed TLS (https://tls.mbed.org)
 */
/*
 *  The AES block cipher was designed by Vincent Rijmen and Joan Daemen.
 *
 *  http://csrc.nist.gov/encryption/aes/rijndael/Rijndael.pdf
 *  http://csrc.nist.gov/publications/fips/fips197/fips-197.pdf
 */

#include "mbedtls/aes.h"
#include "platform_mbed.h"

#if defined(MBEDTLS_AES_ALT)

#include "adi_crypto.h"
#include "mbed_assert.h"

/* CRYPTO Device number */
#define CRYPTO_DEV_NUM               (0u)

/* Memory Required for crypto driver */
static uint32_t DeviceMemory[(ADI_CRYPTO_MEMORY_SIZE+3)/4];

/* Implementation that should never be optimized out by the compiler */
static void mbedtls_zeroize( void *v, size_t n ) {
    volatile unsigned char *p = (unsigned char*)v; while( n-- ) *p++ = 0;
}


void mbedtls_aes_init( mbedtls_aes_context *ctx )
{
    ADI_CRYPTO_HANDLE       hDevice;
    ADI_CRYPTO_TRANSACTION  *pBuffer = &ctx->Buffer;

#ifdef CRYPTO_ENABLE_CALLBACK
    CALLBACK_PARAMETERS     *pCBParam = ctx->pCBParam;
    void *                  pfCryptoCallback = ctx->pfCryptoCallback;
#endif

    MBED_ASSERT(ctx !=  NULL);

    mbedtls_zeroize( ctx, sizeof( mbedtls_aes_context ) );
    mbedtls_zeroize( DeviceMemory, sizeof( DeviceMemory ) );

#ifdef CRYPTO_ENABLE_CALLBACK
    mbedtls_zeroize( pCBParam, sizeof( CALLBACK_PARAMETERS ) );
#endif

    /* Open the crypto device */
    adi_crypto_Open(CRYPTO_DEV_NUM, DeviceMemory, sizeof(DeviceMemory), &hDevice);

    ctx->hDevice    = hDevice;

#ifdef CRYPTO_ENABLE_CALLBACK
    ctx->pCBParam         = pCBParam;
    ctx->pfCryptoCallback = pfCryptoCallback;
    /* Register Callback */
    adi_crypto_RegisterCallback (hDevice, (ADI_CALLBACK const)pfCryptoCallback, pCBParam);
#endif

    return;
}

/*
 * AES key schedule (encryption)
 */
int mbedtls_aes_setkey_enc( mbedtls_aes_context *ctx, const unsigned char *key,
                    unsigned int keybits )
{
    ADI_CRYPTO_TRANSACTION *pBuffer = &ctx->Buffer;
        unsigned int adi_aes_key_len;

        switch(keybits) {
            case 128 :
                adi_aes_key_len = ADI_CRYPTO_AES_KEY_LEN_128_BIT;
                break;
            case 256 :
                adi_aes_key_len = ADI_CRYPTO_AES_KEY_LEN_256_BIT;
                break;
        default :
            return(1);
    }

    pBuffer->pKey = (uint8_t *)key;
    pBuffer->eAesKeyLen = adi_aes_key_len;

    return( 0 );
}

/*
 * AES-ECB block encryption
 */
int mbedtls_internal_aes_encrypt( mbedtls_aes_context *ctx,
                          const unsigned char input[16],
                          unsigned char output[16] )
{
    ADI_CRYPTO_HANDLE      hDevice = ctx->hDevice;
    ADI_CRYPTO_TRANSACTION *pBuffer = &ctx->Buffer;

/* If (Callback mode enabled) */
#ifdef CRYPTO_ENABLE_CALLBACK
    CALLBACK_PARAMETERS    *pCBParam = ctx->pCBParam;
#else
    static volatile ADI_CRYPTO_TRANSACTION *pGottenBuffer;
#endif /* CRYPTO_ENABLE_CALLBACK */

    pBuffer->eCipherMode    = ADI_CRYPTO_MODE_ECB;
    pBuffer->eCodingMode    = ADI_CRYPTO_ENCODE;
#if defined (__ADUCM4x50__)
    pBuffer->eKeyByteSwap   = ADI_CRYPTO_AES_LITTLE_ENDIAN;
#endif
    pBuffer->eAesByteSwap   = ADI_CRYPTO_AES_LITTLE_ENDIAN;

    pBuffer->pInputData     = (uint32_t*)input;
    pBuffer->numInputBytes = 16;
    pBuffer->pOutputData    = (uint32_t*)output;
    pBuffer->numOutputBytes = 16;

    /* Submit the buffer for encryption */
    adi_crypto_SubmitBuffer (hDevice, pBuffer);

#ifdef CRYPTO_ENABLE_CALLBACK
    /* reset callback counter */
    pCBParam->numBuffersReturned = 0;
#endif

    /* Enable the device */
    adi_crypto_Enable (hDevice, true);

#ifdef CRYPTO_ENABLE_CALLBACK
    /* await any callback */
    while (pCBParam->numBuffersReturned == 0)
        ;
    MBED_ASSERT(pBuffer == pCBParam->pcbReturnedBuffer);
#else
    /* Get ECB ComputedCipher */
    adi_crypto_GetBuffer (hDevice, (ADI_CRYPTO_TRANSACTION ** const)&pGottenBuffer);
    MBED_ASSERT(pBuffer == pGottenBuffer);
#endif

    /* Disable the device */
    adi_crypto_Enable (hDevice, false);

    return(0);
}

void mbedtls_aes_free( mbedtls_aes_context *ctx )
{
    if( ctx == NULL )
        return;

    adi_crypto_Close (ctx->hDevice);
    mbedtls_zeroize( ctx, sizeof( mbedtls_aes_context ) );
}

/*
 * AES key schedule (decryption)
 */
int mbedtls_aes_setkey_dec( mbedtls_aes_context *ctx, const unsigned char *key,
                    unsigned int keybits )
{
    ADI_CRYPTO_TRANSACTION *pBuffer = &ctx->Buffer;
    unsigned int adi_aes_key_len;

        switch(keybits) {
            case 128 :
                adi_aes_key_len = ADI_CRYPTO_AES_KEY_LEN_128_BIT;
                break;
            case 256 :
                adi_aes_key_len = ADI_CRYPTO_AES_KEY_LEN_256_BIT;
                break;
        default :
            return(1);
    }

    pBuffer->pKey = (uint8_t *)key;
    pBuffer->eAesKeyLen = adi_aes_key_len;

    return( 0 );
}

/*
 * AES-ECB block decryption
 */
int mbedtls_internal_aes_decrypt( mbedtls_aes_context *ctx,
                          const unsigned char input[16],
                          unsigned char output[16] )
{
    ADI_CRYPTO_HANDLE      hDevice = ctx->hDevice;
    ADI_CRYPTO_TRANSACTION *pBuffer = &ctx->Buffer;

/* If (Callback mode enabled) */
#ifdef CRYPTO_ENABLE_CALLBACK
    CALLBACK_PARAMETERS    *pCBParam = ctx->pCBParam;
#else
    static volatile ADI_CRYPTO_TRANSACTION *pGottenBuffer;
#endif /* CRYPTO_ENABLE_CALLBACK */

    /* switch buffers for decode */
    pBuffer->eCipherMode    = ADI_CRYPTO_MODE_ECB;
    pBuffer->eCodingMode    = ADI_CRYPTO_DECODE;
#if defined (__ADUCM4x50__)
    pBuffer->eKeyByteSwap   = ADI_CRYPTO_AES_LITTLE_ENDIAN;
#endif
    pBuffer->eAesByteSwap   = ADI_CRYPTO_AES_LITTLE_ENDIAN;

    pBuffer->pInputData     = (uint32_t*)input;
    pBuffer->numInputBytes = 16;
    pBuffer->pOutputData    = (uint32_t*)output;
    pBuffer->numOutputBytes = 16;

    /* Submit the buffer for decryption */
    adi_crypto_SubmitBuffer (hDevice, pBuffer);

#ifdef CRYPTO_ENABLE_CALLBACK
    /* reset callback counter */
    pCBParam->numBuffersReturned = 0;
#endif

    /* Enable the device */
    adi_crypto_Enable (hDevice, true);

#ifdef CRYPTO_ENABLE_CALLBACK
    /* await any callback */
    while (pCBParam->numBuffersReturned == 0)
        ;
    MBED_ASSERT(pBuffer == pCBParam->pcbReturnedBuffer);
#else
    /* Get ECB plaintext */
    adi_crypto_GetBuffer (hDevice, (ADI_CRYPTO_TRANSACTION ** const)&pGottenBuffer);
    MBED_ASSERT(pBuffer == pGottenBuffer);
#endif

    /* Disable the device */
    adi_crypto_Enable (hDevice, false);

    return(0);
}


/*
 * AES-ECB block encryption/decryption
 */
int mbedtls_aes_crypt_ecb( mbedtls_aes_context *ctx,
                           int mode,
                           const unsigned char input[16],
                           unsigned char output[16] )
{
    if( mode == MBEDTLS_AES_ENCRYPT )
        mbedtls_internal_aes_encrypt( ctx, input, output );
    else
        mbedtls_internal_aes_decrypt( ctx, input, output );

    return( 0 );
}

/*
 * AES-CBC buffer encryption/decryption
 */
#ifdef MBEDTLS_CIPHER_MODE_CBC
int mbedtls_aes_crypt_cbc( mbedtls_aes_context *ctx,
                    int mode,
                    size_t length,
                    unsigned char iv[16],
                    const unsigned char *input,
                    unsigned char *output )
{
    ADI_CRYPTO_HANDLE      hDevice  = ctx->hDevice;
    ADI_CRYPTO_TRANSACTION *pBuffer = &ctx->Buffer;

    unsigned char NextFrame_iv[16]; /* temporary storage for input vector.
                                       this is necessary when input buffer = output buffer
                                       eg the selftest TEST */
/* If (Callback mode enabled) */
#ifdef CRYPTO_ENABLE_CALLBACK
    CALLBACK_PARAMETERS    *pCBParam = ctx->pCBParam;
#else
    static volatile ADI_CRYPTO_TRANSACTION *pGottenBuffer;
#endif /* CRYPTO_ENABLE_CALLBACK */

    if( mode == MBEDTLS_AES_ENCRYPT)
    {
        pBuffer->eCipherMode    = ADI_CRYPTO_MODE_CBC;
        pBuffer->eCodingMode    = ADI_CRYPTO_ENCODE;
#if defined (__ADUCM4x50__)
        pBuffer->eKeyByteSwap   = ADI_CRYPTO_AES_LITTLE_ENDIAN;
#endif
        pBuffer->eAesByteSwap   = ADI_CRYPTO_AES_LITTLE_ENDIAN;

        pBuffer->pNonceIV       = (uint8_t *) iv;

        pBuffer->pInputData     = (uint32_t *)input;
        pBuffer->numInputBytes  = length;
        pBuffer->pOutputData    = (uint32_t *)output;
        pBuffer->numOutputBytes = length;

        /* Submit the buffer for encryption */
        adi_crypto_SubmitBuffer (hDevice, pBuffer);

#ifdef CRYPTO_ENABLE_CALLBACK
        /* reset callback counter */
        pCBParam->numBuffersReturned = 0;
#endif

        /* Enable the device */
        adi_crypto_Enable (hDevice, true);

#ifdef CRYPTO_ENABLE_CALLBACK
        /* await any callback */
         while (pCBParam->numBuffersReturned == 0)
             ;
        MBED_ASSERT(pBuffer == pCBParam->pcbReturnedBuffer);
#else
        /* Get ECB ComputedCipher */
        adi_crypto_GetBuffer (hDevice, (ADI_CRYPTO_TRANSACTION ** const)&pGottenBuffer);
        MBED_ASSERT(pBuffer == pGottenBuffer);
#endif

        /* Disable the device */
        adi_crypto_Enable (hDevice, false);

        memcpy(iv, output, 16);
    }
    else    // MBEDTLS_AES_ENCRYPT
    {
        memcpy(NextFrame_iv, input, 16);

        /* switch buffers for decode */
        pBuffer->eCipherMode    = ADI_CRYPTO_MODE_CBC;
        pBuffer->eCodingMode    = ADI_CRYPTO_DECODE;
#if defined (__ADUCM4x50__)
        pBuffer->eKeyByteSwap   = ADI_CRYPTO_AES_LITTLE_ENDIAN;
#endif
        pBuffer->eAesByteSwap   = ADI_CRYPTO_AES_LITTLE_ENDIAN;

        pBuffer->pNonceIV       = (uint8_t *) iv;

        pBuffer->pInputData     = (uint32_t *)input;
        pBuffer->numInputBytes  = length;
        pBuffer->pOutputData    = (uint32_t *)output;
        pBuffer->numOutputBytes = length;

        /* Submit the buffer for decryption */
        adi_crypto_SubmitBuffer (hDevice, pBuffer);

#ifdef CRYPTO_ENABLE_CALLBACK
        /* reset callback counter */
        pCBParam->numBuffersReturned = 0;
#endif

        /* Enable the device */
        adi_crypto_Enable (hDevice, true);

#ifdef CRYPTO_ENABLE_CALLBACK
        /* await any callback */
        while (pCBParam->numBuffersReturned == 0)
            ;
        MBED_ASSERT(pBuffer == pCBParam->pcbReturnedBuffer);
#else
        /* Get ECB plaintext */
        adi_crypto_GetBuffer (hDevice, (ADI_CRYPTO_TRANSACTION ** const) &pGottenBuffer);
        MBED_ASSERT(pBuffer == pGottenBuffer);
#endif

        /* Disable the device */
        adi_crypto_Enable (hDevice, false);

        memcpy(iv, NextFrame_iv, 16);
    }
    return( 0 );
}
#endif  /* MBEDTLS_CIPHER_MODE_CBC  */

#if defined(MBEDTLS_CIPHER_MODE_CTR)
/*
 * AES-CTR buffer encryption/decryption
 */
int mbedtls_aes_crypt_ctr( mbedtls_aes_context *ctx,
                       size_t length,
                       size_t *nc_off,
                       unsigned char nonce_counter[16],
                       unsigned char stream_block[16],
                       const unsigned char *input,
                       unsigned char *output )
{
    int c, i;
    size_t n = *nc_off;

    while( length-- )
    {
        if( n == 0 ) {
            mbedtls_aes_crypt_ecb( ctx, MBEDTLS_AES_ENCRYPT, nonce_counter, stream_block );

            for( i = 16; i > 0; i-- )
                if( ++nonce_counter[i - 1] != 0 )
                    break;
        }
        c = *input++;
        *output++ = (unsigned char)( c ^ stream_block[n] );

        n = ( n + 1 ) & 0x0F;
    }

    *nc_off = n;

    return( 0 );
}
#endif /* MBEDTLS_CIPHER_MODE_CTR */

/*
 * AES-CFB128 buffer encryption/decryption
 */
#ifdef MBEDTLS_CIPHER_MODE_CFB
int mbedtls_aes_crypt_cfb128( mbedtls_aes_context *ctx,
                       int mode,
                       size_t length,
                       size_t *iv_off,
                       unsigned char iv[16],
                       const unsigned char *input,
                       unsigned char *output )
{
    int c;
    size_t n = *iv_off;

    if( mode == MBEDTLS_AES_DECRYPT )
    {
        while( length-- )
        {
            if( n == 0 )
                mbedtls_aes_crypt_ecb( ctx, MBEDTLS_AES_ENCRYPT, iv, iv );

            c = *input++;
            *output++ = (unsigned char)( c ^ iv[n] );
            iv[n] = (unsigned char) c;

            n = ( n + 1 ) & 0x0F;
        }
    }
    else
    {
        while( length-- )
        {
            if( n == 0 )
                mbedtls_aes_crypt_ecb( ctx, MBEDTLS_AES_ENCRYPT, iv, iv );

            iv[n] = *output++ = (unsigned char)( iv[n] ^ *input++ );

            n = ( n + 1 ) & 0x0F;
        }
    }

    *iv_off = n;

    return( 0 );
}

/*
 * AES-CFB8 buffer encryption/decryption
 */
int mbedtls_aes_crypt_cfb8( mbedtls_aes_context *ctx,
                       int mode,
                       size_t length,
                       unsigned char iv[16],
                       const unsigned char *input,
                       unsigned char *output )
{
    unsigned char c;
    unsigned char ov[17];

    while( length-- )
    {
       memcpy( ov, iv, 16 );
       mbedtls_aes_crypt_ecb( ctx, MBEDTLS_AES_ENCRYPT, iv, iv );

        if( mode == MBEDTLS_AES_DECRYPT )
            ov[16] = *input;

        c = *output++ = (unsigned char)( iv[0] ^ *input++ );

        if( mode == MBEDTLS_AES_ENCRYPT )
            ov[16] = c;

        memcpy( iv, ov + 1, 16 );
    }

    return( 0 );
}
#endif  /* MBEDTLS_CIPHER_MODE_CFB  */

#endif /* !MBEDTLS_AES_ALT */
