/** @file wlan_secure.c
 *
 *  @brief  This file provides functions to process enterprise secure key.
 *
 *  Copyright 2026 NXP
 *
 *  SPDX-License-Identifier: BSD-3-Clause
 *
 */
#if CONFIG_WIFI_ENTERPRISE_SECURE_BLOB
#include "mbedtls/build_info.h"
#include "mbedtls/x509_crt.h"
#include "mbedtls/pk.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"
#include "psa/crypto.h"
#include "ca-key.h"
#include "wlan.h"

#define CERT_VALID_FROM   "20200101000000"
#define CERT_VALID_TO     "20500101000000"
extern const unsigned char ca_der[];
extern unsigned int ca_der_len;
unsigned char local_client_der[2048] = {0};
#define ISSUER_NAME_BUF_SIZE  256

static psa_status_t wlan_psa_validate_ecc_key(psa_key_type_t key_type, size_t key_id, const psa_algorithm_t key_alg)
{
    psa_status_t status = PSA_SUCCESS;
    uint8_t *signature = NULL;
    const uint8_t message[] =  "Sign message test";
    size_t sig_size = PSA_SIGN_OUTPUT_SIZE(key_type, 256, key_alg);
    size_t sig_len = 0U;

    if (sig_size == 0U)
    {
        PRINTF("%s: unsupported algorithm\r\n", __FUNCTION__);
        return PSA_ERROR_NOT_SUPPORTED;
    }

    signature = OSA_MemoryAllocate(sig_size);
    if (signature == NULL)
    {
        PRINTF("%s: memory allocation failed\r\n", __FUNCTION__);
        return PSA_ERROR_INSUFFICIENT_MEMORY;
    }

    status = psa_sign_message((psa_key_id_t)key_id, key_alg,
                              message, sizeof(message),
                              signature, sig_size, &sig_len);
    if (status != PSA_SUCCESS)
    {
        PRINTF("ECC key validation failed (key_id=0x%x, err=%d)\r\n", key_id, status);
    }
    else
    {
        PRINTF("ECC key validation passed (key_id=0x%x)\r\n", key_id);
    }

    OSA_MemoryFree(signature);
    return status;
}

static int wlan_psa_generate_client_cert(
    psa_key_id_t client_key_id,
    const unsigned char *ca_key_der,
    size_t ca_key_der_len,
    const unsigned char *ca_cert_der,
    size_t ca_cert_der_len,
    unsigned char *out_buf,
    size_t out_buf_size)
{
    int ret = 0;
    mbedtls_x509write_cert crt;
    mbedtls_pk_context ca_key;
    mbedtls_pk_context client_key;
    mbedtls_x509_crt ca_cert;
    /* Certificate serial number */
    mbedtls_mpi serial;
    /* Random generator (required for signing) */
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_entropy_context entropy;
    const char *pers = "crt_psa";
    char *issuer_name = NULL;

    /* Initialize all structures */
    mbedtls_x509write_crt_init(&crt);
    mbedtls_pk_init(&ca_key);
    mbedtls_pk_init(&client_key);
    mbedtls_x509_crt_init(&ca_cert);
    mbedtls_mpi_init(&serial);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_entropy_init(&entropy);

    /* Seed the random number generator */
    ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                               (const unsigned char *)pers, strlen(pers));
    if (ret != 0)
    {
        PRINTF("RNG seed failed: 0x%04X\r\n", ret);
        goto cleanup;
    }

    /* Parse CA private key (DER format) */
    ret = mbedtls_pk_parse_key(&ca_key, ca_key_der, ca_key_der_len,
                              NULL, 0, mbedtls_ctr_drbg_random, &ctr_drbg);
    if (ret != 0)
    {
        PRINTF("Failed to parse CA key: 0x%04X\r\n", ret);
        goto cleanup;
    }

    /* Parse CA certificate (DER format) */
    ret = mbedtls_x509_crt_parse(&ca_cert, ca_cert_der, ca_cert_der_len);
    if (ret != 0)
    {
        PRINTF("Failed to parse CA certificate: 0x%04X\r\n", ret);
        goto cleanup;
    }

    /* Bind PSA opaque client key */
    ret = mbedtls_pk_setup_opaque(&client_key, client_key_id);
    if (ret != 0)
    {
        PRINTF("Failed to setup PSA key: 0x%04X\r\n", ret);
        goto cleanup;
    }

    /* Build certificate fields */
    mbedtls_x509write_crt_set_subject_key(&crt, &client_key);
    mbedtls_x509write_crt_set_issuer_key(&crt, &ca_key);
    mbedtls_x509write_crt_set_md_alg(&crt, MBEDTLS_MD_SHA256);
    ret = mbedtls_x509write_crt_set_subject_name(&crt, "CN=WiFi,O=NXP");
    if (ret != 0)
    {
        PRINTF("Failed to Set subject name: 0x%04X\r\n", ret);
        goto cleanup;
    }

    /* Extract issuer name from CA certificate to ensure exact match */
    issuer_name = OSA_MemoryAllocate(ISSUER_NAME_BUF_SIZE);
    if (issuer_name == NULL)
    {
        PRINTF("Allocate issuer_name failed\r\n");
        ret = MBEDTLS_ERR_X509_ALLOC_FAILED;
        goto cleanup;
    }

    ret = mbedtls_x509_dn_gets(issuer_name, ISSUER_NAME_BUF_SIZE, &ca_cert.subject);
    if (ret < 0)
    {
        PRINTF("Get CA subject failed: 0x%04X\r\n", ret);
        goto cleanup;
    }

    ret = mbedtls_x509write_crt_set_issuer_name(&crt, issuer_name);
    if (ret != 0)
    {
        PRINTF("Failed to Set issuer name: 0x%04X\r\n", ret);
        goto cleanup;
    }

    /* Serial number — use random 8-byte value for RFC 5280 compliance  */
    ret = mbedtls_mpi_fill_random(&serial, 8, mbedtls_ctr_drbg_random, &ctr_drbg);
    if (ret != 0)
    {
        PRINTF("Generate serial number failed: 0x%04X\r\n", ret);
        goto cleanup;
    }

    /* Ensure most significant bit is 0 (positive integer) */
    ret = mbedtls_mpi_set_bit(&serial, 63, 0);
    if (ret != 0)
    {
        PRINTF("Set serial MSB failed: 0x%04X\r\n", ret);
        goto cleanup;
    }

    ret = mbedtls_x509write_crt_set_serial(&crt, &serial);
    if (ret != 0)
    {
        PRINTF("Failed to Set serial: 0x%04X\r\n", ret);
        goto cleanup;
    }

    /* Set certificate validity period */
    ret = mbedtls_x509write_crt_set_validity(&crt, CERT_VALID_FROM, CERT_VALID_TO);
    if (ret != 0)
    {
        PRINTF("Failed to Set certificate validity period: 0x%04X\r\n", ret);
        goto cleanup;
    }

    /* Key usage: digital signature */
    ret = mbedtls_x509write_crt_set_key_usage(&crt, MBEDTLS_X509_KU_DIGITAL_SIGNATURE);
    if (ret != 0)
    {
        PRINTF("Failed to Set Key usage: 0x%04X\r\n", ret);
        goto cleanup;
    }

    /* Write DER — fills out_buf from the END, returns byte count */
    ret = mbedtls_x509write_crt_der(&crt, out_buf, out_buf_size,
                                    mbedtls_ctr_drbg_random, &ctr_drbg);
    if (ret <= 0)
    {
        PRINTF("Certificate generation failed: 0x%04X\r\n", ret);
        goto cleanup;
    }

cleanup:
    mbedtls_x509write_crt_free(&crt);
    mbedtls_pk_free(&ca_key);
    mbedtls_pk_free(&client_key);
    mbedtls_x509_crt_free(&ca_cert);
    mbedtls_mpi_free(&serial);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
    OSA_MemoryFree(issuer_name);

    return ret;
}

psa_status_t wlan_find_eap_tls_client_key(
    const psa_key_id_t *key_id_list,
    size_t key_count,
    psa_key_id_t *client_key_id)
{
    psa_status_t status;
    psa_key_type_t type;
    psa_algorithm_t alg;
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;

    for (size_t i = 0U; i < key_count; i++)
    {
        status = psa_get_key_attributes(key_id_list[i], &attributes);
        if (status != PSA_SUCCESS)
        {
            continue;
        }

        type = psa_get_key_type(&attributes);
        alg = psa_get_key_algorithm(&attributes);
        psa_reset_key_attributes(&attributes);

        /* For RW612, EAP-TLS client key is an ECC key pair on secp256r1 curve
         * with ECDSA-SHA256 signing algorithm. Match these attributes
         * to identify the correct key from the imported blob list. */
        if (type == PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1) &&
            alg == PSA_ALG_ECDSA(PSA_ALG_SHA_256))
        {
            *client_key_id = key_id_list[i];
            return PSA_SUCCESS;
        }
    }

    return PSA_ERROR_DOES_NOT_EXIST;
}

void wlan_set_client_key_and_generate_cert(    psa_key_id_t key_id)
{
    psa_status_t ret;
    t_u8 KeyID[4];
    int cert_len;

    /* Validate ECC key pair with ECDSA-SHA256 */
    ret = wlan_psa_validate_ecc_key(PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1), key_id, PSA_ALG_ECDSA(PSA_ALG_SHA_256));
    if (ret != PSA_SUCCESS)
    {
        PRINTF("Key is not correct\r\n");
        return;
    }

    /* Serialize key_id as little-endian 4-byte array */
    KeyID[0] = (t_u8)((key_id) & 0xFFU);
    KeyID[1] = (t_u8)((key_id >> 8U) & 0xFFU);
    KeyID[2] = (t_u8)((key_id >> 16U) & 0xFFU);
    KeyID[3] = (t_u8)((key_id >> 24U) & 0xFFU);
    wlan_set_entp_cert_files(FILE_TYPE_ENTP_CLIENT_KEY, KeyID, sizeof(KeyID));
    wlan_set_entp_cert_files(FILE_TYPE_ENTP_CLIENT_KEY2, KeyID, sizeof(KeyID));
    PRINTF("Set client key (0x%x) successfully\r\n", key_id);

    (void)memset(local_client_der, 0, sizeof(local_client_der));

    /* Generate and set client certificate */
    cert_len = wlan_psa_generate_client_cert(key_id, ca_key_der, ca_key_der_len, ca_der, ca_der_len,
                                  local_client_der, sizeof(local_client_der));
    if (cert_len > 0)
    {
        /* mbedTLS DER write fills buffer from the end */
        t_u8 *cert_ptr = local_client_der + sizeof(local_client_der) - (size_t)cert_len;
        wlan_set_entp_cert_files(FILE_TYPE_ENTP_CLIENT_CERT, cert_ptr, cert_len);
        wlan_set_entp_cert_files(FILE_TYPE_ENTP_CLIENT_CERT2, cert_ptr, cert_len);
        PRINTF("Client certificate generated and set successfully, len=%u\r\n", cert_len);
    }
    else
    {
        PRINTF("Generate client certificate failed (err=%d)\r\n", cert_len);
    }
}
#endif
