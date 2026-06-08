/*
 *  Copyright 2026 NXP
 *
 *  SPDX-License-Identifier: BSD-3-Clause
 *
 */

/*! \file wlan_secure.h
 * \brief This file provides functions to process enterprise secure key.
 */
#ifndef _WLAN_SECURE_H
#define _WLAN_SECURE_H

#include "psa/crypto.h"

#ifdef __cplusplus
extern "C" {
#endif

#if CONFIG_WIFI_ENTERPRISE_SECURE_BLOB
/**
 * Find the EAP-TLS client key from a list of imported PSA key IDs.
 *
 * Iterates through the key ID list and identifies the EAP-TLS client key
 * by matching key type (ECC key pair, secp256r1) and algorithm (ECDSA-SHA256).
 *
 * @param[in]  key_id_list   Array of PSA key IDs to search
 * @param[in]  key_count     Number of valid entries in key_id_list
 * @param[out] client_key_id The matching EAP-TLS client key ID
 *
 * @retval PSA_SUCCESS if a matching key is found
 * @retval PSA_ERROR_DOES_NOT_EXIST if no matching key is found
 */
psa_status_t wlan_find_eap_tls_client_key(
    const psa_key_id_t *key_id_list,
    size_t key_count,
    psa_key_id_t *client_key_id);

/**
 * Set the EAP-TLS client key and generate the corresponding client certificate.
 *
 * Validates the given key ID as an ECC key pair, configures it for enterprise
 * authentication, and generates a client certificate signed by the CA.
 *
 * @param[in] key_id PSA key ID of the EAP-TLS client key
 */
void wlan_set_client_key_and_generate_cert(psa_key_id_t key_id);
#endif

#ifdef __cplusplus
}
#endif

#endif /*_WLAN_SECURE_H */
