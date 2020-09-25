#ifndef FE_TA_H
#define FE_TA_H

#include <tee_ta_api.h>
#include <tee_internal_api.h>

/*!
 * \addtogroup GroupTA Trusted Application
 * \{
 */

#define FE_UUID { 0xfe0022e7, 0x5bd6, 0x408a, { 0x82, 0x87, 0xb9, 0x99, 0xe1, 0x94, 0xd8, 0xde} }


/*!
 * \brief ID of callable TA functions
 */
enum {
    FE_CMD_KEYGEN,
    FE_CMD_ENCRYPT,
    FE_CMD_DECRYPT,
    FE_CMD_CLEAR
};

/*!
 * \}
 */


TEE_Result TA_fe_keygen(uint32_t param_types,
                        TEE_Param params[TEE_NUM_PARAMS]);

TEE_Result TA_fe_encrypt(uint32_t param_types,
                         TEE_Param params[TEE_NUM_PARAMS]);

TEE_Result TA_fe_decrypt(uint32_t param_types,
                         TEE_Param params[TEE_NUM_PARAMS]);

TEE_Result TA_fe_clear(uint32_t param_types,
                       TEE_Param params[TEE_NUM_PARAMS]);

#endif /* FE_TA_H */
