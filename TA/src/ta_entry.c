#include <fe_config.h>
#include <tee_ta_api.h>
#include <tee_internal_api.h>
#include <trace.h>

/* ========================================================================== */

TEE_Result TA_CreateEntryPoint(void)
{
    DMSG("[FE] Creating TA.");
    return TEE_SUCCESS;
}

void TA_DestroyEntryPoint(void)
{
    DMSG("[FE] Destroying TA.");
}

TEE_Result TA_OpenSessionEntryPoint(uint32_t parameters_type,
                                    TEE_Param parameters[TEE_NUM_PARAMS],
                                    void** session_id_ptr)
{
    /* unused variables */
    (void) (parameters_type);
    (void) (parameters);
    (void) (session_id_ptr);

    DMSG("[FE] Opening TA Session.");
    return TEE_SUCCESS;
}

void TA_CloseSessionEntryPoint(void* sess_ptr)
{
    /* unused variables */
    (void) (sess_ptr);

    DMSG("[FE] Closing TA Session.");
}

TEE_Result TA_InvokeCommandEntryPoint(void* session_id,
                                      uint32_t command_id,
                                      uint32_t parameters_type,
                                      TEE_Param parameters[TEE_NUM_PARAMS])
{
    TEE_Result result = TEE_SUCCESS;

    /* unused variables */
    (void) (session_id);

    switch (command_id) {

    case FE_CMD_KEYGEN:
        DMSG("[FE_CMD_KEYGEN] Command received.");
        result = TA_fe_keygen(parameters_type, parameters);
        break;
    case FE_CMD_ENCRYPT:
        DMSG("[FE_CMD_ENCRYPT] Command received.");
        result = TA_fe_encrypt(parameters_type, parameters);
        break;
    case FE_CMD_DECRYPT:
        DMSG("[FE_CMD_DECRYPT] Command received.");
        result = TA_fe_encrypt(parameters_type, parameters);
        break;
    case FE_CMD_CLEAR:
        DMSG("[FE_CMD_CLEAR] Command received.");
        result = TA_fe_clear(parameters_type, parameters);
        break;
    default:
        DMSG("[FE] Invalid command.");
        result = TEE_ERROR_BAD_PARAMETERS;
        break;
    }

    return result;
}
