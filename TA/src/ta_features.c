#include <fe_config.h>
#include <tee_ta_api.h>
#include <tee_internal_api.h>
#include <trace.h>
#include <gmp.h>
#include <stdlib.h>
#include <stdbool.h>

#include "cifer/data/vec.h"
#include "cifer/data/mat.h"
#include "cifer/sample/uniform.h"
#include "cifer/innerprod/simple/ddh_multi.h"

#define MPZ_WORDS_ORDER 1 /* Most significant order first */
#define MPZ_WORDS_ENDIANNESS 0 /* Use host endianness */
#define MPZ_NAILS 0 /* Use full words */

#define BENCH_INPUT_BOUND_BYTELEN 2
#define BENCH_INPUT_BOUND 1024
#define BENCH_MAX_USERS 8

/* TODO: I have no idea if retaining all of these is necessary */
static bool initialized = false;
static cfe_mat Y, mpk;
static cfe_ddh_multi inst, decryptor;
static cfe_ddh_multi_enc encryptors[BENCH_MAX_USERS];
static cfe_ddh_multi_fe_key fe_key;
static cfe_ddh_multi_sec_key msk;

/* ========================================================================== */

TEE_Result TA_fe_keygen(uint32_t param_types,
                        TEE_Param params[TEE_NUM_PARAMS])
{
    mpz_t bound, tmp;
    cfe_error err = 0;

    size_t N_modlen = 0, n_users = 0, m_veclen = 0;
    char *data_inp = NULL;
    size_t data_inp_sz = 0;
    size_t i = 0, j = 0;

    const uint32_t exp_param_types =
        TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT, /* params[0]: (N,m)  */
                TEE_PARAM_TYPE_VALUE_INPUT,         /* params[1]: n      */
                TEE_PARAM_TYPE_MEMREF_INPUT,        /* params[2]: Y      */
                TEE_PARAM_TYPE_NONE);               /* params[3]: (none) */

    /* In case instance was already initialized */
    if (initialized)
    {
        EMSG("[FE_CMD_KEYGEN] Instance already initialized.");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    /* Handles unexpected parameters combination */
    if (param_types != exp_param_types)
    {
        EMSG("[FE_CMD_KEYGEN] Bad parameters.");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    /* Retrieves parameters */
    N_modlen = params[0].value.a;
    n_users = params[0].value.b;
    m_veclen = params[1].value.a;

    /* Checks number of users */
    if (n_users > BENCH_MAX_USERS)
    {
        EMSG("[FE_CMD_KEYGEN] Too many users (%lu, max is %d).",
             n_users,
             BENCH_MAX_USERS);
        return TEE_ERROR_BAD_PARAMETERS;
    }

    data_inp = (char*) params[2].memref.buffer;
    data_inp_sz = params[2].memref.size;

    /* Checks size discrepancy */
    if (data_inp_sz != BENCH_INPUT_BOUND_BYTELEN*m_veclen*n_users)
    {
        EMSG("[FE_CMD_KEYGEN] Wrong data size (%lu, instead of %lu).",
             data_inp_sz,
             BENCH_INPUT_BOUND_BYTELEN*m_veclen*n_users);
        return TEE_ERROR_BAD_PARAMETERS;
    }

    /* Loads Y */
    mpz_init(tmp);
    cfe_mat_init(&Y, n_users, m_veclen);
    for (i = 0; i < n_users; ++i)
    {
        for (j = 0; j < m_veclen; ++j)
        {
            /*
             * The following assumes that there are
             * (n_users*m_veclen*BENCH_INPUT_BOUND_BYTELEN) bytes in data_inp
             * that are laid out in order, i.e.,
             *
             * data_inp =    [user 1]    ||    [user 2]   || ... ||   [user n]
             *          = [y_1, ..., y_m]||[y_1, ..., y_m]|| ... ||[y_1, ..., y_m].
             *
             */
            mpz_import(tmp,
                       BENCH_INPUT_BOUND_BYTELEN,
                       MPZ_WORDS_ORDER,
                       sizeof(data_inp[0]),
                       MPZ_WORDS_ENDIANNESS,
                       MPZ_NAILS,
                       &data_inp[BENCH_INPUT_BOUND_BYTELEN*m_veclen*i +
                                 BENCH_INPUT_BOUND_BYTELEN*j]);
            cfe_mat_set(&Y, tmp, i, j);
        }
    }

    /* Use only pre-computed instance */
    mpz_init_set_ui(bound, BENCH_INPUT_BOUND);
    if (N_modlen >= 1024)
    {
        err = cfe_ddh_multi_precomp_init(&inst, n_users, m_veclen, N_modlen, bound);
    }
    else
    {
        err = cfe_ddh_multi_init(&inst, n_users, m_veclen, N_modlen, bound);
    }

    /* Handles uninitialized instance */
    if (err)
    {
        EMSG("[FE_CMD_KEYGEN] Instance init failed (err=%d).", err);
        return (TEE_ERROR_GENERIC | err);
    }

    /* Generates keys */
    cfe_ddh_multi_master_keys_init(&mpk, &msk, &inst);
    cfe_ddh_multi_generate_master_keys(&mpk, &msk, &inst);
    cfe_ddh_multi_fe_key_init(&fe_key, &inst);
    cfe_ddh_multi_derive_fe_key(&fe_key, &inst, &msk, &Y);

    /* Prepares encryptor/decryptor */
    for (i = 0; i < n_users; ++i) {
        cfe_ddh_multi_enc_init(&encryptors[i], &inst);
    }
    cfe_ddh_multi_copy(&decryptor, &inst);

    /* Registers initialization */
    initialized = true;

    return TEE_SUCCESS;
}

TEE_Result TA_fe_encrypt(uint32_t param_types,
                         TEE_Param params[TEE_NUM_PARAMS])
{
    mpz_t tmp;
    cfe_vec x_vec, ct;
    cfe_vec *pub_key, *otp;
    cfe_error err = 0;
    size_t user_id = 0;
    size_t i = 0;
    const uint32_t exp_param_types =
        TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT, /* params[0]: user's id */
                TEE_PARAM_TYPE_MEMREF_INPUT,        /* params[1]: x         */
                TEE_PARAM_TYPE_MEMREF_OUTPUT,       /* params[2]: ct        */
                TEE_PARAM_TYPE_NONE);               /* params[3]: (none)    */
    char *data_inp = 0, *data_out = 0;
    size_t data_inp_sz = 0, data_out_sz = 0;

    /* Handles uninitialized instance */
    if (!initialized)
    {
        EMSG("[FE_CMD_ENCRYPT] Instance already uninitialized.");
        return TEE_ERROR_BAD_STATE;
    }

    /* Handles parameters correctness */
    if (param_types != exp_param_types)
    {
        EMSG("[FE_CMD_ENCRYPT] Bad parameters combination.");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    /* Retrieves user's id */
    user_id = params[0].value.a;

    /* Handles input buffer */
    data_inp = (char *)params[1].memref.buffer;
    data_inp_sz = params[1].memref.size;
    /* Handles output bufer */
    data_out = (char *)params[2].memref.buffer;
    data_out_sz = params[2].memref.size;

    /* Checks size discrepancy */
    if (data_inp_sz != BENCH_INPUT_BOUND_BYTELEN*inst.slots*inst.scheme.l)
    {
        EMSG("[FE_CMD_ENCRYPT] Wrong data size (%lu, instead of %lu).",
             data_inp_sz,
             BENCH_INPUT_BOUND_BYTELEN*inst.scheme.l*inst.slots);
        return TEE_ERROR_BAD_PARAMETERS;
    }

    /* Loads x_vec */
    mpz_init(tmp);
    cfe_vec_init(&x_vec, inst.scheme.l);
    for (i = 0; i < inst.scheme.l; ++i)
    {
        mpz_import(tmp,
                   BENCH_INPUT_BOUND_BYTELEN,
                   MPZ_WORDS_ORDER,
                   sizeof(data_inp[0]),
                   MPZ_WORDS_ENDIANNESS,
                   MPZ_NAILS,
                   &data_inp[BENCH_INPUT_BOUND_BYTELEN*i]);
        cfe_vec_set(&x_vec, tmp, i);
    }

    /* Recover public key, otp key */
    pub_key = cfe_mat_get_row_ptr(&mpk, 0);
    otp = cfe_mat_get_row_ptr(&msk.otp_key, 0);

    /* Starts encryption */
    cfe_ddh_multi_ciphertext_init(&ct, &encryptors[user_id]);
    err = cfe_ddh_multi_encrypt(&ct, &encryptors[user_id], &x_vec, pub_key, otp);

    if (err)
    {
        EMSG("[FE_CMD_ENCRYPT] Encryption error.");
    }
    else {
        /* Exports ciphertext */
        params[2].memref.size = 0;
        data_out_sz = 0;
        for (i = 0; i < inst.scheme.l; ++i)
        {
            cfe_vec_get(tmp, &ct, i);
            /* 
             * HACK: total size used as a index in the array (which is updated
             *       at each iteration).
             *
             * The correct method here would be to predict how any bytes are
             * required in the worst case for each component of the vector.
             *
             * However, the TA maximal size limits the number of bytes to be
             * transferred back to the client with the largest benchmark
             * parameters (64 KB = 524 288 bits = 128*4096 bits).
             *
             * The code below was just written to compile, but there is no
             * guarantee of functionality.
             */
            mpz_export(&data_out[params[2].memref.size], /* here */
                       &data_out_sz,
                       MPZ_WORDS_ORDER,
                       sizeof(data_out[0]),
                       MPZ_WORDS_ENDIANNESS,
                       MPZ_NAILS,
                       tmp);
            params[2].memref.size += data_out_sz;
        }
    }

    /* Free everything */
    cfe_vec_free(&ct);
    cfe_vec_free(&x_vec);
    mpz_clear(tmp);

    return (err == 0 ? TEE_SUCCESS : TEE_ERROR_GENERIC | err);
}

TEE_Result TA_fe_decrypt(uint32_t param_types,
                         TEE_Param params[TEE_NUM_PARAMS])
{
    mpz_t tmp, prod;
    cfe_mat C;
    cfe_error err = 0;
    size_t i = 0, j = 0;
    size_t chunk_size = 1;
    const uint32_t exp_param_types =
        TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT, /* params[0]: C      */
                TEE_PARAM_TYPE_MEMREF_OUTPUT,        /* params[1]: prod   */
                TEE_PARAM_TYPE_NONE,                /* params[2]: (none) */
                TEE_PARAM_TYPE_NONE);               /* params[3]: (none) */
    char *data_inp = 0, *data_out = 0;
    size_t data_inp_sz = 0, data_out_sz = 0;

    /* Handles uninitialized instance */
    if (!initialized)
    {
        EMSG("[FE_CMD_DECRYPT] Instance already uninitialized.");
        return TEE_ERROR_BAD_STATE;
    }

    /* Handles parameters correctness */
    if (param_types != exp_param_types)
    {
        EMSG("[FE_CMD_DECRYPT] Bad parameters combination.");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    /* Handles input buffer */
    data_inp = (char *)params[0].memref.buffer;
    data_inp_sz = params[0].memref.size;
    /* Handles output bufer */
    data_out = (char *)params[1].memref.buffer;
    data_out_sz = params[1].memref.size;

    /* Checks size discrepancy */
    chunk_size = ((data_inp_sz / inst.slots) / inst.scheme.l);
    if (chunk_size*inst.scheme.l*inst.slots != data_inp_sz)
    {
        EMSG("[FE_CMD_DECRYPT] Wrong data size (%lu is not a multiple of %lu*%lu).",
             data_inp_sz,
             inst.slots,
             inst.scheme.l);
        return TEE_ERROR_BAD_PARAMETERS;
    }

    /* Loads C */
    mpz_init(tmp);
    cfe_mat_init(&C, inst.slots, inst.scheme.l);
    for (i = 0; i < inst.slots; ++i)
    {
        for (j = 0; j < inst.scheme.l; ++j)
        {
            /*
             * The following assumes that there are
             * (inst.slots*inst.scheme.l*BENCH_INPUT_BOUND_BYTELEN) bytes in data_inp
             * that are laid out in order, i.e.,
             *
             * data_inp =    [user 1]    ||    [user 2]   || ... ||   [user n]
             *          = [c_1, ..., c_m]||[c_1, ..., c_m]|| ... ||[c_1, ..., c_m].
             *
             */
            mpz_import(tmp,
                       BENCH_INPUT_BOUND_BYTELEN,
                       MPZ_WORDS_ORDER,
                       sizeof(data_inp[0]),
                       MPZ_WORDS_ENDIANNESS,
                       MPZ_NAILS,
                       &data_inp[BENCH_INPUT_BOUND_BYTELEN*inst.scheme.l*i +
                                 BENCH_INPUT_BOUND_BYTELEN*j]);
            cfe_mat_set(&C, tmp, i, j);
        }
    }

    /* Starts encryption */
    mpz_init(prod);
    err = cfe_ddh_multi_decrypt(prod, &decryptor, &C, &fe_key, &Y);

    if (err)
    {
        EMSG("[FE_CMD_DECRYPT] Encryption error.");
    }
    else {
        /* Exports product */
        mpz_export(&data_out[params[2].memref.size],
                   &data_out_sz,
                   MPZ_WORDS_ORDER,
                   sizeof(data_out[0]),
                   MPZ_WORDS_ENDIANNESS,
                   MPZ_NAILS,
                   tmp);
        params[1].memref.size += data_out_sz;
    }

    /* Free everything so init can work again */
    cfe_mat_free(&C);
    mpz_clear(tmp);

    return (err == 0 ? TEE_SUCCESS : TEE_ERROR_GENERIC | err);
}

TEE_Result TA_fe_clear(uint32_t param_types,
                      TEE_Param params[TEE_NUM_PARAMS])
{
    const uint32_t exp_param_types =
        TEE_PARAM_TYPES(TEE_PARAM_TYPE_NONE, /* params: (none) */
                TEE_PARAM_TYPE_NONE,
                TEE_PARAM_TYPE_NONE,
                TEE_PARAM_TYPE_NONE);
    size_t i = 0;

    /* Handles uninitialized instance */
    if (!initialized)
    {
        EMSG("[FE_CMD_CLEAR] Instance uninitialized.");
        return TEE_ERROR_BAD_STATE;
    }

    /* Handles unexpected parameters combination */
    if (param_types != exp_param_types)
    {
        EMSG("[FE_CMD_CLEAR] Bad parameters.");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    /* Clears everything */
    cfe_mat_frees(&Y, &mpk, NULL);
    cfe_ddh_multi_sec_key_free(&msk);
    cfe_ddh_multi_fe_key_free(&fe_key);
    cfe_ddh_multi_free(&inst);
    for (i = 0; i < inst.slots; ++i)
    {
        cfe_ddh_multi_enc_free(&encryptors[i]);
    }
    cfe_ddh_multi_free(&decryptor);

    /* Registers uninitialization */
    initialized = false;

    return TEE_SUCCESS;
}