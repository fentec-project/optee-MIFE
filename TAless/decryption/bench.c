#include <gmp.h>
#include <time.h>
#include <stdio.h>
#include <stdlib.h>

#define BENCH_INPUT_BOUND_BASE 2
#define BENCH_INPUT_BOUND_POW  10

const size_t bench_modlen[] = {512, 1024, 2048, 3072, 4096};
const size_t bench_users[] = {2, 3, 4, 5};
const size_t bench_inpsize[] = {5, 10, 15, 20};
const size_t bench_times[] = {100, 100, 100, 10, 1};
const size_t bench_rand[] = {100, 100, 100, 100, 100};
#define BENCH_MODLEN_N 5
#define BENCH_INPSIZE_N 4
#define BENCH_USERS_N 4

#define BENCH_MAX_USERS 8

#include "cifer/data/vec.h"
#include "cifer/data/mat.h"
#include "cifer/sample/uniform.h"
#include "cifer/innerprod/simple/ddh_multi.h"

int main(void)
{
    /* Benchmark indexes */
    volatile size_t m = 0, n = 0, u = 0, i = 0, t = 0, r = 0, k = 0;

    clock_t tic = 0, total_time = 0;
    cfe_mat global_X, global_Y;
    mpz_t bound, prod;
    cfe_mat X, Y, mpk, ciphertext;
    cfe_ddh_multi_sec_key msk;
    cfe_ddh_multi inst, decryptor;
    cfe_ddh_multi_fe_key fe_key;
    cfe_ddh_multi_enc encryptors[BENCH_MAX_USERS];
    cfe_vec ct;
    cfe_vec *pub_key, *otp, *x_vec;
    cfe_error err = 0, err_count = 0;

    /* Sanity check */
    if (bench_users[BENCH_MODLEN_N-1] > BENCH_MAX_USERS)
    {
        fprintf(stderr, "[ERROR] more users than max (%ld > %d).\n",
                bench_users[BENCH_MODLEN_N-1], BENCH_MAX_USERS);
        return 1;
    }

    /* Bounds borrowed from tests */
    mpz_inits(bound, prod, NULL);
    mpz_set_ui(bound, BENCH_INPUT_BOUND_BASE);
    mpz_pow_ui(bound, bound, BENCH_INPUT_BOUND_POW);

    /* Draw X and Y once and for all */
    cfe_mat_inits(bench_users[BENCH_USERS_N-1],
                  bench_rand[BENCH_MODLEN_N-1]*bench_inpsize[BENCH_INPSIZE_N-1],
                  &global_X, &global_Y, NULL);
    cfe_uniform_sample_mat(&global_X, bound);
    cfe_uniform_sample_mat(&global_Y, bound);

    #ifdef DEBUG
    gmp_printf("[INIT] global_X, global_Y of size %dx%d sampled: %Zd, %Zd, ...\n",
               bench_users[BENCH_USERS_N-1],
               bench_rand[BENCH_MODLEN_N-1]*bench_inpsize[BENCH_INPSIZE_N - 1],
               global_X.mat[0].vec[0], global_Y.mat[0].vec[0]);
    #endif

    for (m = 0; m < BENCH_MODLEN_N; ++m) {
        for (i = 0; i < BENCH_INPSIZE_N; ++i) {
            for (n = 0; n < BENCH_USERS_N; ++n) {
                cfe_mat_inits(bench_users[n],
                              bench_inpsize[i],
                              &X, &Y, NULL);
                /* Set appropriate matrix for Y */
                for (u = 0; u < bench_users[n]; ++u) {
                    for (k = 0; k < bench_inpsize[i]; ++k) {
                        cfe_mat_set(&Y, global_Y.mat[u].vec[k], u, k);
                    }
                }

                /* Init instance of multi_ddh */
                if (bench_modlen[m] >= 1024) {
                    cfe_ddh_multi_precomp_init(&inst,
                                               bench_users[n],
                                               bench_inpsize[i],
                                               bench_modlen[m],
                                               bound);
                } else {
                    cfe_ddh_multi_init(&inst,
                                       bench_users[n],
                                       bench_inpsize[i],
                                       bench_modlen[m],
                                       bound);
                }

                /* Derive keys */
                cfe_ddh_multi_master_keys_init(&mpk, &msk, &inst);
                cfe_ddh_multi_generate_master_keys(&mpk, &msk, &inst);
                cfe_ddh_multi_fe_key_init(&fe_key, &inst);
                cfe_ddh_multi_derive_fe_key(&fe_key, &inst, &msk, &Y);

                printf("[N=%ld, m=%ld, n=%ld] ... ", bench_modlen[m], bench_inpsize[i], bench_users[n]);
                for (r = 0; r < bench_rand[m]; ++r) {
                    /* Draw next random values for X */
                    for (u = 0; u < bench_users[n]; ++u) {
                        for (k = 0; k < bench_inpsize[i]; ++k) {
                            cfe_mat_set(&X, global_X.mat[u].vec[k+r*bench_inpsize[i]], u, k);
                        }
                    }

                    /* Init encryption and encrypt */
                    cfe_mat_init(&ciphertext, bench_users[n], bench_inpsize[i] + 1);
                    for (u = 0; u < bench_users[n]; ++u) {
                        cfe_ddh_multi_enc_init(&encryptors[u], &inst);
                        pub_key = cfe_mat_get_row_ptr(&mpk, u);
                        otp = cfe_mat_get_row_ptr(&msk.otp_key, u);
                        x_vec = cfe_mat_get_row_ptr(&X, u);
                        cfe_ddh_multi_ciphertext_init(&ct, &encryptors[u]);
                        err = cfe_ddh_multi_encrypt(&ct, &encryptors[u], x_vec, pub_key, otp);
                        if (err) {
                            printf("[ERROR] user %ld failed encryption.\n", u);
                        }
                        cfe_mat_set_vec(&ciphertext, &ct, u);
                        cfe_vec_free(&ct);
                        cfe_ddh_multi_enc_free(&encryptors[u]);
                    }

                    /* Benchmark */
                    cfe_ddh_multi_copy(&decryptor, &inst);
                    tic = clock();
                    for (t = 0; t < bench_times[m]; ++t) {
                        err_count += cfe_ddh_multi_decrypt(prod, &decryptor, &ciphertext, &fe_key, &Y) ? 1 : 0;
                    }
                    total_time = clock() - tic;
                }

                printf("clock cycles/total runs:  %ld/%ld\tTime:  %f/%ld seconds (total errs: %d).\n",
                   total_time,
                   bench_times[m]*bench_rand[m],
                   (double) total_time/CLOCKS_PER_SEC,
                   bench_times[m]*bench_rand[m],
                   err_count);

                /* Free everything so init can work again */
                total_time = 0;
                cfe_mat_frees(&X, &Y, &mpk, &ciphertext, NULL);
                cfe_ddh_multi_sec_key_free(&msk);
                cfe_ddh_multi_fe_key_free(&fe_key);
                cfe_ddh_multi_free(&inst);
                cfe_ddh_multi_free(&decryptor);
            }
        }
    }

    /* Final free */
    mpz_clears(bound, prod, NULL);
    cfe_mat_frees(&global_X, &global_Y, NULL);

    return 0;
}
