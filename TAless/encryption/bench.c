#include <gmp.h>
#include <time.h>
#include <stdio.h>
#include <stdlib.h>

#define BENCH_INPUT_BOUND_BASE 2
#define BENCH_INPUT_BOUND_POW  10

const size_t bench_modlen[] = {512, 1024, 2048, 3072, 16};
const size_t bench_inpsize[] = {2, 20, 30, 40, 50};
const size_t bench_times[] = {100, 100,100 , 10, 10};
const size_t bench_rand[] = {100, 100, 100, 100, 10};
#define BENCH_MODLEN_N 5
#define BENCH_INPSIZE_N 5
#define BENCH_USERS_N 1

#include "cifer/data/vec.h"
#include "cifer/data/mat.h"
#include "cifer/sample/uniform.h"
#include "cifer/innerprod/simple/ddh_multi.h"

int main(void)
{
    /* Benchmark indexes */
    volatile size_t i = 0, j = 0, k = 0, r = 0;

    clock_t t = 0, total_t = 0;
    mpz_t bound, prod;
    cfe_mat X, Y, mpk, ciphertext;
    cfe_mat global_X, global_Y;
    cfe_ddh_multi m, decryptor;
    cfe_ddh_multi_sec_key msk;
    cfe_ddh_multi_fe_key fe_key;
    cfe_ddh_multi_enc encryptor;
    cfe_vec ct;
    cfe_vec *pub_key, *otp, *x_vec;
    cfe_error err = 0;

    /* Bounds borrowed from tests */
    mpz_inits(bound, prod, NULL);
    mpz_set_ui(bound, BENCH_INPUT_BOUND_BASE);
    mpz_pow_ui(bound, bound, BENCH_INPUT_BOUND_POW);

    /* Draw X and Y once and for all */
    cfe_mat_init(&global_X,
                 BENCH_USERS_N,
                 bench_rand[0]*bench_inpsize[BENCH_INPSIZE_N - 1]);
    cfe_mat_init(&global_Y,
                 BENCH_USERS_N,
                 bench_inpsize[BENCH_INPSIZE_N - 1]);
    cfe_uniform_sample_mat(&global_Y, bound);
    cfe_uniform_sample_mat(&global_X, bound);

    #ifdef DEBUG
    gmp_printf("[INIT] global_X, global_Y of size %dx%d sampled: %Zd, %Zd, ...\n",
               BENCH_USERS_N,
               bench_rand[0]*bench_inpsize[BENCH_INPSIZE_N - 1],
               global_X.mat[0].vec[0], global_Y.mat[0].vec[0]);
    #endif

    for (i = 4; i < BENCH_MODLEN_N; ++i) {
        for (j = 0; j < BENCH_INPSIZE_N; ++j) {
            cfe_mat_inits(BENCH_USERS_N,
                          bench_inpsize[j],
                          &X, &Y, NULL);
            for (k = 0; k < bench_inpsize[j]; ++k) {
                cfe_mat_set(&Y, global_Y.mat[0].vec[k], 0, k);
            }
            #ifdef DEBUG
            gmp_printf("[LOOP:%d,%d] Y of size %dx%d sampled: %Zd, ...\n",
               i, j, BENCH_USERS_N,
               bench_inpsize[j],
               Y.mat[0].vec[0]);
            #endif

            /* Simultaneously init and set everything with parameters */
            if (bench_modlen[i] >= 1024) {
                err = cfe_ddh_multi_precomp_init(&m, BENCH_USERS_N, bench_inpsize[j], bench_modlen[i], bound);
            } else {
                err = cfe_ddh_multi_init(&m, BENCH_USERS_N, bench_inpsize[j], bench_modlen[i], bound);
            }

            /* Handles uninitialized instance */
            if (err) {
                printf("[ERROR] err=%d occurred after initialization.\n", err);
                return 1;
            }
            #ifdef DEBUG
            gmp_printf("[LOOP:%d,%d] m = {\n\tslots=%ld, \
                       \n\tscheme={\n\t\tl=%ld,          \
                       \n\t\tbound=%Zd,                  \
                       \n\t\tg=%Zd,                      \
                       \n\t\tp=%Zd,                      \
                       \n\t\tq=%Zd                       \
                       \n\t\t}                           \
                       \n\t}\n",
               i, j, m.slots, m.scheme.l, m.scheme.bound, m.scheme.g, m.scheme.p, m.scheme.q);
            #endif
            cfe_ddh_multi_master_keys_init(&mpk, &msk, &m);
            cfe_ddh_multi_generate_master_keys(&mpk, &msk, &m);
            cfe_ddh_multi_fe_key_init(&fe_key, &m);
            cfe_ddh_multi_derive_fe_key(&fe_key, &m, &msk, &Y);
            cfe_ddh_multi_enc_init(&encryptor, &m);
            cfe_ddh_multi_ciphertext_init(&ct, &encryptor);
            cfe_mat_init(&ciphertext, BENCH_USERS_N, bench_inpsize[j] + 1);

            /* Recover public key, otp key */
            pub_key = cfe_mat_get_row_ptr(&mpk, 0);
            otp = cfe_mat_get_row_ptr(&msk.otp_key, 0);

            printf("[N=%ld, m=%ld] ... ", bench_modlen[i], bench_inpsize[j]);
            for (r = 0; r < bench_rand[i]; ++r) {
                /* Draw next random values for X */
                for (k = 0; k < bench_inpsize[j]; ++k) {
                    cfe_mat_set(&X, global_X.mat[0].vec[k+r*bench_inpsize[j]], 0, k);
                }
                x_vec = cfe_mat_get_row_ptr(&X, 0);

                #ifdef DEBUG
                gmp_printf("[LOOP:%d,%d,%d] X of size %dx%d sampled: %Zd, ...\n",
                   i, j, r, BENCH_USERS_N,
                   bench_inpsize[j],
                   x_vec->vec[0]);
                #endif

                /* Begin benchmark */
                t = clock();
                for (k = 0; k < bench_times[i]; ++k) {
                    err = cfe_ddh_multi_encrypt(&ct, &encryptor, x_vec, pub_key, otp);
                }
                total_t += clock() - t;

                cfe_mat_set_vec(&ciphertext, &ct, 0);
                cfe_ddh_multi_copy(&decryptor, &m);
                err = cfe_ddh_multi_decrypt(prod, &decryptor, &ciphertext, &fe_key, &Y);

                if (err != 0) {
                    printf("[ERROR] err=%d occurred after decryption.\n", err);
                }
                cfe_ddh_multi_free(&decryptor);
            }

            printf("clock cycles/total runs:  %ld/%ld\tTime:  %f/%ld seconds.\n",
                   total_t,
                   bench_times[i]*bench_rand[i],
                   (double) total_t/CLOCKS_PER_SEC,
                   bench_times[i]*bench_rand[i]);

            /* Free everything so init can work again */
            total_t = 0;
            cfe_vec_free(&ct);
            cfe_mat_frees(&X, &Y, &mpk, &ciphertext, NULL);
            cfe_ddh_multi_sec_key_free(&msk);
            cfe_ddh_multi_fe_key_free(&fe_key);
            cfe_ddh_multi_free(&m);
            cfe_ddh_multi_enc_free(&encryptor);
        }
    }

    /* Final free */
    mpz_clears(bound, prod, NULL);
    cfe_mat_frees(&global_X, &global_Y, NULL);


    return 0;
}
