/* #OPTEE */

#ifndef CIFER_DATA_TYPES_H
#define CIFER_DATA_TYPES_H

#include <gmp.h>

/**
 * Vector of arbitrary precision (GMP) integers.
 */
typedef struct cfe_vec {
    mpz_t *vec; /** A pointer to the first integer */
    size_t size; /** The size of the vector */
} cfe_vec;

/**
 * Matrix of arbitrary precision (GMP) integers.
 * It represents a row-major matrix. A matrix of dimensions i, j consists of i
 * vectors, each consisting of j elements.
 */
typedef struct cfe_mat {
    cfe_vec *mat; /** The pointer to the first vector */
    size_t rows; /** The number or rows (vectors) */
    size_t cols; /** The number of columns (size of vectors */
} cfe_mat;


#endif /* CIFER_DATA_TYPES_H */