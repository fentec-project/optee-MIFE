/*
 * Copyright (c) 2018 XLAB d.o.o.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/* #OPTEE */
/*include <sodium.h>*/
/* #OPTEE */
#include <tee_internal_api.h>
#include <user_ta_header_defines.h>

#include "cifer/internal/common.h"

cfe_error cfe_init(void) {
    /* #OPTEE */
    /*
    if (sodium_init() == -1) {
        return CFE_ERR_INIT;
    }
    */
    return CFE_ERR_NONE;
}

void *cfe_malloc(size_t size) {
    /* #OPTEE */
    void *ptr = TEE_Malloc(size,
                           TEE_MALLOC_FILL_ZERO |
                           TEE_MALLOC_NO_SHARE);

    if (size != 0 && ptr == NULL) {
        /* #OPTEE */
        EMSG("[cfe_malloc] Failed to allocate memory.");
        /* #OPTEE */
        return NULL;
    }

    return ptr;
}
