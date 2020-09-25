#ifndef USER_TA_HEADER_DEFINES_H
#define USER_TA_HEADER_DEFINES_H

#include <fe_config.h>

#define TA_UUID FE_UUID

#define TA_FLAGS (TA_FLAG_USER_MODE | \
                  TA_FLAG_EXEC_DDR)

#define TA_STACK_SIZE (64 * 1024) /* 64 KB */
#define TA_DATA_SIZE  (64 * 1024) /* 64 KB */

#define TA_DESCRIPTION "Multi-Input Functional Encryption Algorithm for FENTEC"
#define TA_VERSION "1.0.0"

/* From TEE Internal Core API Specification (v1.2, Oct 2018) */
#define TEE_MALLOC_NO_SHARE 0x00000002

#endif /* USER_TA_HEADER_DEFINES_H */
