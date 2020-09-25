
CFG_TEE_TA_LOG_LEVEL ?= 4
TA_UUID_STRING ?= fe0022e7-5bd6-408a-8287-b999e194d8de

CPPFLAGS += \
    -DCFG_TEE_TA_LOG_LEVEL=$(CFG_TEE_TA_LOG_LEVEL) \
    -DTA_UUID_STRING=$(TA_UUID_STRING) \
    -DSAL_TEST_SUITE_OS_MALLOC_NEVER_NULL \
    -Wall \
    -Wextra \
    -Wno-missing-field-initializers \
    -Wno-unused-parameter \
    -Wfloat-equal \
    -Wformat-security \
    -Wformat-nonliteral \
    -Wformat-y2k \
    -Wmissing-declarations \
    -Wmissing-include-dirs \
    -Wmissing-noreturn \
    -Wnested-externs \
    -Wshadow \
    -Wstrict-prototypes \
    -Wswitch-default \
    -pedantic \
    -fstack-protector-all \
    -fpie

# The UUID for the trusted application (must match DSEC_TA_UUID)
BINARY=$(TA_UUID_STRING)

$(info Binary of TA ${BINARY})

ifeq ($(TA_DEV_KIT_DIR),)
    $(error "TA_DEV_KIT_DIR not set. Aborting...")
endif

$(info Using TA_DEV_KIT_DIR=$(TA_DEV_KIT_DIR))

ifeq ($(wildcard $(TA_DEV_KIT_DIR)/mk/ta_dev_kit.mk), )
    $(error "TA_DEV_KIT_DIR is an invalid directory. Aborting...")
endif

include $(TA_DEV_KIT_DIR)/mk/ta_dev_kit.mk
