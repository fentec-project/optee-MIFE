# Include directories used by the TA
global-incdirs-y += ../include ../plugin/include \

# Source files to build the TA
srcs-y += $(wildcard ../plugin/src/**/*.c) $(wildcard ../plugin/src/innerprod/**/*.c) ta_features.c ta_entry.c

# Additional libraries
libnames += gmp
libdeps += $(ta-dev-kit-dir)/lib/libgmp.a
