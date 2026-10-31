# SPDX-License-Identifier: BSD-2-Clause
# OP-TEE Trusted Application Makefile fragment

global-incdirs-y += .
global-incdirs-y += ../../usepqc

srcs-y += ta_entry.c
srcs-y += crypto_service.c
srcs-y += policy_service.c

# Link liboqs shim / PQC primitives compiled into TA space
libdirs-y += ../../usepqc
libnames-y += usepqc_ta

# Security and optimization flags
cflags-y += -Wall -Wextra -Werror -Wno-unused-parameter
cflags-y += -fstack-protector-strong -fPIE -D_FORTIFY_SOURCE=2
cflags-y += -O2

