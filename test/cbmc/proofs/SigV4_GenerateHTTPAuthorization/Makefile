# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

HARNESS_ENTRY = harness
HARNESS_FILE = SigV4_GenerateHTTPAuthorization_harness

# This should be a unique identifier for this proof, and will appear on the
# Litani dashboard. It can be human-readable and contain spaces if you wish.
PROOF_UID = SigV4_GenerateHTTPAuthorization

MAX_QUERY_LEN=6
MAX_HEADERS_LEN=6
MAX_PATH_LEN=6
MAX_URI_LEN=3
MAX_ENCODED_PATH_LEN=$(shell expr $(MAX_URI_LEN) \* 2)
S3_SERVICE_LEN=2

DEFINES += -DMAX_QUERY_LEN=$(MAX_QUERY_LEN)
DEFINES += -DMAX_HEADERS_LEN=$(MAX_HEADERS_LEN)
DEFINES += -DMAX_URI_LEN=$(MAX_URI_LEN)
INCLUDES +=

REMOVE_FUNCTION_BODY += memcpy
REMOVE_FUNCTION_BODY += memmove
REMOVE_FUNCTION_BODY += maskrune
UNWINDSET += setQueryStringFieldsAndValues.0:$(MAX_QUERY_LEN)
UNWINDSET += parseHeaderKeyValueEntries.0:$(MAX_HEADERS_LEN)
UNWINDSET += __CPROVER_file_local_sigv4_c_encodeURI.0:$(MAX_ENCODED_PATH_LEN)
UNWINDSET += strncmp.0:$(S3_SERVICE_LEN)

PROOF_SOURCES += $(PROOFDIR)/$(HARNESS_FILE).c
PROOF_SOURCES += $(SRCDIR)/test/cbmc/stubs/hash_stubs.c
PROOF_SOURCES += $(SRCDIR)/test/cbmc/stubs/memcpy.c
PROOF_SOURCES += $(SRCDIR)/test/cbmc/stubs/memmove.c
PROOF_SOURCES += $(SRCDIR)/test/cbmc/stubs/sigv4_stubs.c

include ../Makefile-json.common

# Substitution command to pass to sed for patching sigv4.c. The
# characters " and # must be escaped with backslash.
SIGV4_SED_EXPR = 1s/^/\#include \"sigv4_stubs.h\" /; s/^static //; s/SigV4Status_t (scanValue|encodeURI)\b/&_/
