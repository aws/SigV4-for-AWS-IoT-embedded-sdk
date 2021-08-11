# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

HARNESS_ENTRY = harness
HARNESS_FILE = SigV4_GenerateHTTPAuthorization_harness

# This should be a unique identifier for this proof, and will appear on the
# Litani dashboard. It can be human-readable and contain spaces if you wish.
PROOF_UID = SigV4_GenerateHTTPAuthorization

DEFINES +=
INCLUDES +=


REMOVE_FUNCTION_BODY +=
UNWINDSET +=

PROOF_SOURCES += $(PROOFDIR)/$(HARNESS_FILE).c
PROOF_SOURCES += $(SRCDIR)/test/cbmc/stubs/sigv4_stubs.c

PROJECT_SOURCES += $(SRCDIR)/source/sigv4.c

include ../Makefile-json.common

# Substitution command to pass to sed for patching sigv4.c. The
# characters " and # must be escaped with backslash.
SIGV4_SED_EXPR = 1s/^/\#include \"sigv4_stubs.h\" /; s/^static //; s/SigV4Status_t scanValue\b/&_/
