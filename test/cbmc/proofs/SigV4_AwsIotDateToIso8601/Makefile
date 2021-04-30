# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

HARNESS_ENTRY = harness
HARNESS_FILE = SigV4_AwsIotDateToIso8601_harness

# This should be a unique identifier for this proof, and will appear on the
# Litani dashboard. It can be human-readable and contain spaces if you wish.
PROOF_UID = SigV4_AwsIotDateToIso8601

DEFINES +=
INCLUDES +=

MONTH_ASCII_LEN=3
ISO_YEAR_LEN=4
MONTHS_IN_YEAR=12
FORMAT_RFC_5322_LEN=32

REMOVE_FUNCTION_BODY +=
UNWINDSET += __CPROVER_file_local_sigv4_c_parseDate.0:$(FORMAT_RFC_5322_LEN)
UNWINDSET += __CPROVER_file_local_sigv4_c_scanValue.0:$(MONTHS_IN_YEAR)
UNWINDSET += __CPROVER_file_local_sigv4_c_scanValue.1:$(ISO_YEAR_LEN)
UNWINDSET += __CPROVER_file_local_sigv4_c_intToAscii.0:$(ISO_YEAR_LEN)
UNWINDSET += strncmp.0:$(MONTH_ASCII_LEN)

PROOF_SOURCES += $(PROOFDIR)/$(HARNESS_FILE).c
PROJECT_SOURCES += $(SRCDIR)/source/sigv4.c

include ../Makefile.common
