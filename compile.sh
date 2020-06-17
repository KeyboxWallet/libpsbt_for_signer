#!/bin/sh
CRYPTOLIB_DIR=../crypto_lib
gcc -I./include/ -I${CRYPTOLIB_DIR} src/psbt.c src/script.c \
 src/buffer.c src/chainparams.c src/tx.c src/memory.c src/vector.c src/cstr.c \
 src/serialize.c test/psbt_tests.c test/utils.c \
 ${CRYPTOLIB_DIR}/sha2.c ${CRYPTOLIB_DIR}/ripemd160.c ${CRYPTOLIB_DIR}/memzero.c \
 ${CRYPTOLIB_DIR}/segwit_addr.c ${CRYPTOLIB_DIR}/base58.c ${CRYPTOLIB_DIR}/hasher.c \
 ${CRYPTOLIB_DIR}/blake*.c ${CRYPTOLIB_DIR}/groestl.c ${CRYPTOLIB_DIR}/sha3.c
