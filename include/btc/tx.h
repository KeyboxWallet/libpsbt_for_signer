/*

 The MIT License (MIT)

 Copyright (c) 2015 Jonas Schnelli

 Permission is hereby granted, free of charge, to any person obtaining
 a copy of this software and associated documentation files (the "Software"),
 to deal in the Software without restriction, including without limitation
 the rights to use, copy, modify, merge, publish, distribute, sublicense,
 and/or sell copies of the Software, and to permit persons to whom the
 Software is furnished to do so, subject to the following conditions:

 The above copyright notice and this permission notice shall be included
 in all copies or substantial portions of the Software.

 THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES
 OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
 ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 OTHER DEALINGS IN THE SOFTWARE.

*/

#ifndef __LIBBTC_TX_H__
#define __LIBBTC_TX_H__

#include "btc.h"
#include "chainparams.h"
#include "cstr.h"
#include "hash.h"
#include "script.h"
#include "vector.h"

LIBBTC_BEGIN_DECL

typedef struct btc_script_ {
    int* data;
    size_t limit;   // Total size of the vector
    size_t current; //Number of vectors in it at present
} btc_script;

typedef struct btc_tx_outpoint_ {
    uint256 hash;
    uint32_t n;
} btc_tx_outpoint;

typedef struct btc_tx_in_ {
    btc_tx_outpoint prevout;
    cstring* script_sig;
    uint32_t sequence;
    vector* witness_stack;
} btc_tx_in;

typedef struct btc_tx_out_ {
    int64_t value;
    cstring* script_pubkey;
} btc_tx_out;

typedef struct btc_tx_ {
    int32_t version;
    vector* vin;
    vector* vout;
    uint32_t locktime;
} btc_tx;


//!create a new tx input
LIBBTC_API btc_tx_in* btc_tx_in_new(void);
LIBBTC_API void btc_tx_in_free(btc_tx_in* tx_in);
LIBBTC_API void btc_tx_in_copy(btc_tx_in* dest, const btc_tx_in* src);

//!create a new tx output
LIBBTC_API btc_tx_out* btc_tx_out_new(void);
LIBBTC_API void btc_tx_out_free(btc_tx_out* tx_out);
LIBBTC_API void btc_tx_out_copy(btc_tx_out* dest, const btc_tx_out* src);

//!create a new tx input
LIBBTC_API btc_tx* btc_tx_new(void);
LIBBTC_API void btc_tx_free(btc_tx* tx);
LIBBTC_API void btc_tx_copy(btc_tx* dest, const btc_tx* src);

//!deserialize/parse a p2p serialized bitcoin transaction
LIBBTC_API int btc_tx_deserialize(const unsigned char* tx_serialized, size_t inlen, btc_tx* tx, size_t* consumed_length, btc_bool allow_witness);
btc_bool btc_tx_out_deserialize(btc_tx_out* tx_out, struct const_buffer* buf);

//!serialize a lbc bitcoin data structure into a p2p serialized buffer
LIBBTC_API void btc_tx_serialize(cstring* s, const btc_tx* tx, btc_bool allow_witness);

LIBBTC_API void btc_tx_hash(const btc_tx* tx, uint8_t* hashout);

LIBBTC_API btc_bool btc_tx_sighash(const btc_tx* tx_to, const cstring* fromPubKey, unsigned int in_num, int hashtype, const uint64_t amount, const enum btc_sig_version sigversion, uint8_t* hash);

LIBBTC_API btc_bool btc_tx_add_address_out(btc_tx* tx, const btc_chainparams* chain, int64_t amount, const char* address);
LIBBTC_API btc_bool btc_tx_add_p2sh_hash160_out(btc_tx* tx, int64_t amount, uint160 hash160);
LIBBTC_API btc_bool btc_tx_add_p2pkh_hash160_out(btc_tx* tx, int64_t amount, uint160 hash160);
//LIBBTC_API btc_bool btc_tx_add_p2pkh_out(btc_tx* tx, int64_t amount, const btc_pubkey* pubkey);

LIBBTC_API btc_bool btc_tx_add_data_out(btc_tx* tx, const int64_t amount, const uint8_t *data, const size_t datalen);
LIBBTC_API btc_bool btc_tx_add_puzzle_out(btc_tx* tx, const int64_t amount, const uint8_t *puzzle, const size_t puzzlelen);

LIBBTC_API btc_bool btc_tx_outpoint_is_null(btc_tx_outpoint* tx);
LIBBTC_API btc_bool btc_tx_is_coinbase(btc_tx* tx);

LIBBTC_API btc_bool btc_tx_has_witness(const btc_tx *tx);
LIBBTC_API btc_bool btc_tx_has_scriptSig(const btc_tx *tx);
LIBBTC_API void btc_tx_get_output_address(char address[98], const btc_tx_out * tx_out, const btc_chainparams * params);
LIBBTC_API void bch_tx_get_output_address(char address[98], const btc_tx_out * tx_out, const char * hrp);


LIBBTC_END_DECL

#endif // __LIBBTC_TX_H__
