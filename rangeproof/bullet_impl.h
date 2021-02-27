/**********************************************************************
* Copyright (c) 2017 Andrew Poelstra                                 *
* Distributed under the MIT software license, see the accompanying   *
* file COPYING or http://www.opensource.org/licenses/mit-license.php.*
**********************************************************************/
//#include "D:/GitR/ConsoleApplication1/ConsoleApplication1/stdafx.h"

#include <stdint.h>
#include<string.h>
#include<malloc.h>
#include "include/secp256k1_generator.h"
#include "include/secp256k1_commitment.h"
#include "include/secp256k1_bulletproofs.h"
#include "util.h"
//#include "bench.h"
//using namespace std;


#define MAX_PROOF_SIZE	2000
//#define CIRCUIT_DIR "D:/GitR/secp256k1-mw/src/modules/bulletproofs/bin_circuits/"

typedef struct {
	secp256k1_context *ctx;
	secp256k1_scratch_space *scratch;
	unsigned char nonce[32];
	unsigned char **proof;
	secp256k1_bulletproof_generators *generators;
	secp256k1_generator *value_gen;
	secp256k1_generator blind_gen;
	size_t n_proofs;
	size_t plen;
	size_t iters;//
} bulletproof_t;

typedef struct {
	bulletproof_t *common;
	secp256k1_pedersen_commitment **commit;
	const unsigned char **blind;
	size_t *value;
	//uint64_t *value;
	size_t n_commits;
	size_t nbits;
} bulletproof_rangeproof_t;

//set up for the prove and verify,
//value generators r set
//spaces are malloced
//specify n_proofs=1?numBanks before call this
void bulletproofs_setupmini(bulletproof_t*bpt,int n_proofs) {
	size_t i;
	bpt->n_proofs = n_proofs;
	const unsigned char nonce[32] = "my kingdom for some randomness!";
	const unsigned char genbd[32] = "yet more blinding, for the asse";
	memcpy(bpt->nonce, nonce, 32);
	//malloc enough space for proofs pointer
	bpt->proof = (unsigned char **)malloc(bpt->n_proofs * sizeof(*bpt->proof));
	//malloc enough space for vale generator
	bpt->value_gen = (secp256k1_generator *)malloc(bpt->n_proofs * sizeof(*bpt->value_gen));
	//malloc enough space for every proof
	for (i = 0; i < bpt->n_proofs; i++) {
		bpt->proof[i] = (unsigned char *)malloc(MAX_PROOF_SIZE);
		//check if the generate func works && 
		//generate value generators which are placed in value_gen[i]
		//value generators are r
		CHECK(secp256k1_generator_generate(bpt->ctx, &bpt->value_gen[i], genbd));
	}
	//specify the length of each proof
	bpt->plen = MAX_PROOF_SIZE;
}

//generate some proofs using bprp->value[i] and pu the proofs in bprpt->proofs
//malloc values and sepecify value before call this function
//specify n_commmits before call this
//specify nbits/iters=1 before call this
void bulletproofs_setup(bulletproof_rangeproof_t*bprpt,int n_proofs,int n_commits,int nbits,size_t*value) {
	size_t i;
	size_t v;
	unsigned char blind[32] = "and my kingdom too for a blinde";
	//set the bpt in bprpt, thats **value generators**, **malloc space for proofs** and **nonce init**
	bulletproofs_setupmini(bprpt->common,n_proofs);
	bprpt->n_commits = n_commits;
	bprpt->nbits = nbits;
	bprpt->value = (size_t*)malloc(bprpt->n_commits * sizeof(*bprpt->blind));
	for (int i = 0; i < n_commits; i++) {//may not work TODO
		bprpt->value[i] = value[i];
	}

	//malloc enough space for commits pointers , every proof has several commits
	bprpt->commit = (secp256k1_pedersen_commitment **)malloc(bprpt->common->n_proofs * sizeof(*bprpt->commit));
	//malloc enough space for blind pointer
	bprpt->blind = (const unsigned char **)malloc(bprpt->n_commits * sizeof(*bprpt->blind));
	//malloc enough space for values..........sizeof(pointer)?
	//bprpt->value = (size_t *)malloc(bprpt->n_commits * sizeof(*bprpt->commit));

	//malloc enough space for every commit
	for (i = 0; i < bprpt->common->n_proofs; i++) {
		bprpt->commit[i] = (secp256k1_pedersen_commitment *)malloc(bprpt->n_commits * sizeof(*bprpt->commit[i]));
	}
	//init blind and value
	for (i = 0; i < bprpt->n_commits; i++) {
		//malloc space for blind
		bprpt->blind[i] = (unsigned char*)malloc(32);
		blind[0] = i;
		blind[1] = i >> 8;
		memcpy((unsigned char*)bprpt->blind[i], blind, 32);
		//value TODO
		//bprpt->value[i] = 1;
		//check whether the commit can be produced.
		//given value\blind\valuegen\blindgen\ctx , produce commit which is put in commit[0][i]
		CHECK(secp256k1_pedersen_commit(bprpt->common->ctx, &bprpt->commit[0][i], bprpt->blind[i], bprpt->value[i], &bprpt->common->value_gen[0], &bprpt->common->blind_gen));
	}

	//duplicate commit[0]
	//whats the relationship between n_commit and n_proof?
	for (i = 1; i < bprpt->common->n_proofs; i++) {
		memcpy(bprpt->commit[i], bprpt->commit[0], bprpt->n_commits * sizeof(*bprpt->commit[0]));
	}

	//check wether the prove func works
	//generate proof 0
	CHECK(secp256k1_bulletproof_rangeproof_prove(bprpt->common->ctx, bprpt->common->scratch,
		bprpt->common->generators, bprpt->common->proof[0], &bprpt->common->plen, bprpt->value,
		NULL, bprpt->blind, bprpt->n_commits, bprpt->common->value_gen, bprpt->nbits, bprpt->common->nonce, NULL, 0) == 1);

	//duplicate proof[0]
	for (i = 1; i < bprpt->common->n_proofs; i++) {
		memcpy(bprpt->common->proof[i], bprpt->common->proof[0], bprpt->common->plen);
		//check wether the prove effective
		CHECK(secp256k1_bulletproof_rangeproof_verify(bprpt->common->ctx, bprpt->common->scratch, bprpt->common->generators,
			bprpt->common->proof[i], bprpt->common->plen, NULL, bprpt->commit[i], bprpt->n_commits, bprpt->nbits,
			&bprpt->common->value_gen[0], NULL, 0) == 1);
	}
	//verify proof[0] 
	CHECK(secp256k1_bulletproof_rangeproof_verify(bprpt->common->ctx, bprpt->common->scratch, bprpt->common->generators,
		bprpt->common->proof[0], bprpt->common->plen, NULL, bprpt->commit[0], bprpt->n_commits, bprpt->nbits,
		bprpt->common->value_gen, NULL, 0) == 1);
	//verify multi proofs once
	CHECK(secp256k1_bulletproof_rangeproof_verify_multi(bprpt->common->ctx, bprpt->common->scratch,
		bprpt->common->generators, (const unsigned char **)bprpt->common->proof, bprpt->common->n_proofs,
		bprpt->common->plen, NULL, (const secp256k1_pedersen_commitment **)bprpt->commit, bprpt->n_commits,
		bprpt->nbits, bprpt->common->value_gen, NULL, 0) == 1);
}
void bulletproofs_prove(bulletproof_rangeproof_t*bprpt) {
	size_t i;
	//why 25?
	for (i = 0; i < bprpt->common->n_proofs; i++) {
		//generate proofs
		CHECK(secp256k1_bulletproof_rangeproof_prove(bprpt->common->ctx, bprpt->common->scratch,
			bprpt->common->generators, bprpt->common->proof[i], &bprpt->common->plen, bprpt->value,
			NULL, bprpt->blind, bprpt->n_commits, bprpt->common->value_gen, bprpt->nbits, bprpt->common->nonce,
			NULL, 0) == 1);
	}
}
void bulletproofs_verify(bulletproof_rangeproof_t *bprpt) {
	size_t i;
	//verfify multi
	//iter
	//for (i = 0; i < bprpt->common->iter; i++) {
		CHECK(secp256k1_bulletproof_rangeproof_verify_multi(bprpt->common->ctx,
			bprpt->common->scratch, bprpt->common->generators, (const unsigned char **)bprpt->common->proof,
			bprpt->common->n_proofs, bprpt->common->plen, NULL, (const secp256k1_pedersen_commitment **)bprpt->commit,
			bprpt->n_commits, bprpt->nbits, bprpt->common->value_gen, NULL, 0) == 1);
	//}
}

void bulletproofs_global(bulletproof_t*bpt,int nbits){
	bpt->blind_gen=secp256k1_generator_const_g;
	bpt->ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
	bpt->scratch = secp256k1_scratch_space_create(bpt->ctx, 1024 * 1024 * 1024);
	bpt->generators=secp256k1_bulletproof_generators_create(bpt->ctx,&bpt->blind_gen,nbits*1024);
}
void bulletproofs_transfer(bulletproof_rangeproof_t*bprpt,bulletproof_t*bpt,bulletproof_t*a){
	bprpt->common=bpt;
	bpt->blind_gen=a->blind_gen;
	bpt->ctx=a->ctx;
	bpt->scratch=a->scratch;
	bpt->generators=a->generators;
}


void bulletproofs_teardown(bulletproof_rangeproof_t*bprpt) {
	size_t i;
	if (bprpt->blind != NULL) {
		for (i = 0; i < bprpt->n_commits; i++) {
			free((unsigned char*)bprpt->blind[i]);
		}
	}
	if (bprpt->commit != NULL) {
		for (i = 0; i < bprpt->common->n_proofs; i++) {
			free(bprpt->commit[i]);
		}
		free(bprpt->commit);
	}
	free(bprpt->blind);
	free(bprpt->value);
	size_t j;
	for (j = 0; j < bprpt->common->n_proofs; j++) {
		free(bprpt->common->proof[j]);
	}
	free(bprpt->common->proof);
	free(bprpt->common->value_gen);
}

