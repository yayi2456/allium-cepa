package rangeproof

//#include "bullet_impl.h"
import "C"

//import "unsafe"

type Bulletproofs_t struct {
	bpt C.bulletproof_t
}

type Bulletproofs_rangeproof_t struct {
	bprpt C.bulletproof_rangeproof_t
}

var BptParam Bulletproofs_t

func Global_setup(nbits int) {
	nb := C.int(nbits)
	C.bulletproofs_global(&(BptParam.bpt), nb)
}
func Make_Transfer(datarp *Bulletproofs_rangeproof_t, data *Bulletproofs_t) {
	C.bulletproofs_transfer(&(datarp.bprpt), &(data.bpt), &(BptParam.bpt))
}

func Make_setup(data *Bulletproofs_rangeproof_t, nproofs int, nbits int, ncommits int, value []uint64) {
	np := C.int(nproofs)
	//nb := C.int(nbits)
	nb := C.int(32)
	nc := C.int(ncommits)
	nv := (*C.uint64_t)(&value[0])
	C.bulletproofs_setup(&(data.bprpt), np, nb, nc, nv)
}

func Make_prove(data *Bulletproofs_rangeproof_t) {
	C.bulletproofs_prove(&(data.bprpt))
}

func Make_verify(data *Bulletproofs_rangeproof_t) {
	C.bulletproofs_verify(&(data.bprpt))
}
