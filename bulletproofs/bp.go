/*
 * Copyright (C) 2019 ING BANK N.V.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

package bulletproofs

import (
	"crypto/rand"
	"errors"
	"fmt"
	"log"
	"math/big"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/dcrpalg/crypto/p256"
	"github.com/dcrpalg/util"
	"github.com/dcrpalg/util/bn"
	//"strconv"
)

/*
BulletProofSetupParams is the structure that stores the parameters for
the Zero Knowledge Proof system.
*/
type BulletProofSetupParams struct {
	// N is the bit-length of the range.
	N int64
	// G is the Elliptic Curve generator.
	G *p256.P256
	// H is a new generator, computed using MapToGroup function,
	// such that there is no discrete logarithm relation with G.
	/*H、Gg、Hh使用 MapToGroup函数计算*/
	H *p256.P256
	// Gg and Hh are sets of new generators obtained using MapToGroup.
	// They are used to compute Pedersen Vector Commitments.
	Gg []*p256.P256
	Hh []*p256.P256
	// InnerProductParams is the setup parameters for the inner product proof.
	InnerProductParams InnerProductParams
}

/*
BulletProofs structure contains the elements that are necessary for the verification
of the Zero Knowledge Proof.
*/
type BulletProof struct {
	V                 []*p256.P256
	A                 *p256.P256
	S                 *p256.P256
	T1                *p256.P256
	T2                *p256.P256
	Taux              *big.Int
	Mu                *big.Int
	Tprime            *big.Int
	InnerProductProof InnerProductProof
	Commit            *p256.P256
	Params            BulletProofSetupParams
}

const ncommits_total = 4
const nbit_total = 32

var p2n = make([]*big.Int, 128)
var ynm = make([]*big.Int, 64*512)
var precomputed_Gg [nbit_total * ncommits_total][256]*p256.P256
var precomputed_Hh [nbit_total * ncommits_total][256]*p256.P256

func BitDecompose(x *big.Int) [256]int8 {
	uints := x.Bits()
	var bits [256]int8
	for i := 0; i < 256; i++ {
		bits[0] = 0
	}
	for i := 0; i < 4 && i < len(uints); i++ {
		temp := uints[i]
		for j := 0; j < 64; j++ {

			bits[64*i+j] = int8(temp & 1)
			temp >>= 1

		}
	}
	return bits
}

/*
SetupInnerProduct is responsible for computing the common parameters.
Only works for ranges to 0 to 2^n, where n is a power of 2 and n <= 32
TODO: allow n > 32 (need uint64 for that).
*/
func Setup(b int64, ncommits int) (BulletProofSetupParams, error) {
	var wg sync.WaitGroup
	//if !IsPowerOfTwo(b) {
	//    return BulletProofSetupParams{}, errors.New("range end is not a power of 2")
	//}
	p2n = powerOf(new(big.Int).SetInt64(2), 128)
	params := BulletProofSetupParams{}
	params.G = new(p256.P256).ScalarBaseMult(new(big.Int).SetInt64(1))
	params.H, _ = p256.MapToGroup(SEEDH)
	//params.N = int64(math.Log2(float64(b)))
	params.N = b
	if !IsPowerOfTwo(params.N) {
		return BulletProofSetupParams{}, fmt.Errorf("range end is a power of 2, but it's exponent should also be. Exponent: %d", params.N)
	}

	params.Gg = make([]*p256.P256, params.N*int64((ncommits)))
	params.Hh = make([]*p256.P256, params.N*int64((ncommits)))
	for i := 0; i < int(params.N)*(ncommits); i++ {
		wg.Add(1)
		go func(i int) {
			params.Gg[i], _ = p256.MapToGroup(SEEDH + "g" + string(i))
			params.Hh[i], _ = p256.MapToGroup(SEEDH + "h" + string(i))
			precomputed_Gg[i][0] = params.Gg[i]
			precomputed_Hh[i][0] = params.Hh[i]
			for j := 1; j < 256; j++ {
				precomputed_Gg[i][j] = new(p256.P256).Double(precomputed_Gg[i][j-1])
				precomputed_Hh[i][j] = new(p256.P256).Double(precomputed_Hh[i][j-1])
			}
			wg.Done()
		}(i)
	}
	wg.Wait()
	return params, nil
}

/*
Prove computes the ZK rangeproof. The documentation and comments are based on
eprint version of Bulletproofs papers:
https://eprint.iacr.org/2017/1066.pdf
*/
func Prove(secret []*big.Int, ncommits int, params BulletProofSetupParams) (BulletProof, error) {
	//startTimeAll := time.Now().UnixNano()
	var wg sync.WaitGroup
	var (
		proof BulletProof
	)
	// ////////////////////////////////////////////////////////////////////////////
	/*// First phase: page 19*/
	// ////////////////////////////////////////////////////////////////////////////

	// commitment to v and gamma
	//startTime := time.Now().UnixNano()
	V_aggregate := make([]*p256.P256, ncommits) /*xuxu*/
	gamma_aggregate := make([]*big.Int, ncommits)
	aL_aggregate := make([]int64, int(params.N)*ncommits) /*xuux*/
	for j := 0; j < ncommits; j++ {
		wg.Add(1)
		go func(i int64) {
			gamma_aggregate[i], _ = rand.Int(rand.Reader, ORDER)           //生成承诺的随机值
			V, _ := util.CommitG1(secret[i], gamma_aggregate[i], params.H) /*//生成承诺*/ /*————————————————————————V要改写成向量*/ /*可以并行*/
			V_aggregate[i] = V
			aL, _ := util.Decompose(secret[i], 2, params.N) /*计算aL，将秘密值分解成基底表示形式              (41)*/ /*可以并行*/
			copy(aL_aggregate[int(i)*int(params.N):int(i+1)*int(params.N)], aL)
			wg.Done()
		}(int64(j))
	}
	wg.Wait()
	//for j := 0; j < ncommits; j++ {
	//	wg.Add(1)
	//	V, _ := CommitG1(secret[j], gamma_aggregate[j], params.H) /*//生成承诺*/ /*————————————————————————V要改写成向量*/ /*可以并行*/
	//	V_aggregate[j] = V
	//}
	// aL, aR and commitment: (A, alpha)
	//aL_aggregate := make([]int64, int(params.N)*ncommits) /*xuux*/
	//for j := 0; j < ncommits; j++ {
	//	aL, _ := Decompose(secret[j], 2, params.N) /*计算aL，将秘密值分解成基底表示形式              (41)*/ /*可以并行*/
	//	copy(aL_aggregate[j*int(params.N):(j+1)*int(params.N)], aL)
	//}
	aR, _ := computeAR(aL_aggregate)                                                                     //aR = aL - 1^n，aR与aL互补                // (42)
	alpha, _ := rand.Int(rand.Reader, ORDER)                                                             // (43)
	A := commitVector(aL_aggregate, aR, alpha, params.H, params.Gg, params.Hh, params.N*int64(ncommits)) // (44)

	// sL, sR and commitment: (S, rho)                                     // (45)
	sL := sampleRandomVector(params.N * int64(ncommits))                                        /*扩成n*m维   xuux*/
	sR := sampleRandomVector(params.N * int64(ncommits))                                        /*扩成n*m维   xuxu*/
	rho, _ := rand.Int(rand.Reader, ORDER)                                                      // (46)
	S := commitVectorBig(sL, sR, rho, params.H, params.Gg, params.Hh, params.N*int64(ncommits)) // (47)

	// Fiat-Shamir heuristic to compute challenges y and z, corresponds to    (49)
	y, z, _ := HashBP(A, S)
	log.Printf("y = %d,     z = %d", y, z)

	//计算y^(-n*m),把他传给updateGenerators

	//endTime := time.Now().UnixNano()
	////seconds:= float64((endTime - startTime) / 1e9)
	//Milliseconds := float64(endTime-startTime) / 1e6
	//string_Milliseconds := strconv.FormatFloat(Milliseconds, 'f', 6, 64) //float64
	//log.Printf("#####First phase: %v", string_Milliseconds)
	// ////////////////////////////////////////////////////////////////////////////
	/*// Second phase: page 20*/
	// ////////////////////////////////////////////////////////////////////////////
	//startTime = time.Now().UnixNano()
	tau1, _ := rand.Int(rand.Reader, ORDER) // (52)
	tau2, _ := rand.Int(rand.Reader, ORDER) // (52)

	/*
	   The paper does not describe how to compute t1 and t2.
	*/
	/*// compute t1: < aL - z.1^n, y^n . sR > + < sL, y^n . (aR + z . 1^n)+z^2.2^n >*/
	vz, _ := VectorCopy(z, params.N*int64(ncommits))
	vy := powerOf(y, params.N*int64(ncommits)) /*扩张成n*m维 */

	/*//                                                                                                       aL - z.1^n*/
	naL, _ := VectorConvertToBig(aL_aggregate, params.N*int64(ncommits))
	aLmvz, _ := VectorSub(naL, vz)

	// y^n .sR
	ynsR, _ := VectorMul(vy, sR)

	// scalar prod: < aL - z.1^n, y^n . sR >
	sp1, _ := ScalarProduct(aLmvz, ynsR)

	// scalar prod: < sL, y^n . (aR + z . 1^n) >
	naR, _ := VectorConvertToBig(aR, params.N*int64(ncommits))
	aRzn, _ := VectorAdd(naR, vz)
	ynaRzn, _ := VectorMul(vy, aRzn)

	// Add z^2.2^n to the result
	// z^2 . 2^n
	zsquared_aggregate := make([]*big.Int, ncommits)
	zsquared := z
	for j := 0; j < ncommits; j++ {
		zsquared = bn.Multiply(z, zsquared) /*是否可以优化？？？？？*/
		//zsquared=bn.Mod(zsquared,ORDER)
		zsquared_aggregate[j] = zsquared
	}
	z22n_aggregate := make([]*big.Int, int(params.N)*ncommits)
	for j := 0; j < ncommits; j++ {
		wg.Add(1)
		go func(j int) {
			//p2n := powerOf(new(big.Int).SetInt64(2), params.N)
			z22n, _ := VectorScalarMul(p2n[0:params.N], zsquared_aggregate[j]) /*把z^2乘以2^n替换为z^(1+j)*/
			copy(z22n_aggregate[j*int(params.N):(j+1)*int(params.N)], z22n)
			wg.Done()
		}(j)
	}
	wg.Wait()
	ynaRzn, _ = VectorAdd(ynaRzn, z22n_aggregate)
	sp2, _ := ScalarProduct(sL, ynaRzn)
	// sp1 + sp2
	t1 := bn.Add(sp1, sp2)
	t1 = bn.Mod(t1, ORDER)
	/*// compute t2: < sL, y^n . sR >                                                       */
	t2, _ := ScalarProduct(sL, ynsR)
	t2 = bn.Mod(t2, ORDER)

	// compute T1
	T1, _ := util.CommitG1(t1, tau1, params.H) // (53)

	// compute T2
	T2, _ := util.CommitG1(t2, tau2, params.H) // (53)

	// Fiat-Shamir heuristic to compute 'random' challenge x
	x, _, _ := HashBP(T1, T2)
	//endTime = time.Now().UnixNano()
	////seconds:= float64((endTime - startTime) / 1e9)
	//Milliseconds = float64(endTime-startTime) / 1e6
	//string_Milliseconds = strconv.FormatFloat(Milliseconds, 'f', 6, 64) //float64
	//log.Printf("#####Second phase: %v", string_Milliseconds)
	// ////////////////////////////////////////////////////////////////////////////
	/*    // Third phase                                                              //*/
	// ////////////////////////////////////////////////////////////////////////////
	//thirdstartTime := time.Now().UnixNano()
	/*// compute bl                                                          // (58)                                                  */
	sLx, _ := VectorScalarMul(sL, x)
	bl, _ := VectorAdd(aLmvz, sLx)

	/*// compute br                                                          // (59)                                                  */
	// y^n . ( aR + z.1^n + sR.x )
	sRx, _ := VectorScalarMul(sR, x)
	aRzn, _ = VectorAdd(aRzn, sRx)
	ynaRzn, _ = VectorMul(vy, aRzn)
	// y^n . ( aR + z.1^n sR.x ) + z^2 . 2^n
	br, _ := VectorAdd(ynaRzn, z22n_aggregate)

	/*// Compute t` = < bl, br >                                             // (60)                                                  */
	tprime, _ := ScalarProduct(bl, br)

	/*// Compute taux = tau2 . x^2 + tau1 . x + z^2 . gamma                  // (61)                                                 */
	taux := bn.Multiply(tau2, bn.Multiply(x, x))
	taux = bn.Add(taux, bn.Multiply(tau1, x))
	temp_aggregate := make([]*big.Int, ncommits)
	for j := 0; j < ncommits; j++ { /*并行*/
		//wg.Add(1)
		//go func(j int) {
		temp_aggregate[j] = bn.Multiply(zsquared_aggregate[j], gamma_aggregate[j])
		taux = bn.Add(taux, temp_aggregate[j])
		//wg.Done()
		//}(j)
	}
	//wg.Wait()
	taux = bn.Mod(taux, ORDER)

	// Compute mu = alpha + rho.x                                          // (62)
	mu := bn.Multiply(rho, x)
	mu = bn.Add(mu, alpha)
	mu = bn.Mod(mu, ORDER)

	// Inner Product over (g, h', P.h^-mu, tprime)
	hprime := updateGenerators(params.Hh, y, params.N*int64(ncommits))

	/*// SetupInnerProduct Inner Product (Section 4.2)*/
	var setupErr error
	//startTime = time.Now().UnixNano()
	params.InnerProductParams, setupErr = setupInnerProduct(params.H, params.Gg, hprime, tprime, params.N*int64(ncommits))
	//endTime = time.Now().UnixNano()
	//Milliseconds = float64(endTime-startTime) / 1e6
	//string_Milliseconds = strconv.FormatFloat(Milliseconds, 'f', 6, 64) //float64
	//log.Printf("     setupInnerProduct: %v", string_Milliseconds)
	if setupErr != nil {
		return proof, setupErr
	}
	//startTime = time.Now().UnixNano()
	commit := commitInnerProduct(params.Gg, hprime, bl, br)
	//endTime = time.Now().UnixNano()
	//Milliseconds = float64(endTime-startTime) / 1e6
	//string_Milliseconds = strconv.FormatFloat(Milliseconds, 'f', 6, 64) //float64
	//log.Printf("     commitInnerProduct: %v", string_Milliseconds)

	//startTime = time.Now().UnixNano()
	proofip, _ := proveInnerProduct(bl, br, commit, params.InnerProductParams)

	//endTime = time.Now().UnixNano()
	//Milliseconds = float64(endTime-startTime) / 1e6
	//string_Milliseconds = strconv.FormatFloat(Milliseconds, 'f', 6, 64) //float64
	//log.Printf("     proveInnerProduct: %v", string_Milliseconds)

	proof.V = V_aggregate
	proof.A = A
	proof.S = S
	proof.T1 = T1
	proof.T2 = T2
	proof.Taux = taux
	proof.Mu = mu
	proof.Tprime = tprime
	proof.InnerProductProof = proofip
	proof.Commit = commit
	proof.Params = params

	//endTime = time.Now().UnixNano()
	////seconds:= float64((endTime - startTime) / 1e9)
	//Milliseconds = float64(endTime-thirdstartTime) / 1e6
	//string_Milliseconds = strconv.FormatFloat(Milliseconds, 'f', 6, 64) //float64
	//log.Printf("#####Third phase: %v", string_Milliseconds)
	//endTimeAll := time.Now().UnixNano()
	//Millisecondsall := float64(endTimeAll-startTimeAll) / 1e6
	//string_Millisecondsall := strconv.FormatFloat(Millisecondsall, 'f', 6, 64) //float64
	//log.Printf("####################################provetime phase: %v", string_Millisecondsall)
	return proof, nil
}

/*
Verify returns true if and only if the proof is valid.
*/
func (proof *BulletProof) Verify(ncommits int) (bool, error) {
	var wg sync.WaitGroup
	//starttimeAll := time.Now().UnixNano()
	params := proof.Params
	var result bool

	// Recover x, y, z using Fiat-Shamir heuristic
	x, _, _ := HashBP(proof.T1, proof.T2)
	y, z, _ := HashBP(proof.A, proof.S)
	// ////////////////////////////////////////////////////////////////////////////
	/* // Check that tprime  = t(x) = t0 + t1x + t2x^2  ----------  Condition (65) //*/
	// ////////////////////////////////////////////////////////////////////////////
	startTime := time.Now().UnixNano()
	// Compute left hand side
	lhs, _ := util.CommitG1(proof.Tprime, proof.Taux, params.H)
	// Compute right hand side
	zsquared_aggregate := make([]*big.Int, ncommits+2)
	zsquared := z
	for j := 0; j < ncommits+2; j++ {
		zsquared_aggregate[j] = zsquared
		zsquared = bn.Multiply(z, zsquared)
		zsquared = bn.Mod(zsquared, ORDER)
	}
	//z2 := bn.Multiply(z, z)
	//z2 = bn.Mod(z2, ORDER)
	x2 := bn.Multiply(x, x)
	x2 = bn.Mod(x2, ORDER)

	rhs := make([]*p256.P256, ncommits)
	for j := 0; j < ncommits; j++ {
		wg.Add(1)
		go func(j int) {
			rhs[j] = new(p256.P256).ScalarMult(proof.V[j], zsquared_aggregate[j+1])
			wg.Done()
		}(j)
	}
	wg.Wait()

	length := ncommits
	//gap := length / 2
	for gap := length / 2; gap > 0; gap = length / 2 {
		length = length - gap
		for i := int(0); i < gap; i++ {
			wg.Add(1)
			go func(i int) {
				rhs[i].Add(rhs[i], rhs[length+i])
				wg.Done()
			}(i)
		}
		wg.Wait()
	}
	rhs_aggregate := rhs[0]
	// rhs_aggregate := new(p256.P256).ScalarMult(proof.V[0], zsquared_aggregate[1])
	// for j := 1; j < ncommits; j++ {
	// 	rhs := new(p256.P256).ScalarMult(proof.V[j], zsquared_aggregate[j+1])
	// 	rhs_aggregate.Add(rhs_aggregate, rhs)
	// }

	/*                                                               */
	//rhs :=make([]*p256.P256,ncommits)
	//for j := 1; j < ncommits; j++ {
	//	wg.Add(1)
	//	go func(j int) {
	//		rhs[j] = new(p256.P256).ScalarMult(proof.V[j], zsquared_aggregate[j+1])
	//		//rhs_aggregate.Add(rhs_aggregate, rhs)
	//		wg.Done()
	//	}(j)
	//}
	//for j := 1; j < ncommits; j++ {
	//	wg.Add(1)
	//	go func(j int) {
	//	//rhs := new(p256.P256).ScalarMult(proof.V[j], zsquared_aggregate[j+1])
	//	rhs_aggregate.Add(rhs_aggregate, rhs[j])
	//		wg.Done()
	//	}(j)
	//}
	//wg.Wait()
	vy := powerOf(y, params.N*int64(ncommits))
	delta := params.delta(y, zsquared_aggregate, ncommits, vy) /*计算deta                */
	gdelta := new(p256.P256).ScalarBaseMult(delta)
	rhs_aggregate.Multiply(rhs_aggregate, gdelta)

	T1x := new(p256.P256).ScalarMult(proof.T1, x)
	T2x2 := new(p256.P256).ScalarMult(proof.T2, x2)

	rhs_aggregate.Multiply(rhs_aggregate, T1x)
	rhs_aggregate.Multiply(rhs_aggregate, T2x2)

	// Subtract lhs and rhs and compare with poitn at infinity
	lhs.Neg(lhs)
	rhs_aggregate.Multiply(rhs_aggregate, lhs)
	c65 := rhs_aggregate.IsZero() // Condition (65), page 20, from eprint version

	endTime := time.Now().UnixNano()
	//seconds:= float64((endTime - startTime) / 1e9)
	Milliseconds := float64(endTime-startTime) / 1e6
	string_Milliseconds := strconv.FormatFloat(Milliseconds, 'f', 6, 64) //float64
	log.Printf("计算 c65  %v ", string_Milliseconds)

	/*                                                                                           */
	/* // Compute P - lhs  #################### Condition (66) ######################            */

	startTime = time.Now().UnixNano()
	// S^x
	Sx := new(p256.P256).ScalarMult(proof.S, x)
	// A.S^x
	ASx := new(p256.P256).Add(proof.A, Sx)
	// g^-z
	mz := bn.Sub(ORDER, z)
	//vmz, _ := VectorCopy(mz, params.N*int64(ncommits))
	/*利用precomputed的值计算关于g^-z的点乘                      */
	precomputed_gpmz := make([]*p256.P256, ncommits*int(params.N))
	mzBit := BitDecompose(mz)
	for i := 0; i < ncommits*int(params.N); i++ {
		wg.Add(1)
		go func(i int) {
			precomputed_gpmz[i] = new(p256.P256).SetInfinity()
			for j := 0; j < 256; j++ {
				if mzBit[j] == 1 {
					precomputed_gpmz[i].Multiply(precomputed_gpmz[i], precomputed_Gg[i][j])
				}
			}
			wg.Done()
		}(i)
	}
	wg.Wait()

	length = ncommits * int(params.N)
	//gap := length / 2
	for gap := length / 2; gap > 0; gap = length / 2 {
		length = length - gap
		for i := int(0); i < gap; i++ {
			wg.Add(1)
			go func(i int) {

				precomputed_gpmz[i].Multiply(precomputed_gpmz[i], precomputed_gpmz[length+i])
				wg.Done()
			}(i)
		}
		wg.Wait()
	}
	//for i := 1; i < ncommits*int(params.N); i++ {
	//	precomputed_gpmz[0].Multiply(precomputed_gpmz[0], precomputed_gpmz[i])
	//}
	//gpmz, _ := VectorExp(params.Gg, vmz)
	gpmz := precomputed_gpmz[0]

	endTime = time.Now().UnixNano()
	Milliseconds = float64(endTime-startTime) / 1e6
	string_Milliseconds = strconv.FormatFloat(Milliseconds, 'f', 6, 64) //float64
	log.Printf("计算 c67第一部分  %v ", string_Milliseconds)                  /*log  c67*/

	/*                                                                                          */
	startTime = time.Now().UnixNano()
	/*// z.y^n*m此处y^n*m和y^-nm抵消，直接计算h^z就好*/
	vz, _ := VectorCopy(z, params.N*int64(ncommits)) /*z*/
	//vy := powerOf(y, params.N*int64(ncommits))
	//zyn_aggregate, _ := VectorMul(vy, vz)
	//var z22n_aggregate []*big.Int
	//p2n := powerOf(new(big.Int).SetInt64(2), params.N)
	//z^(j+1).2^n

	/* y^-n*m  */
	yinv := bn.ModInverse(y, ORDER)
	//expyinv := make([]*big.Int, int(params.N)*ncommits)
	expyinv := powerOf(yinv, int64(params.N)*int64(ncommits))
	//expyinv[0] = new(big.Int).SetInt64(1)
	//for i := 1; i < int(params.N)*ncommits; i++ {
	//expyinv[i] = bn.Multiply(expyinv[i-1], yinv)
	//}
	zj2n_aggregate := make([]*big.Int, int(params.N)*ncommits)
	for j := 0; j < ncommits; j++ {
		wg.Add(1)
		go func(j int) {
			z22n, _ := VectorScalarMul(p2n[0:params.N], zsquared_aggregate[j+1]) /*把z^2乘以2^n替换为z^(1+j)*/
			copy(zj2n_aggregate[j*int(params.N):(j+1)*int(params.N)], z22n)
			wg.Done()
		}(j)
	}
	wg.Wait()
	zj2n_aggregate, _ = VectorMul(zj2n_aggregate, expyinv)
	zj2n_aggregate, _ = VectorAdd(zj2n_aggregate, vz)

	lP := new(p256.P256)
	lP.Add(ASx, gpmz)
	// h'^(z.y^n + z^2.2^n)
	/*利用precomputed的值计算h点乘                      */
	precomputed_hprimeexp := make([]*p256.P256, ncommits*int(params.N))
	var zj2n_aggregateBit [ncommits_total * nbit_total][256]int8
	for i := 0; i < ncommits*int(params.N); i++ {
		wg.Add(1)
		go func(i int) {
			zj2n_aggregateBit_temp := BitDecompose(zj2n_aggregate[i])
			for j := 0; j < 256; j++ {
				zj2n_aggregateBit[i][j] = zj2n_aggregateBit_temp[j]
			}
			wg.Done()
		}(i)
	}
	wg.Wait()
	for i := 0; i < ncommits*int(params.N); i++ {
		wg.Add(1)
		go func(i int) {
			precomputed_hprimeexp[i] = new(p256.P256).SetInfinity()
			for j := 0; j < 256; j++ {
				if zj2n_aggregateBit[i][j] == 1 {
					precomputed_hprimeexp[i].Multiply(precomputed_hprimeexp[i], precomputed_Hh[i][j])
				}
			}
			wg.Done()
		}(i)
	}
	wg.Wait()
	length = ncommits * int(params.N)
	//gap := length / 2
	for gap := length / 2; gap > 0; gap = length / 2 {
		length = length - gap
		for i := int(0); i < gap; i++ {
			wg.Add(1)
			go func(i int) {
				precomputed_hprimeexp[i].Multiply(precomputed_hprimeexp[i], precomputed_hprimeexp[length+i])

				wg.Done()
			}(i)
		}
		wg.Wait()
	}
	//for i := 1; i < ncommits*int(params.N); i++ {
	//	precomputed_hprimeexp[0].Multiply(precomputed_hprimeexp[0], precomputed_hprimeexp[i])
	//}
	hprimeexp := precomputed_hprimeexp[0]
	lP.Add(lP, hprimeexp)
	//hprimeexp, _ := VectorExp(params.Hh, zj2n_aggregate)
	/************************************/
	endTime = time.Now().UnixNano()
	Milliseconds = float64(endTime-startTime) / 1e6
	string_Milliseconds = strconv.FormatFloat(Milliseconds, 'f', 6, 64) //float64
	log.Printf("计算 c67第二部分  %v ", string_Milliseconds)
	//log.Println("Compute P - rhs  #################### Condition (67) ######################")
	/*// Compute P - rhs  #################### Condition (67) ######################*/

	// h^mu
	rP := new(p256.P256).ScalarMult(params.H, proof.Mu)
	rP.Multiply(rP, proof.Commit)
	// Subtract lhs and rhs and compare with poitn at infinity
	lP = lP.Neg(lP)
	rP.Add(rP, lP)
	c67 := rP.IsZero()

	/* // Verify Inner Product Proof ################################################*/
	//startTime = time.Now().UnixNano()
	startTime = time.Now().UnixNano()
	ok, _ := proof.InnerProductProof.Verify() /*代价在这里                               */
	endTime = time.Now().UnixNano()
	//seconds:= float64((endTime - startTime) / 1e9)
	Milliseconds = float64(endTime-startTime) / 1e6
	string_Milliseconds = strconv.FormatFloat(Milliseconds, 'f', 6, 64) //float64
	log.Printf("内积证明  %v ", string_Milliseconds)

	log.Println("ok %", ok)
	log.Println("c65 %", c65)
	log.Println("c67 %", c67)
	result = c65 && c67 && ok
	return result, nil
}

/*
SampleRandomVector generates a vector composed by random big numbers.
*/
func sampleRandomVector(N int64) []*big.Int {
	var wg sync.WaitGroup
	s := make([]*big.Int, N)
	for i := int64(0); i < N; i++ {
		wg.Add(1)
		go func(i int64) {
			s[i], _ = rand.Int(rand.Reader, ORDER)
			wg.Done()
		}(i)
	}
	wg.Wait()
	return s
	//s := make([]*big.Int, N)
	//for i := int64(0); i < N; i++ {
	//	s[i], _ = rand.Int(rand.Reader, ORDER)
	//}
	//
	//return s
}

/*
updateGenerators is responsible for computing generators in the following format:
[h_1, h_2^(y^-1), ..., h_n^(y^(-n+1))], where [h_1, h_2, ..., h_n] is the original
vector of generators. This method is used both by prover and verifier. After this
update we have that A is a vector commitments to (aL, aR . y^n). Also S is a vector
commitment to (sL, sR . y^n).
*/
func updateGenerators(Hh []*p256.P256, y *big.Int, N int64) []*p256.P256 {
	/*var (
		i int64
	)*/
	// Compute h'                                                          // (64)
	var wg sync.WaitGroup
	yinv := bn.ModInverse(y, ORDER)
	expy := make([]*big.Int, N)
	expy[0] = new(big.Int).SetInt64(1)
	for i := int64(1); i < N; i++ {
		expy[i] = bn.Multiply(expy[i-1], yinv)
	}
	hprime := make([]*p256.P256, N)
	for i := int64(0); i < N; i++ {
		wg.Add(1)
		go func(i int) {
			hprime[i] = new(p256.P256).ScalarMult(Hh[i], expy[i])
			wg.Done()
		}(int(i))
	}
	wg.Wait()
	return hprime
	//var (
	//	i int64
	//)
	//// Compute h'                                                          // (64)
	//hprime := make([]*p256.P256, N)
	//// Switch generators
	//yinv := bn.ModInverse(y, ORDER)
	//expy := yinv
	//hprime[0] = Hh[0]
	//i = 1
	//for i < N {
	//	hprime[i] = new(p256.P256).ScalarMult(Hh[i], expy)
	//	expy = bn.Multiply(expy, yinv)
	//	i = i + 1
	//}
	//return hprime
}

/*
aR = aL - 1^n
*/
func computeAR(x []int64) ([]int64, error) {
	//var wg sync.WaitGroup
	result := make([]int64, len(x))
	//for i := int64(0); i < int64(len(x)); i++ {
	//	wg.Add(1)
	//	go func(i int) {
	//		if x[i] == 0 {
	//			result[i] = -1
	//		} else if x[i] == 1 {
	//			result[i] = 0
	//		}
	//		//} else {
	//		//	return nil, errors.New("input contains non-binary element")
	//		//}
	//		wg.Done()
	//	}(int(i))
	//}
	//wg.Wait()
	for i := int64(0); i < int64(len(x)); i++ {
		if x[i] == 0 {
			result[i] = -1
		} else if x[i] == 1 {
			result[i] = 0
		} else {
			return nil, errors.New("input contains non-binary element")
		}
	}

	return result, nil
}

func commitVectorBig(aL, aR []*big.Int, alpha *big.Int, H *p256.P256, g, h []*p256.P256, n int64) *p256.P256 {
	// Compute h^alpha.vg^aL.vh^aR
	// Compute h^alpha.vg^aL.vh^aR
	//R := new(p256.P256).ScalarMult(H, alpha)
	var tmp = make([]*p256.P256, 2*n+1)
	tmp[0] = new(p256.P256).ScalarMult(H, alpha)
	var wg sync.WaitGroup
	for i := int64(0); i < n; i++ {
		wg.Add(2)
		go func(i int64) {
			tmp[2*i+1] = new(p256.P256).ScalarMult(g[i], aL[i])
			wg.Done()
		}(i)
		go func(i int64) {
			tmp[2*i+2] = new(p256.P256).ScalarMult(h[i], aR[i])
			wg.Done()
		}(i)
	}
	wg.Wait()
	//TODO
	length := 2*n + 1
	//gap := length / 2

	for gap := length / 2; gap > 0; gap = length / 2 {
		length = length - gap
		for i := int64(0); i < gap; i++ {
			wg.Add(1)
			go func(i int64) {
				tmp[i].Multiply(tmp[i], tmp[i+length])
				wg.Done()
			}(i)
		}
		wg.Wait()
	}
	// for i := int64(0); i < 2*n; i++ {
	// 	tmp[0].Multiply(tmp[0], tmp[i+1])
	// }
	return tmp[0]
}

/*
Commitvector computes a commitment to the bit of the secret.
*/
func commitVector(aL, aR []int64, alpha *big.Int, H *p256.P256, g, h []*p256.P256, n int64) *p256.P256 {
	// Compute h^alpha.vg^aL.vh^aR
	//R := new(p256.P256).ScalarMult(H, alpha)
	//for i := int64(0); i < n; i++ {
	//	gaL := new(p256.P256).ScalarMult(g[i], new(big.Int).SetInt64(aL[i]))
	//	haR := new(p256.P256).ScalarMult(h[i], new(big.Int).SetInt64(aR[i]))
	//	R.Multiply(R, gaL)
	//	R.Multiply(R, haR)
	//}
	//return R
	// Compute h^alpha.vg^aL.vh^aR
	var tmp = make([]*p256.P256, 2*n+1)
	tmp[0] = new(p256.P256).ScalarMult(H, alpha)
	var wg sync.WaitGroup
	for i := int64(0); i < n; i++ {
		wg.Add(2)
		go func(i int64) {
			tmp[2*i+1] = new(p256.P256).ScalarMult(g[i], new(big.Int).SetInt64(aL[i]))
			wg.Done()
		}(i)
		go func(i int64) {
			tmp[2*i+2] = new(p256.P256).ScalarMult(h[i], new(big.Int).SetInt64(aR[i]))
			wg.Done()
		}(i)
	}
	wg.Wait()
	//TODO
	length := 2*n + 1
	//gap := length / 2
	var left int64
	for gap := length / 2; gap > 0; gap = length / 2 {
		left = length - gap
		for i := int64(0); i < gap; i++ {
			wg.Add(1)
			go func(i int64) {
				tmp[i].Multiply(tmp[i], tmp[i+left])
				wg.Done()
			}(i)
		}
		wg.Wait()
		length = left
	}

	return tmp[0]
}

/*
delta(y,z) = (z-z^2) . < 1^n, y^n > - z^3 . < 1^n, 2^n >
*/
func (params *BulletProofSetupParams) delta(y *big.Int, zsquared_aggregate []*big.Int, ncommits int, vy []*big.Int) *big.Int {
	var (
		result *big.Int
	)
	// delta(y,z) = (z-z^2) . < 1^n, y^n > - z^3 . < 1^n, 2^n >
	//z2 := bn.Multiply(zsquared_aggregate[0], z)
	//z2 = bn.Mod(z2, ORDER)
	//z3 := bn.Multiply(z2, z)
	//z3 = bn.Mod(z3, ORDER)

	// < 1^(n*m), y^(n*m) >
	v1_aggregate, _ := VectorCopy(new(big.Int).SetInt64(1), params.N*int64(ncommits))
	//vy := powerOf(y, params.N*int64(ncommits))
	sp1y, _ := ScalarProduct(v1_aggregate, vy)

	// < 1^n, 2^n >
	//v1, _ := VectorCopy(new(big.Int).SetInt64(1), params.N)
	//p2n := powerOf(new(big.Int).SetInt64(2), params.N)
	//sp12=new(big.Int).SetInt64(0)
	sp12 := new(big.Int).SetInt64(1)
	sp12.Lsh(sp12, uint(params.N))
	sp12.Sub(sp12, new(big.Int).SetInt64(1))
	//sp12, _ := ScalarProduct(v1, p2n[0:params.N])
	//for i:=0;i<params.N;i++{
	//	sp12.Add(sp12,p2n[i])
	//}

	result = bn.Sub(zsquared_aggregate[0], zsquared_aggregate[1])
	result = bn.Mod(result, ORDER)
	result = bn.Multiply(result, sp1y)
	result = bn.Mod(result, ORDER)
	for j := 0; j < ncommits; j++ { /*可以并行*/
		result = bn.Sub(result, bn.Multiply(zsquared_aggregate[j+2], sp12))
	}
	result = bn.Mod(result, ORDER)

	return result
}

//xuxu
func Write(filename string, text string) {
	// 要追加的字符串
	str := []byte("\n" + text)

	// 以追加模式打开文件
	txt, err := os.OpenFile(filename, os.O_APPEND, 0666)

	// 以追加模式打开文件，当文件不存在时生成文件
	// txt, err := os.OpenFile(`test.txt`, os.O_APPEND|os.O_CREATE, 0666)

	defer txt.Close()
	if err != nil {
		panic(err)
	}

	// 写入文件
	n, err := txt.Write(str)
	// 当 n != len(b) 时，返回非零错误
	if err == nil && n != len(str) {
		println(`错误代码：`, n)
		panic(err)
	}
}
