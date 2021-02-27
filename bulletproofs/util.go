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
	"bytes"
	"crypto/sha256"
	"errors"
	"math/big"
	"sync"

	"github.com/dcrpalg/crypto/p256"
	"github.com/dcrpalg/util/bn"
	"github.com/dcrpalg/util/intconversion"
)

/*
powerOf returns a vector composed by powers of x.
*/
func powerOf(x *big.Int, n int64) []*big.Int {
	var (
		i      int64
		result []*big.Int
	)

	result = make([]*big.Int, n)
	current := intconversion.BigFromBase10("1")
	i = 0
	for i < 17 && i < n {
		result[i] = current
		current = bn.Multiply(current, x)
		current = bn.Mod(current, ORDER)
		i = i + 1
	}
	var wg sync.WaitGroup
	for expand := int64(16); expand < n-1; expand = 2 * expand {
		for i := int64(1); i <= expand && i+expand < n; i++ {
			wg.Add(1)
			go func(i int64) {
				result[i+expand] = bn.Multiply(result[i], result[expand])
				result[i+expand] = bn.Mod(result[i+expand], ORDER)
				wg.Done()
			}(i)
		}
		wg.Wait()
	}
	// for j := int64(0); j < n; j++ {
	// 	print("the ", j, " result is ", result[j], " \n ")
	// }
	return result
}

/*
Hash is responsible for the computing a Zp element given elements from GT and G1.
*/
func HashBP(A, S *p256.P256) (*big.Int, *big.Int, error) {

	digest1 := sha256.New()
	var buffer bytes.Buffer
	buffer.WriteString(A.X.String())
	buffer.WriteString(A.Y.String())
	buffer.WriteString(S.X.String())
	buffer.WriteString(S.Y.String())
	digest1.Write(buffer.Bytes())
	output1 := digest1.Sum(nil)
	tmp1 := output1[0:]
	result1 := new(big.Int).SetBytes(tmp1)

	digest2 := sha256.New()
	var buffer2 bytes.Buffer
	buffer2.WriteString(A.X.String())
	buffer2.WriteString(A.Y.String())
	buffer2.WriteString(S.X.String())
	buffer2.WriteString(S.Y.String())
	buffer2.WriteString(result1.String())
	digest2.Write(buffer.Bytes())
	output2 := digest2.Sum(nil)
	tmp2 := output2[0:]
	result2 := new(big.Int).SetBytes(tmp2)

	return result1, result2, nil
}

/*
VectorExp computes Prod_i^n{a[i]^b[i]}.
*/
func VectorExp(a []*p256.P256, b []*big.Int) (*p256.P256, error) {
	var (
		result  []*p256.P256
		i, n, m int64
	)
	var wg sync.WaitGroup
	n = int64(len(a))
	m = int64(len(b))
	if n != m {
		return nil, errors.New("Size of first argument is different from size of second argument.")
	}
	i = 0
	result = make([]*p256.P256, m)

	for i < n {
		wg.Add(1)
		go func(i int64) {
			//result[i] = new(p256.P256).SetInfinity()
			result[i] = new(p256.P256).ScalarMult(a[i], b[i])
			wg.Done()
		}(i)
		i = i + 1
	}
	wg.Wait()
	i = 0
	//TODO
	length := n
	//gap := length / 2
	//var left int64
	for gap := length / 2; gap > 8; gap = length / 2 {
		length = length - gap
		for i := int64(0); i < gap; i++ {
			wg.Add(1)
			go func(i int64) {
				result[i].Multiply(result[i], result[i+length])
				wg.Done()
			}(i)
		}
		wg.Wait()

	}
	for i := int64(1); i < length; i++ {
		result[0].Multiply(result[0], result[i])
	}
	// for i < n-1 {
	// 	result[0].Multiply(result[0], result[i+1])
	// 	i = i + 1
	// }
	return result[0], nil

	/*                                                                                 */
	//var (
	//   result  *p256.P256
	//   i, n, m int64
	//)
	//n = int64(len(a))
	//m = int64(len(b))
	//if n != m {
	//   return nil, errors.New("Size of first argument is different from size of second argument.")
	//}
	//i = 0
	//result = new(p256.P256).SetInfinity()
	//for i < n {
	//   result.Multiply(result, new(p256.P256).ScalarMult(a[i], b[i]))
	//   i = i + 1
	//}
	//return result, nil
}

/*
ScalarProduct return the inner product between a and b.
*/
func ScalarProduct(a, b []*big.Int) (*big.Int, error) {
	var (
		result  []*big.Int
		i, n, m int64
	)
	var wg sync.WaitGroup

	n = int64(len(a))
	m = int64(len(b))
	if n != m {
		return nil, errors.New("Size of first argument is different from size of second argument.")
	}
	i = 0
	result = make([]*big.Int, m)
	//result = intconversion.BigFromBase10("0")
	for i < n {
		wg.Add(1)
		go func(i int64) {
			result[i] = bn.Multiply(a[i], b[i])
			wg.Done()
		}(i)
		i = i + 1
	}
	wg.Wait()
	i = 0
	//TODO
	length := n
	//gap := length / 2

	for gap := length / 2; gap > 8; gap = length / 2 {
		length = length - gap
		for i := int64(0); i < gap; i++ {
			wg.Add(1)
			go func(i int64) {
				result[i].Add(result[i], result[i+length])
				result[i] = bn.Mod(result[i], ORDER)
				wg.Done()
			}(i)
		}
		wg.Wait()

	}
	for i := int64(1); i < length; i++ {
		result[0].Add(result[0], result[i])
		result[i] = bn.Mod(result[i], ORDER)
	}

	// for i < n-1 {
	// 	result[0].Add(result[0], result[i+1])
	// 	result[0] = bn.Mod(result[0], ORDER)
	// 	i = i + 1
	// }
	return result[0], nil
}

/*
IsPowerOfTwo returns true for arguments that are a power of 2, false otherwise.
https://stackoverflow.com/a/600306/844313
*/
func IsPowerOfTwo(x int64) bool {
	return (x != 0) && ((x & (x - 1)) == 0)
}
