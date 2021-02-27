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
	"math/big"
	"strconv"
	"testing"
	"time"
)

/*func TestXEqualsRangeStart(t *testing.T) {
    rangeEnd := int64(math.Pow(2, 32))
    x := new(big.Int).SetInt64(0)

    params := setupRange(t, rangeEnd)
    if proveAndVerifyRange(x, params) != true {
        t.Errorf("x equal to range start should verify successfully")
    }
}

func TestXLowerThanRangeStart(t *testing.T) {
    rangeEnd := int64(math.Pow(2, 32))
    x := new(big.Int).SetInt64(-1)

    params := setupRange(t, rangeEnd)
    if proveAndVerifyRange(x, params) == true {
        t.Errorf("x lower than range start should not verify")
    }
}

func TestXHigherThanRangeEnd(t *testing.T) {
    rangeEnd := int64(math.Pow(2, 32))
    x := new(big.Int).SetInt64(rangeEnd + 1)

    params := setupRange(t, rangeEnd)
    if proveAndVerifyRange(x, params) == true {
        t.Errorf("x higher than range end should not verify")
    }
}
*/
/*func TestXEqualToRangeEnd(t *testing.T) {
    rangeEnd := int64(math.Pow(2, 32))
    x := new(big.Int).SetInt64(rangeEnd)

    params := setupRange(t, rangeEnd)
    if proveAndVerifyRange(x, params) == true {
        t.Errorf("x equal to range end should not verify")
    }
}
*/

func TestXWithinRange(t *testing.T) {
	//rangeEnd := int64(real(cmplx.Pow(2, 64)))
	ncommits := 2
	x := make([]*big.Int, ncommits)
	for j := 0; j < ncommits; j++ {
		x[j] = new(big.Int).SetInt64(3)
	}
	params := setupRange(t, int64(32), ncommits)
	if proveAndVerifyRange(x, ncommits, params) != true {
		t.Errorf("x within range should verify successfully")
	}
}

func setupRange(t *testing.T, rangeEnd int64, ncommits int) BulletProofSetupParams {
	params, err := Setup(rangeEnd, ncommits)
	if err != nil {
		t.Errorf("Invalid range end: %s", err)
		t.FailNow()
	}
	return params
}

func proveAndVerifyRange(x []*big.Int, ncommits int, params BulletProofSetupParams) bool {
	var ok bool
	startTime := time.Now().UnixNano()
	proof, _ := Prove(x, ncommits, params)
	endTime := time.Now().UnixNano()
	//seconds:= float64((endTime - startTime) / 1e9)
	Milliseconds := float64(endTime-startTime) / 1e6
	string_Milliseconds := strconv.FormatFloat(Milliseconds, 'f', 6, 64) //float64
	Write(".//test//provetime.txt", string_Milliseconds)

	startTime1 := time.Now().UnixNano()
	ok, _ = proof.Verify(ncommits)
	endTime1 := time.Now().UnixNano()
	//seconds:= float64((endTime - startTime) / 1e9)
	Milliseconds1 := float64(endTime1-startTime1) / 1e6
	string_Milliseconds1 := strconv.FormatFloat(Milliseconds1, 'f', 6, 64) //float64
	Write(".//test//verifytime.txt", string_Milliseconds1)

	return ok
}

//func TestJsonEncodeDecode(t *testing.T) {
//    params, _ := Setup(MAX_RANGE_END)
//    proof, _ := Prove(new(big.Int).SetInt64(18), params)
//    jsonEncoded, err := json.Marshal(proof)
//    if err != nil {
//        t.Fatal("encode error:", err)
//    }
//
//    // network transfer takes place here
//
//    var decodedProof BulletProof
//    err = json.Unmarshal(jsonEncoded, &decodedProof)
//    if err != nil {
//        t.Fatal("decode error:", err)
//    }
//
//    assert.Equal(t, proof, decodedProof, "should be equal")
//
//    ok, err := decodedProof.Verify()
//    if err != nil {
//        t.Fatal("verify error:", err)
//    }
//    assert.True(t, ok, "should verify")
//}
