package ourproof

import (
	"crypto/rand"
	"math/big"
	"testing"
)

func TestDisjunctive(t *testing.T) {

	x := big.NewInt(100)
	y := big.NewInt(101)

	Base1 := TestCurve.G
	Result1 := TestCurve.Mult(TestCurve.G, x)
	Base2 := TestCurve.H
	Result2 := TestCurve.Mult(TestCurve.H, y)

	djProofLEFT, status1 := NewDisjunctiveProof(TestCurve, Base1, Result1, Base2, Result2, x, Left)

	if status1 != nil {
		proofStatus(status1.(*errorProof))
		t.Fatalf("TestDisjunctive - incorrect error message for correct proof, case 1\n")
	}

	djProofRIGHT, status2 := NewDisjunctiveProof(TestCurve, Base1, Result1, Base2, Result2, y, Right)

	if status2 != nil {
		proofStatus(status2.(*errorProof))
		t.Fatalf("TestDisjunctive - incorrect error message for correct proof, case 2\n")
	}

	t.Logf("Testing DisjunctiveProof:\n")
	t.Logf("First djProof : ")
	check, err := djProofLEFT.Verify(TestCurve, Base1, Result1, Base2, Result2)
	if !check || err != nil {
		t.Fatalf("djProof failed to generate properly for left side\n")
	}

	t.Logf("Passed \n [testing] Second djProof : ")
	check, err = djProofRIGHT.Verify(TestCurve, Base1, Result1, Base2, Result2)
	if !check || err != nil {
		t.Fatalf("djProof failed to generate properly for right side\n")
	}

	t.Logf("Passed \n [testing] Next djProof attempt should result in an error message\n")
	_, status3 := NewDisjunctiveProof(TestCurve, Base1, Result1, Base2, Result2, y, Left) // This should fail

	if status3 == nil {
		t.Fatalf("TestDisjunctive - incorrect error message for incorrect proof, case 3\n")
	}

}

func TestDisjuncSerialization(t *testing.T) {
	value, _ := rand.Int(rand.Reader, TestCurve.C.Params().N)
	randVal, _ := rand.Int(rand.Reader, TestCurve.C.Params().N)
	Base1 := TestCurve.G
	Result1 := TestCurve.Mult(Base1, value)
	Base2 := TestCurve.H
	Result2 := TestCurve.Mult(Base2, randVal)
	proof, _ := NewDisjunctiveProof(TestCurve, Base1, Result1, Base2, Result2, value, Left)
	proof, err := NewDisjunctiveProofFromBytes(proof.Bytes())
	if err != nil {
		t.Fatalf("TestDisjuncSerialization failed to deserialize\n")
	}
	ok, err := proof.Verify(TestCurve, Base1, Result1, Base2, Result2)
	if !ok || err != nil {
		t.Fatalf("TestDisjuncSerialization failed to verify\n")
	}

}

func BenchmarkDisjuncProve_LEFT(b *testing.B) {
	value, _ := rand.Int(rand.Reader, TestCurve.C.Params().N)
	randVal, _ := rand.Int(rand.Reader, TestCurve.C.Params().N)
	Base1 := TestCurve.G
	Result1 := TestCurve.Mult(Base1, value)
	Base2 := TestCurve.H
	Result2 := TestCurve.Mult(Base2, randVal)
	b.ResetTimer()
	for ii := 0; ii < b.N; ii++ {
		NewDisjunctiveProof(TestCurve, Base1, Result1, Base2, Result2, value, Left)
	}
}

func BenchmarkDisjuncProve_RIGHT(b *testing.B) {
	value, _ := rand.Int(rand.Reader, TestCurve.C.Params().N)
	randVal, _ := rand.Int(rand.Reader, TestCurve.C.Params().N)
	Base1 := TestCurve.G
	Result1 := TestCurve.Mult(Base1, value)
	Base2 := TestCurve.H
	Result2 := TestCurve.Mult(Base2, randVal)
	b.ResetTimer()
	for ii := 0; ii < b.N; ii++ {
		NewDisjunctiveProof(TestCurve, Base1, Result1, Base2, Result2, randVal, Right)
	}
}

func BenchmarkDisjuncVerify_LEFT(b *testing.B) {
	value, _ := rand.Int(rand.Reader, TestCurve.C.Params().N)
	randVal, _ := rand.Int(rand.Reader, TestCurve.C.Params().N)
	Base1 := TestCurve.G
	Result1 := TestCurve.Mult(Base1, value)
	Base2 := TestCurve.H
	Result2 := TestCurve.Mult(Base2, randVal)
	proof, _ := NewDisjunctiveProof(TestCurve, Base1, Result1, Base2, Result2, value, Left)
	b.ResetTimer()
	for ii := 0; ii < b.N; ii++ {
		proof.Verify(TestCurve, Base1, Result1, Base2, Result2)
	}
}

func BenchmarkDisjuncVerify_RIGHT(b *testing.B) {
	value, _ := rand.Int(rand.Reader, TestCurve.C.Params().N)
	randVal, _ := rand.Int(rand.Reader, TestCurve.C.Params().N)
	Base1 := TestCurve.G
	Result1 := TestCurve.Mult(Base1, value)
	Base2 := TestCurve.H
	Result2 := TestCurve.Mult(Base2, randVal)
	proof, _ := NewDisjunctiveProof(TestCurve, Base1, Result1, Base2, Result2, randVal, Right)
	b.ResetTimer()
	for ii := 0; ii < b.N; ii++ {
		proof.Verify(TestCurve, Base1, Result1, Base2, Result2)
	}
}
