package schnorr

import (
	"crypto/sha256"
	"errors"
	"math/big"

	"github.com/btcsuite/btcd/btcec"
)

var (
	tagChallenge = "BIP0340/challenge"
	tagAux       = "BIP0340/aux"
	tagNonce     = "BIP0340/nonce"

	Curve = btcec.S256()
	Zero  = new(big.Int).SetInt64(0)
	One   = new(big.Int).SetInt64(1)
	Three = new(big.Int).SetInt64(3)
	Four  = new(big.Int).SetInt64(4)
	Seven = new(big.Int).SetInt64(7)
)

// Sign signs the given message with the given private key and auxilary data
// as definied in https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki#default-signing
func Sign(privateKey *btcec.PrivateKey, message, aux [32]byte) ([64]byte, error) {
	sig := [64]byte{}

	// Let d' = int(sk)
	// Fail if d'=0 or d'>=n
	d := privateKey.D
	if d.Cmp(Zero) == 0 || d.Cmp(new(big.Int).Sub(Curve.N, One)) > 0 {
		return sig, errors.New("the private key must be an integer in the range 1..n-1")
	}

	// Let P = d'⋅G
	// Let d = d' if has_even_y(P), otherwise let d = n - d'
	P := privateKey.PubKey()
	if !hasEvenY(P) {
		d.Sub(btcec.S256().N, d)
	}

	// Let t be the byte-wise xor of bytes(d) and hashBIP0340/aux(a)
	t, err := fixedXOR(intToByte(d), taggedHash(tagAux, aux[:]))
	if err != nil {
		return sig, err
	}

	// Let rand = hashBIP0340/nonce(t || bytes(P) || m)
	// Let k' = int(rand) mod n
	// Fail if k' = 0
	rand := taggedHash(tagNonce, append(t, append(pointToBytes(P), message[:]...)...))
	k := (&big.Int{}).SetBytes(rand)
	k.Mod(k, btcec.S256().N)
	if k.Cmp(Zero) == 0 {
		return sig, errors.New("private nonce cant be zero")
	}

	// Let R = k'⋅G
	// Let k = k' if has_even_y(R), otherwise let k = n - k'
	_, R := btcec.PrivKeyFromBytes(Curve, k.Bytes())
	if !hasEvenY(R) {
		k.Sub(Curve.N, k)
	}

	// Let e = int(hashBIP0340/challenge(bytes(R) || bytes(P) || m)) mod n
	e := (&big.Int{}).SetBytes(taggedHash(tagChallenge, append(pointToBytes(R), append(pointToBytes(P), message[:]...)...)))

	temp := &big.Int{}
	temp.Mul(e, d)
	temp.Add(temp, k)
	temp.Mod(temp, Curve.N)

	// Let sig = bytes(R) || bytes((k + ed) mod n)
	copy(sig[:32], pointToBytes(R))
	copy(sig[32:], intToByte(temp))

	return sig, nil
}

// Verify checks that the given signature is valid for the public key and message
// as defined in https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki#verification
func Verify(publicKey, message [32]byte, signature [64]byte) (bool, error) {
	// Let P = lift_x(int(pk)); fail if that fails
	P, err := liftX(publicKey)
	if err != nil {
		return false, err
	}

	if P.X == nil || P.Y == nil || !Curve.IsOnCurve(P.X, P.Y) {
		return false, errors.New("signature verification failed")
	}

	// Let r = int(sig[0:32]); fail if r ≥ p
	r := new(big.Int).SetBytes(signature[:32])
	if r.Cmp(Curve.P) >= 0 {
		return false, errors.New("r is larger than or equal to field size")
	}

	// Let s = int(sig[32:64]); fail if s ≥ n
	s := new(big.Int).SetBytes(signature[32:])
	if s.Cmp(Curve.N) >= 0 {
		return false, errors.New("s is larger than or equal to curve order")
	}

	// Let e = int(hashBIP0340/challenge(bytes(r) || bytes(P) || m)) mod n.
	e := getE(intToByte(r), pointToBytes(P), message)

	// Let R = s⋅G - e⋅P
	sGx, sGy := Curve.ScalarBaseMult(intToByte(s))
	ePx, ePy := Curve.ScalarMult(P.X, P.Y, intToByte(e))
	ePy.Sub(Curve.P, ePy)
	Rx, Ry := Curve.Add(sGx, sGy, ePx, ePy)

	if (Rx.Sign() == 0 && Ry.Sign() == 0) || Ry.Bit(0) != 0 || Rx.Cmp(r) != 0 {
		return false, errors.New("signature verification failed")
	}
	return true, nil
}

func getE(R, P []byte, m [32]byte) *big.Int {
	return (&big.Int{}).SetBytes(taggedHash(tagChallenge, append(R, append(P, m[:]...)...)))
}

func hasEvenY(key *btcec.PublicKey) bool {
	return key.Y.Bit(0) == 0
}

func liftX(x [32]byte) (*btcec.PublicKey, error) {
	x0 := new(big.Int).SetBytes(x[:])
	if x0.Cmp(new(big.Int).Sub(Curve.N, One)) > 0 {
		return nil, errors.New("x must be an integer in the range 1..n-1")
	}

	// Let c = (x^3 + 7) mod p
	c := new(big.Int)
	c.Exp(x0, Three, nil)
	c.Add(c, Seven)
	c.Mod(c, Curve.P)

	// Let y = c^((p+1)/4) mod p
	y := new(big.Int)
	y.Add(Curve.P, One)
	y.Div(y, Four)
	y.Exp(c, y, Curve.P)

	// Fail if c ≠ y^2 mod p
	ySqr := new(big.Int).Mul(y, y)
	ySqr.Mod(ySqr, Curve.P)
	if c.Cmp(ySqr) != 0 {
		return nil, errors.New("c != y^2 % p")
	}

	// Return the unique point P such that x(P) = x and y(P) = y
	// if y mod 2 = 0 or y(P) = p-y otherwise
	if y.Bit(0) != 0 {
		y.Sub(Curve.P, y)
	}

	return &btcec.PublicKey{
		Curve: Curve,
		X:     x0,
		Y:     y,
	}, nil
}

func intToByte(i *big.Int) []byte {
	b1 := [32]byte{}
	b2 := i.Bytes()
	copy(b1[32-len(b2):], b2)
	return b1[:]
}

func pointToBytes(P *btcec.PublicKey) []byte {
	return intToByte(P.X)
}

func taggedHash(tag string, data []byte) []byte {
	tagDigest := sha256.New()
	tagDigest.Write([]byte(tag))

	hash := sha256.New()
	hash.Write(tagDigest.Sum(nil))
	hash.Write(tagDigest.Sum(nil))
	hash.Write(data)

	return hash.Sum(nil)
}

func fixedXOR(a []byte, b []byte) ([]byte, error) {
	if len(a) != len(b) {
		return nil, errors.New("byte arrays are of different lengths")
	}

	out := make([]byte, len(a))
	for i := 0; i < len(out); i++ {
		out[i] = a[i] ^ b[i]
	}

	return out, nil
}
