
package ecdsa

import (
	"crypto"
	"crypto/elliptic"
	_ "crypto/sm3"
	"io"
	"math/big"
)

const (
	sm2_default_id = "1234567812345678"
)

func is_sm2_curve(c elliptic.Curve) bool {
	return c.Params().Name == "SM2"
}

//Za = sm3(ENTL||IDa||a||b||Gx||Gy||Xa||Xy)
func getZById(pub *PublicKey, id []byte) []byte {
	var lena = uint16(len(id) * 8) //bit len of IDA
	var ENTLa = []byte{byte(lena >> 8), byte(lena)}
	var z = make([]byte, 0, 1024)

	//判断公钥x,y坐标长度是否小于32字节，若小于则在前面补0
	xBuf := pub.X.Bytes()
	yBuf := pub.Y.Bytes()

	xPadding := make([]byte, 32)
	yPadding := make([]byte, 32)

	if n := len(xBuf); n < 32 {
		xBuf = append(xPadding[:32-n], xBuf...)
	}

	if n := len(yBuf); n < 32 {
		yBuf = append(yPadding[:32-n], yBuf...)
	}

	z = append(z, ENTLa...)
	z = append(z, id...)
	A, _ := new(big.Int).SetString("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC", 16)
	z = append(z, A.Bytes()...)
	c := pub.Curve
	z = append(z, c.Params().B.Bytes()...)
	z = append(z, c.Params().Gx.Bytes()...)
	z = append(z, c.Params().Gy.Bytes()...)
	z = append(z, xBuf...)
	z = append(z, yBuf...)

	h := crypto.SM3.New()
	h.Write(z)
	return h.Sum(nil)
}

func SM2GenerateDigest(pub *PublicKey, msg []byte, id []byte) []byte {
	h := crypto.SM3.New()
	h.Write(getZById(pub, id))
	h.Write(msg)
	return h.Sum(nil)
}

func sm2Sign(rand io.Reader, priv *PrivateKey, msg []byte, id []byte) (r, s *big.Int, err error) {
	digest := SM2GenerateDigest(&priv.PublicKey, msg, id)
	return SM2SignDigest(rand, priv, digest)
}

func SM2SignDigest(rand io.Reader, priv *PrivateKey, digest []byte) (r, s *big.Int, err error) {
	e := new(big.Int).SetBytes(digest)

	c := priv.PublicKey.Curve
	N := c.Params().N
	if N.Sign() == 0 {
		return nil, nil, errZeroParam
	}

	for {
		var k *big.Int
		for {
			// r = (e + x1) mod n.
			k, _ = randFieldElement(c, rand)
			x1, _ := c.ScalarBaseMult(k.Bytes())
			r = e.Add(e, x1)
			r.Mod(r, N)

			// if r = 0 || r + k = n, continue
			if r.Sign() != 0 {
				x1.Add(r, k)
				if x1.Cmp(N) != 0 {
					break
				}
			}
		}

		// s1 = (k - r * dA) mod n
		s1 := new(big.Int).Mul(r, priv.D)
		s1.Mod(s1, N)
		s1.Sub(k, s1)
		s1.Mod(s1, N)

		// s2 = [ 1 / (1 + dA) ] mod n
		s2 := new(big.Int).Add(one, priv.D)
		s2 = fermatInverse(s2, N)

		// s = (s1 * s2) mod n.
		s = s1.Mul(s1, s2)
		s.Mod(s, N)

		// if s = 0, continue
		if s.Sign() != 0 {
			break
		}
	}

	return
}

// fermatInverse calculates the inverse of k in GF(P) using Fermat's method
// (exponentiation modulo P - 2, per Euler's theorem). This has better
// constant-time properties than Euclid's method (implemented in
// math/big.Int.ModInverse and FIPS 186-4, Appendix C.1) although math/big
// itself isn't strictly constant-time so it's not perfect.
func fermatInverse(k, N *big.Int) *big.Int {
	two := big.NewInt(2)
	nMinus2 := new(big.Int).Sub(N, two)
	return new(big.Int).Exp(k, nMinus2, N)
}

func sm2Verify(pub *PublicKey, msg []byte, id []byte, r, s *big.Int) bool {
	digest := SM2GenerateDigest(pub, msg, id)
	return SM2VerifyDigest(pub, digest, r, s)
}

func SM2VerifyDigest(pub *PublicKey, digest []byte, r, s *big.Int) bool {
	c := pub.Curve
	N := c.Params().N

	if r.Sign() <= 0 || s.Sign() <= 0 {
		return false
	}
	if r.Cmp(N) >= 0 || s.Cmp(N) >= 0 {
		return false
	}

	t := new(big.Int).Add(r, s)
	if t.Sign() == 0 {
		return false
	}

	x11, y11 := c.ScalarMult(pub.X, pub.Y, t.Bytes())
	x12, y12 := c.ScalarBaseMult(s.Bytes())
	x1, _ := c.Add(x11, y11, x12, y12)

	e := new(big.Int).SetBytes(digest)
	e.Add(e, x1)
	e.Mod(e, N)
	return e.Cmp(r) == 0
}

type SM2Options struct {
	ID string

	Hash crypto.Hash
}

func (opts *SM2Options) HashFunc() crypto.Hash {
	return opts.Hash
}

func (opts *SM2Options) getID() string {
	if opts == nil {
		return sm2_default_id
	}
	return opts.ID
}
