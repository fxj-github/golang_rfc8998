// Copyright 2015 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// This file contains the Go wrapper for the constant-time, 64-bit assembly
// implementation of SM2. The optimizations performed here are described in
// detail in:
// S.Gueron and V.Krasnov, "Fast prime field elliptic-curve cryptography with
//                          256-bit primes"
// https://link.springer.com/article/10.1007%2Fs13389-014-0090-x
// https://eprint.iacr.org/2013/816.pdf

//go:build amd64 || arm64

package nistec

import (
	_ "embed"
	"encoding/binary"
	"errors"
	"math/bits"
	"runtime"
	"unsafe"
)

// sm2Element is a P-256 base field element in [0, P-1] in the Montgomery
// domain (with R 2²⁵⁶) as four limbs in little-endian order value.
type sm2Element [4]uint64

// sm2One is one in the Montgomery domain.
var sm2One = sm2Element{0x0000000000000001, 0x00000000ffffffff,
	0x0000000000000000, 0x0000000100000000}

var sm2Zero = sm2Element{}

// sm2P is 2²⁵⁶ - 2²²⁴ + 2¹⁹² + 2⁹⁶ - 1 in the Montgomery domain.
var sm2P = sm2Element{0xffffffffffffffff, 0xffffffff00000000,
	0xffffffffffffffff, 0xfffffffeffffffff}

// SM2Point is a P-256 point. The zero value should not be assumed to be valid
// (although it is in this implementation).
type SM2Point struct {
	// (X:Y:Z) are Jacobian coordinates where x = X/Z² and y = Y/Z³. The point
	// at infinity can be represented by any set of coordinates with Z = 0.
	x, y, z sm2Element
}

// NewSM2Point returns a new SM2Point representing the point at infinity.
func NewSM2Point() *SM2Point {
	return &SM2Point{
		x: sm2One, y: sm2One, z: sm2Zero,
	}
}

// SetGenerator sets p to the canonical generator and returns p.
func (p *SM2Point) SetGenerator() *SM2Point {
	p.x = sm2Element{0x61328990f418029e, 0x3e7981eddca6c050,
		0xd6a1ed99ac24c3c3, 0x91167a5ee1c13b05}
	p.y = sm2Element{0xc1354e593c2d0ddd, 0xc1f5e5788d3295fa,
		0x8d4cfb066e2a48f8, 0x63cd65d481d735bd}
	p.z = sm2One
	return p
}

// Set sets p = q and returns p.
func (p *SM2Point) Set(q *SM2Point) *SM2Point {
	p.x, p.y, p.z = q.x, q.y, q.z
	return p
}

const sm2ElementLength = 32
const sm2UncompressedLength = 1 + 2*sm2ElementLength
const sm2CompressedLength = 1 + sm2ElementLength

// SetBytes sets p to the compressed, uncompressed, or infinity value encoded in
// b, as specified in SEC 1, Version 2.0, Section 2.3.4. If the point is not on
// the curve, it returns nil and an error, and the receiver is unchanged.
// Otherwise, it returns p.
func (p *SM2Point) SetBytes(b []byte) (*SM2Point, error) {
	// sm2Mul operates in the Montgomery domain with R = 2²⁵⁶ mod p. Thus rr
	// here is R in the Montgomery domain, or R×R mod p. See comment in
	// SM2OrdInverse about how this is used.
	rr := sm2Element{0x0000000200000003, 0x00000002ffffffff,
		0x0000000100000001, 0x0000000400000002}

	switch {
	// Point at infinity.
	case len(b) == 1 && b[0] == 0:
		return p.Set(NewSM2Point()), nil

	// Uncompressed form.
	case len(b) == sm2UncompressedLength && b[0] == 4:
		var r SM2Point
		sm2BigToLittle(&r.x, (*[32]byte)(b[1:33]))
		sm2BigToLittle(&r.y, (*[32]byte)(b[33:65]))
		if sm2LessThanP(&r.x) == 0 || sm2LessThanP(&r.y) == 0 {
			return nil, errors.New("invalid SM2 element encoding")
		}
		sm2Mul(&r.x, &r.x, &rr)
		sm2Mul(&r.y, &r.y, &rr)
		if err := sm2CheckOnCurve(&r.x, &r.y); err != nil {
			return nil, err
		}
		r.z = sm2One
		return p.Set(&r), nil

	// Compressed form.
	case len(b) == sm2CompressedLength && (b[0] == 2 || b[0] == 3):
		var r SM2Point
		sm2BigToLittle(&r.x, (*[32]byte)(b[1:33]))
		if sm2LessThanP(&r.x) == 0 {
			return nil, errors.New("invalid SM2 element encoding")
		}
		sm2Mul(&r.x, &r.x, &rr)

		// y² = x³ - 3x + b
		sm2Polynomial(&r.y, &r.x)
		if !sm2Sqrt(&r.y, &r.y) {
			return nil, errors.New("invalid SM2 compressed point encoding")
		}

		// Select the positive or negative root, as indicated by the least
		// significant bit, based on the encoding type byte.
		yy := new(sm2Element)
		sm2FromMont(yy, &r.y)
		cond := int(yy[0]&1) ^ int(b[0]&1)
		sm2NegCond(&r.y, cond)

		r.z = sm2One
		return p.Set(&r), nil

	default:
		return nil, errors.New("invalid SM2 point encoding")
	}
}

// sm2Polynomial sets y2 to x³ - 3x + b, and returns y2.
func sm2Polynomial(y2, x *sm2Element) *sm2Element {
	x3 := new(sm2Element)
	sm2Sqr(x3, x, 1)
	sm2Mul(x3, x3, x)

	threeX := new(sm2Element)
	sm2Add(threeX, x, x)
	sm2Add(threeX, threeX, x)
	sm2NegCond(threeX, 1)

	sm2B := &sm2Element{0x90d230632bc0dd42, 0x71cf379ae9b537ab,
		0x527981505ea51c3c, 0x240fe188ba20e2c8}

	sm2Add(x3, x3, threeX)
	sm2Add(x3, x3, sm2B)

	*y2 = *x3
	return y2
}

func sm2CheckOnCurve(x, y *sm2Element) error {
	// y² = x³ - 3x + b
	rhs := sm2Polynomial(new(sm2Element), x)
	lhs := new(sm2Element)
	sm2Sqr(lhs, y, 1)
	if sm2Equal(lhs, rhs) != 1 {
		return errors.New("SM2 point not on curve")
	}
	return nil
}

// sm2LessThanP returns 1 if x < p, and 0 otherwise. Note that a sm2Element is
// not allowed to be equal to or greater than p, so if this function returns 0
// then x is invalid.
func sm2LessThanP(x *sm2Element) int {
	var b uint64
	_, b = bits.Sub64(x[0], sm2P[0], b)
	_, b = bits.Sub64(x[1], sm2P[1], b)
	_, b = bits.Sub64(x[2], sm2P[2], b)
	_, b = bits.Sub64(x[3], sm2P[3], b)
	return int(b)
}

// sm2Add sets res = x + y.
func sm2Add(res, x, y *sm2Element) {
	var c, b uint64
	t1 := make([]uint64, 4)
	t1[0], c = bits.Add64(x[0], y[0], 0)
	t1[1], c = bits.Add64(x[1], y[1], c)
	t1[2], c = bits.Add64(x[2], y[2], c)
	t1[3], c = bits.Add64(x[3], y[3], c)
	t2 := make([]uint64, 4)
	t2[0], b = bits.Sub64(t1[0], sm2P[0], 0)
	t2[1], b = bits.Sub64(t1[1], sm2P[1], b)
	t2[2], b = bits.Sub64(t1[2], sm2P[2], b)
	t2[3], b = bits.Sub64(t1[3], sm2P[3], b)
	// Three options:
	//   - a+b < p
	//     then c is 0, b is 1, and t1 is correct
	//   - p <= a+b < 2^256
	//     then c is 0, b is 0, and t2 is correct
	//   - 2^256 <= a+b
	//     then c is 1, b is 1, and t2 is correct
	t2Mask := (c ^ b) - 1
	res[0] = (t1[0] & ^t2Mask) | (t2[0] & t2Mask)
	res[1] = (t1[1] & ^t2Mask) | (t2[1] & t2Mask)
	res[2] = (t1[2] & ^t2Mask) | (t2[2] & t2Mask)
	res[3] = (t1[3] & ^t2Mask) | (t2[3] & t2Mask)
}

// sm2Sqrt sets e to a square root of x. If x is not a square, sm2Sqrt returns
// false and e is unchanged. e and x can overlap.
func sm2Sqrt(e, x *sm2Element) (isSquare bool) {
	// Since p = 3 mod 4, exponentiation by (p + 1) / 4 yields a square root candidate.
	//
	// https://github.com/mmcloughlin/addchain/blob/master/doc/gen.md
	// addchain search '2^256 - 2^224 - 2^96 + 2^64'|addchain gen
	//
	z := new(sm2Element)
	t0, t1, t2, t3, t4 := new(sm2Element), new(sm2Element), new(sm2Element), new(sm2Element), new(sm2Element)

	sm2Sqr(z, x, 1)
	sm2Mul(z, x, z)
	sm2Sqr(z, z, 1)
	sm2Mul(t0, x, z)
	sm2Sqr(z, t0, 1)
	sm2Mul(z, x, z)
	sm2Sqr(t2, z, 1)
	sm2Sqr(t3, t2, 1)
	sm2Sqr(t1, t3, 1)
	sm2Sqr(t4, t1, 3)
	sm2Mul(t3, t3, t4)
	sm2Sqr(t3, t3, 5)
	sm2Mul(t1, t1, t3)
	sm2Sqr(t3, t1, 2)
	sm2Mul(t2, t2, t3)
	sm2Sqr(t2, t2, 14)
	sm2Mul(t1, t1, t2)
	sm2Mul(t0, t0, t1)
	sm2Sqr(t0, t0, 4)
	sm2Sqr(t1, t0, 31)
	sm2Mul(t0, t0, t1)
	sm2Sqr(t1, t1, 32)
	sm2Mul(t1, t0, t1)
	sm2Sqr(t1, t1, 62)
	sm2Mul(t0, t0, t1)
	sm2Mul(z, z, t0)
	sm2Sqr(z, z, 32)
	sm2Mul(z, x, z)
	sm2Sqr(z, z, 62)

	sm2Sqr(t1, z, 1)
	if sm2Equal(t1, x) != 1 {
		return false
	}
	*e = *z
	return true
}

// The following assembly functions are implemented in sm2_asm_*.s

// Montgomery multiplication. Sets res = in1 * in2 * R⁻¹ mod p.
//
//go:noescape
func sm2Mul(res, in1, in2 *sm2Element)

// Montgomery square, repeated n times (n >= 1).
//
//go:noescape
func sm2Sqr(res, in *sm2Element, n int)

// Montgomery multiplication by R⁻¹, or 1 outside the domain.
// Sets res = in * R⁻¹, bringing res out of the Montgomery domain.
//
//go:noescape
func sm2FromMont(res, in *sm2Element)

// If cond is not 0, sets val = -val mod p.
//
//go:noescape
func sm2NegCond(val *sm2Element, cond int)

// If cond is 0, sets res = b, otherwise sets res = a.
//
//go:noescape
func sm2MovCond(res, a, b *SM2Point, cond int)

//go:noescape
func sm2BigToLittle(res *sm2Element, in *[32]byte)

//go:noescape
func sm2LittleToBig(res *[32]byte, in *sm2Element)

//go:noescape
func sm2OrdBigToLittle(res *sm2OrdElement, in *[32]byte)

//go:noescape
func sm2OrdLittleToBig(res *[32]byte, in *sm2OrdElement)

// sm2Table is a table of the first 16 multiples of a point. Points are stored
// at an index offset of -1 so [8]P is at index 7, P is at 0, and [16]P is at 15.
// [0]P is the point at infinity and it's not stored.
type sm2Table [16]SM2Point

// sm2Select sets res to the point at index idx in the table.
// idx must be in [0, 15]. It executes in constant time.
//
//go:noescape
func sm2Select(res *SM2Point, table *sm2Table, idx int)

// sm2AffinePoint is a point in affine coordinates (x, y). x and y are still
// Montgomery domain elements. The point can't be the point at infinity.
type sm2AffinePoint struct {
	x, y sm2Element
}

// sm2AffineTable is a table of the first 32 multiples of a point. Points are
// stored at an index offset of -1 like in sm2Table, and [0]P is not stored.
type sm2AffineTable [32]sm2AffinePoint

// sm2Precomputed is a series of precomputed multiples of G, the canonical
// generator. The first sm2AffineTable contains multiples of G. The second one
// multiples of [2⁶]G, the third one of [2¹²]G, and so on, where each successive
// table is the previous table doubled six times. Six is the width of the
// sliding window used in sm2ScalarMult, and having each table already
// pre-doubled lets us avoid the doublings between windows entirely. This table
// MUST NOT be modified, as it aliases into sm2PrecomputedEmbed below.
var sm2Precomputed *[43]sm2AffineTable

//go:embed sm2_asm_table.bin
var sm2PrecomputedEmbed string

func sm2_init() {
	sm2PrecomputedPtr := (*unsafe.Pointer)(unsafe.Pointer(&sm2PrecomputedEmbed))
	if runtime.GOARCH == "s390x" {
		var newTable [43 * 32 * 2 * 4]uint64
		for i, x := range (*[43 * 32 * 2 * 4][8]byte)(*sm2PrecomputedPtr) {
			newTable[i] = binary.LittleEndian.Uint64(x[:])
		}
		newTablePtr := unsafe.Pointer(&newTable)
		sm2PrecomputedPtr = &newTablePtr
	}
	sm2Precomputed = (*[43]sm2AffineTable)(*sm2PrecomputedPtr)
}

// sm2SelectAffine sets res to the point at index idx in the table.
// idx must be in [0, 31]. It executes in constant time.
//
//go:noescape
func sm2SelectAffine(res *sm2AffinePoint, table *sm2AffineTable, idx int)

// Point addition with an affine point and constant time conditions.
// If zero is 0, sets res = in2. If sel is 0, sets res = in1.
// If sign is not 0, sets res = in1 + -in2. Otherwise, sets res = in1 + in2
//
//go:noescape
func sm2PointAddAffineAsm(res, in1 *SM2Point, in2 *sm2AffinePoint, sign, sel, zero int)

// Point addition. Sets res = in1 + in2. Returns one if the two input points
// were equal and zero otherwise. If in1 or in2 are the point at infinity, res
// and the return value are undefined.
//
//go:noescape
func sm2PointAddAsm(res, in1, in2 *SM2Point) int

// Point doubling. Sets res = in + in. in can be the point at infinity.
//
//go:noescape
func sm2PointDoubleAsm(res, in *SM2Point)

// sm2OrdElement is a P-256 scalar field element in [0, ord(G)-1] in the
// Montgomery domain (with R 2²⁵⁶) as four uint64 limbs in little-endian order.
type sm2OrdElement [4]uint64

// Add sets q = p1 + p2, and returns q. The points may overlap.
func (q *SM2Point) Add(r1, r2 *SM2Point) *SM2Point {
	var sum, double SM2Point
	r1IsInfinity := r1.isInfinity()
	r2IsInfinity := r2.isInfinity()
	pointsEqual := sm2PointAddAsm(&sum, r1, r2)
	sm2PointDoubleAsm(&double, r1)
	sm2MovCond(&sum, &double, &sum, pointsEqual)
	sm2MovCond(&sum, r1, &sum, r2IsInfinity)
	sm2MovCond(&sum, r2, &sum, r1IsInfinity)
	return q.Set(&sum)
}

// Double sets q = p + p, and returns q. The points may overlap.
func (q *SM2Point) Double(p *SM2Point) *SM2Point {
	var double SM2Point
	sm2PointDoubleAsm(&double, p)
	return q.Set(&double)
}

// ScalarBaseMult sets r = scalar * generator, where scalar is a 32-byte big
// endian value, and returns r. If scalar is not 32 bytes long, ScalarBaseMult
// returns an error and the receiver is unchanged.
func (r *SM2Point) ScalarBaseMult(scalar []byte) (*SM2Point, error) {
	if len(scalar) != 32 {
		return nil, errors.New("invalid scalar length")
	}
	scalarReversed := new(sm2OrdElement)
	sm2OrdBigToLittle(scalarReversed, (*[32]byte)(scalar))

	r.sm2BaseMult(scalarReversed)
	return r, nil
}

// ScalarMult sets r = scalar * q, where scalar is a 32-byte big endian value,
// and returns r. If scalar is not 32 bytes long, ScalarBaseMult returns an
// error and the receiver is unchanged.
func (r *SM2Point) ScalarMult(q *SM2Point, scalar []byte) (*SM2Point, error) {
	if len(scalar) != 32 {
		return nil, errors.New("invalid scalar length")
	}
	scalarReversed := new(sm2OrdElement)
	sm2OrdBigToLittle(scalarReversed, (*[32]byte)(scalar))

	r.Set(q).sm2ScalarMult(scalarReversed)
	return r, nil
}

// sm2Equal returns 1 if a and b are equal and 0 otherwise.
func sm2Equal(a, b *sm2Element) int {
	var acc uint64
	for i := range a {
		acc |= a[i] ^ b[i]
	}
	return uint64IsZero(acc)
}

// isInfinity returns 1 if p is the point at infinity and 0 otherwise.
func (p *SM2Point) isInfinity() int {
	return sm2Equal(&p.z, &sm2Zero)
}

// Bytes returns the uncompressed or infinity encoding of p, as specified in
// SEC 1, Version 2.0, Section 2.3.3. Note that the encoding of the point at
// infinity is shorter than all other encodings.
func (p *SM2Point) Bytes() []byte {
	// This function is outlined to make the allocations inline in the caller
	// rather than happen on the heap.
	var out [sm2UncompressedLength]byte
	return p.bytes(&out)
}

func (p *SM2Point) bytes(out *[sm2UncompressedLength]byte) []byte {
	// The proper representation of the point at infinity is a single zero byte.
	if p.isInfinity() == 1 {
		return append(out[:0], 0)
	}

	x, y := new(sm2Element), new(sm2Element)
	p.affineFromMont(x, y)

	out[0] = 4 // Uncompressed form.
	sm2LittleToBig((*[32]byte)(out[1:33]), x)
	sm2LittleToBig((*[32]byte)(out[33:65]), y)

	return out[:]
}

// affineFromMont sets (x, y) to the affine coordinates of p, converted out of the
// Montgomery domain.
func (p *SM2Point) affineFromMont(x, y *sm2Element) {
	sm2Inverse(y, &p.z)
	sm2Sqr(x, y, 1)
	sm2Mul(y, y, x)

	sm2Mul(x, &p.x, x)
	sm2Mul(y, &p.y, y)

	sm2FromMont(x, x)
	sm2FromMont(y, y)
}

// BytesX returns the encoding of the x-coordinate of p, as specified in SEC 1,
// Version 2.0, Section 2.3.5, or an error if p is the point at infinity.
func (p *SM2Point) BytesX() ([]byte, error) {
	// This function is outlined to make the allocations inline in the caller
	// rather than happen on the heap.
	var out [sm2ElementLength]byte
	return p.bytesX(&out)
}

func (p *SM2Point) bytesX(out *[sm2ElementLength]byte) ([]byte, error) {
	if p.isInfinity() == 1 {
		return nil, errors.New("SM2 point is the point at infinity")
	}

	x := new(sm2Element)
	sm2Inverse(x, &p.z)
	sm2Sqr(x, x, 1)
	sm2Mul(x, &p.x, x)
	sm2FromMont(x, x)
	sm2LittleToBig((*[32]byte)(out[:]), x)

	return out[:], nil
}

// BytesCompressed returns the compressed or infinity encoding of p, as
// specified in SEC 1, Version 2.0, Section 2.3.3. Note that the encoding of the
// point at infinity is shorter than all other encodings.
func (p *SM2Point) BytesCompressed() []byte {
	// This function is outlined to make the allocations inline in the caller
	// rather than happen on the heap.
	var out [sm2CompressedLength]byte
	return p.bytesCompressed(&out)
}

func (p *SM2Point) bytesCompressed(out *[sm2CompressedLength]byte) []byte {
	if p.isInfinity() == 1 {
		return append(out[:0], 0)
	}

	x, y := new(sm2Element), new(sm2Element)
	p.affineFromMont(x, y)

	out[0] = 2 | byte(y[0]&1)
	sm2LittleToBig((*[32]byte)(out[1:33]), x)

	return out[:]
}

// Select sets q to p1 if cond == 1, and to p2 if cond == 0.
func (q *SM2Point) Select(p1, p2 *SM2Point, cond int) *SM2Point {
	sm2MovCond(q, p1, p2, cond)
	return q
}

// sm2Inverse sets out to in⁻¹ mod p. If in is zero, out will be zero.
func sm2Inverse(out, in *sm2Element) {
	// Inversion is calculated through exponentiation by p - 2, per Fermat's
	// little theorem.
	//
	z := new(sm2Element)
	t0, t1, t2 := new(sm2Element), new(sm2Element), new(sm2Element)

	sm2Sqr(z, in, 1)
	sm2Mul(t0, in, z)
	sm2Sqr(z, t0, 1)
	sm2Mul(z, in, z)
	sm2Sqr(t1, z, 3)
	sm2Mul(t1, z, t1)
	sm2Sqr(t2, t1, 1)
	sm2Mul(z, in, t2)
	sm2Sqr(t2, t2, 5)
	sm2Mul(t1, t1, t2)
	sm2Sqr(t2, t1, 12)
	sm2Mul(t1, t1, t2)
	sm2Sqr(t1, t1, 7)
	sm2Mul(z, z, t1)
	sm2Sqr(t2, z, 2)
	sm2Sqr(t1, t2, 29)
	sm2Mul(z, z, t1)
	sm2Sqr(t1, t1, 2)
	sm2Mul(t2, t2, t1)
	sm2Mul(t0, t0, t2)
	sm2Sqr(t1, t1, 32)
	sm2Mul(t1, t0, t1)
	sm2Sqr(t1, t1, 64)
	sm2Mul(t0, t0, t1)
	sm2Sqr(t0, t0, 94)
	sm2Mul(z, z, t0)
	sm2Sqr(z, z, 2)
	sm2Mul(out, in, z)
}

func (p *SM2Point) sm2BaseMult(scalar *sm2OrdElement) {
	var t0 sm2AffinePoint

	wvalue := (scalar[0] << 1) & 0x7f
	sel, sign := boothW6(uint(wvalue))
	sm2SelectAffine(&t0, &sm2Precomputed[0], sel)
	p.x, p.y, p.z = t0.x, t0.y, sm2One
	sm2NegCond(&p.y, sign)

	index := uint(5)
	zero := sel

	for i := 1; i < 43; i++ {
		if index < 192 {
			wvalue = ((scalar[index/64] >> (index % 64)) + (scalar[index/64+1] << (64 - (index % 64)))) & 0x7f
		} else {
			wvalue = (scalar[index/64] >> (index % 64)) & 0x7f
		}
		index += 6
		sel, sign = boothW6(uint(wvalue))
		sm2SelectAffine(&t0, &sm2Precomputed[i], sel)
		sm2PointAddAffineAsm(p, p, &t0, sign, sel, zero)
		zero |= sel
	}

	// If the whole scalar was zero, set to the point at infinity.
	sm2MovCond(p, p, NewSM2Point(), zero)
}

func (p *SM2Point) sm2ScalarMult(scalar *sm2OrdElement) {
	// precomp is a table of precomputed points that stores powers of p
	// from p^1 to p^16.
	var precomp sm2Table
	var t0, t1, t2, t3 SM2Point

	// Prepare the table
	precomp[0] = *p // 1

	sm2PointDoubleAsm(&t0, p)
	sm2PointDoubleAsm(&t1, &t0)
	sm2PointDoubleAsm(&t2, &t1)
	sm2PointDoubleAsm(&t3, &t2)
	precomp[1] = t0  // 2
	precomp[3] = t1  // 4
	precomp[7] = t2  // 8
	precomp[15] = t3 // 16

	sm2PointAddAsm(&t0, &t0, p)
	sm2PointAddAsm(&t1, &t1, p)
	sm2PointAddAsm(&t2, &t2, p)
	precomp[2] = t0 // 3
	precomp[4] = t1 // 5
	precomp[8] = t2 // 9

	sm2PointDoubleAsm(&t0, &t0)
	sm2PointDoubleAsm(&t1, &t1)
	precomp[5] = t0 // 6
	precomp[9] = t1 // 10

	sm2PointAddAsm(&t2, &t0, p)
	sm2PointAddAsm(&t1, &t1, p)
	precomp[6] = t2  // 7
	precomp[10] = t1 // 11

	sm2PointDoubleAsm(&t0, &t0)
	sm2PointDoubleAsm(&t2, &t2)
	precomp[11] = t0 // 12
	precomp[13] = t2 // 14

	sm2PointAddAsm(&t0, &t0, p)
	sm2PointAddAsm(&t2, &t2, p)
	precomp[12] = t0 // 13
	precomp[14] = t2 // 15

	// Start scanning the window from top bit
	index := uint(254)
	var sel, sign int

	wvalue := (scalar[index/64] >> (index % 64)) & 0x3f
	sel, _ = boothW5(uint(wvalue))

	sm2Select(p, &precomp, sel)
	zero := sel

	for index > 4 {
		index -= 5
		sm2PointDoubleAsm(p, p)
		sm2PointDoubleAsm(p, p)
		sm2PointDoubleAsm(p, p)
		sm2PointDoubleAsm(p, p)
		sm2PointDoubleAsm(p, p)

		if index < 192 {
			wvalue = ((scalar[index/64] >> (index % 64)) + (scalar[index/64+1] << (64 - (index % 64)))) & 0x3f
		} else {
			wvalue = (scalar[index/64] >> (index % 64)) & 0x3f
		}

		sel, sign = boothW5(uint(wvalue))

		sm2Select(&t0, &precomp, sel)
		sm2NegCond(&t0.y, sign)
		sm2PointAddAsm(&t1, p, &t0)
		sm2MovCond(&t1, &t1, p, sel)
		sm2MovCond(p, &t1, &t0, zero)
		zero |= sel
	}

	sm2PointDoubleAsm(p, p)
	sm2PointDoubleAsm(p, p)
	sm2PointDoubleAsm(p, p)
	sm2PointDoubleAsm(p, p)
	sm2PointDoubleAsm(p, p)

	wvalue = (scalar[0] << 1) & 0x3f
	sel, sign = boothW5(uint(wvalue))

	sm2Select(&t0, &precomp, sel)
	sm2NegCond(&t0.y, sign)
	sm2PointAddAsm(&t1, p, &t0)
	sm2MovCond(&t1, &t1, p, sel)
	sm2MovCond(p, &t1, &t0, zero)
}
