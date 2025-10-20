package sm3

import (
	"crypto"
	"encoding/binary"
	"hash"
	"math/bits"
)

func init() {
	crypto.RegisterHash(crypto.SM3, New)
}

// The size of the checksum in bytes.
const _sm3_size = 32

// The block size of the hash algorithm in bytes.
const _sm3_block_size = 64

const (
	_sm3_T1	 = 0x79CC4519
	_sm3_T2  = 0x7A879D8A

	_sm3_IVA = 0x7380166f
	_sm3_IVB = 0x4914b2b9
	_sm3_IVC = 0x172442d7
	_sm3_IVD = 0xda8a0600
	_sm3_IVE = 0xa96f30bc
	_sm3_IVF = 0x163138aa
	_sm3_IVG = 0xe38dee4d
	_sm3_IVH = 0xb0fb0e4e
)

type digest struct {
	state [_sm3_size/4]uint32
	count uint64
	buffer [_sm3_block_size]byte
}

func (d *digest) Reset() {
	d.state[0] = _sm3_IVA
	d.state[1] = _sm3_IVB
	d.state[2] = _sm3_IVC
	d.state[3] = _sm3_IVD
	d.state[4] = _sm3_IVE
	d.state[5] = _sm3_IVF
	d.state[6] = _sm3_IVG
	d.state[7] = _sm3_IVH
	d.count = 0
}

// New returns a new hash.Hash computing the checksum.
func New() hash.Hash {
	result := new(digest)
	result.Reset()
	return result
}

func (d *digest) Size() int { return _sm3_size }

func (d *digest) BlockSize() int { return _sm3_block_size }

func p0(x uint32) uint32 {
	return x ^ bits.RotateLeft32(x, 9) ^ bits.RotateLeft32(x, 17)
}

func p1(x uint32) uint32 {
	return x ^ bits.RotateLeft32(x, 15) ^ bits.RotateLeft32(x, 23)
}

func ff(n uint32, a uint32, b uint32, c uint32) uint32 {
	if n < 16 {
		return a ^ b ^ c
	}
	return (a & b) | (a & c) | (b & c)
}

func gg(n uint32, e uint32, f uint32, g uint32) uint32 {
	if n < 16 {
		return e ^ f ^ g
	}
	return (e & f) | ((^e) & g)
}

func t(n uint32) uint32 {
	if n < 16 {
		return _sm3_T1
	}
	return _sm3_T2
}

func sm3_expand(t []byte, w []uint32, wt []uint32) {
	for i := 0; i < 16; i++ {
		w[i] = binary.BigEndian.Uint32(t[i*4:])
	}
	for i := 16; i < 68; i++ {
		tmp := w[i-16] ^ w[i-9] ^ bits.RotateLeft32(w[i-3], 15)
		w[i] = p1(tmp) ^ (bits.RotateLeft32(w[i-13], 7)) ^ w[i-6]
	}
	for i := 0; i < 64; i++ {
		wt[i] = w[i] ^ w[i + 4]
	}
}

func sm3_compress(w []uint32, wt []uint32, m []uint32) {
	a := m[0]
	b := m[1]
	c := m[2]
	d := m[3]
	e := m[4]
	f := m[5]
	g := m[6]
	h := m[7]

	for i := uint32(0); i < 64; i++ {
		ss1 := bits.RotateLeft32((bits.RotateLeft32(a, 12) + e + bits.RotateLeft32(t(i), int(i & 31))), 7)
		ss2 := ss1 ^ bits.RotateLeft32(a, 12)

		tt1 := ff(i, a, b, c) + d + ss2 + wt[i]

		tt2 := gg(i, e, f, g) + h + ss1 + w[i]

		d = c
		c = bits.RotateLeft32(b, 9)
		b = a
		a = tt1
		h = g
		g = bits.RotateLeft32(f, 19)
		f = e
		e = p0(tt2)
	}

	m[0] = a ^ m[0]
	m[1] = b ^ m[1]
	m[2] = c ^ m[2]
	m[3] = d ^ m[3]
	m[4] = e ^ m[4]
	m[5] = f ^ m[5]
	m[6] = g ^ m[6]
	m[7] = h ^ m[7]
}

func sm3_transform(state []uint32, block []byte) {
	var w [68]uint32
	var wt [64]uint32

	sm3_expand(block, w[:], wt[:])
	sm3_compress(w[:], wt[:], state)
}

func (d *digest) Write(p []byte) (int, error) {
	length := uint64(len(p))
	offset := uint64(0)

	partial := d.count % _sm3_block_size
	d.count += length

	if partial + length >= _sm3_block_size {
		if partial > 0 {
			offset = _sm3_block_size - partial

			copy(d.buffer[partial:], p[:offset])

			length -= offset

			sm3_transform(d.state[:], d.buffer[:])

			partial = 0
		}

		blocks := length / _sm3_block_size
		for blocks > 0 {
			sm3_transform(d.state[:], p[offset:])

			offset += _sm3_block_size
			blocks--
		}

		length %= _sm3_block_size
	}

	if length > 0 {
		copy(d.buffer[partial:], p[offset:])
	}

	return len(p), nil
}

func (d0 *digest) Sum(in []byte) []byte {
	// Make a copy of d0 so that caller can keep writing and summing.
	d := *d0

	const count_offset = _sm3_block_size - 8

	var zero [_sm3_block_size]byte

	partial := d.count % _sm3_block_size
	d.buffer[partial] = 0x80
	partial++
	if partial > count_offset {
		copy(d.buffer[partial:], zero[:])

		sm3_transform(d.state[:], d.buffer[:])

		partial = 0
	}

	copy(d.buffer[partial:count_offset], zero[:])

	binary.BigEndian.PutUint64(d.buffer[count_offset:], d.count << 3)

	sm3_transform(d.state[:], d.buffer[:])

	var digest [_sm3_size]byte
	for i, s := range d.state {
		binary.BigEndian.PutUint32(digest[i*4:], s)
	}

	return append(in, digest[:]...)
}
