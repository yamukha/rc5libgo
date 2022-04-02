// rc5-32/12/16  w/r/b
package rc5libgo

import (
	"encoding/binary"
	"math"
	"math/bits"
)

const (
	W32 = 32         // machine word as half of block
	R12 = 12         // rounds, if zero no encoding
	P32 = 0xb7e15163 // magic nunber P for w =32 as Pw = Odd((f - 1) * 2^W;
	Q32 = 0x9e3779b9 // magic number Q for W =32 as Qw = Odd((e - 2) * 2^W;
)

//#define ROTL(x,y) (((x)<<(y&(w-1))) | ((x)>>(w-(y&(w-1)))))
func rotl(a uint32, w uint32, offset uint32) uint32 {
	r1 := bits.RotateLeft(uint(a), int(offset))        //r1 := a << uint8 (offset);
	r2 := bits.RotateLeft(uint(a), int(-(w - offset))) //r2 := a >> uint8 (w - offset);
	return uint32(r1) | uint32(r2)
}

//#define ROTR(x,y) (((x)>>(y&(w-1))) | ((x)<<(w-(y&(w-1)))))
func rotr(a uint32, w uint32, offset uint32) uint32 {
	r1 := bits.RotateLeft(uint(a), int(-offset))  //  r1 := a >> offset;
	r2 := bits.RotateLeft(uint(a), int(w-offset)) // r2 := a << (w - offset);
	return uint32(r1) | uint32(r2)
}

func aligne_key(key []byte, w uint32) []uint32 {
	b := uint32(len(key) - 1)
	u := w >> 3
	i := int32(len(key) - 1)

	var c uint32
	if b%u > 0 {
		c = b/u + 1
	} else {
		c = b / u
	} // c = b % u > 0 ? b / u + 1 : b / u;

	l := make([]uint32, c)

	//for (i = b - 1; i >= 0; i--)
	for i >= 0 {
		l[uint32(i)/u] = rotl(l[uint32(i)/u], w, 8) + uint32(key[i]) //  L [i / u] = ROL(L[i / u], 8) + key[i];
		i--
	}

	return l
}

// Initializing sub-key S.
func sub_keys(p uint32, q uint32, r uint32) []uint32 {
	t := 2 * (r + 1)
	s := make([]uint32, t)

	s[0] = p
	//for (i = 1; i < t; i++)
	for i := uint32(1); i < t; i++ {
		s[i] = s[(i-1)] + q
	}
	return s
}

// Sub-key mixing.
func sub_keys_mix(key []uint8, l []uint32, s []uint32, r uint32, w uint32) []uint32 {
	x := uint32(0)
	y := uint32(0)
	j := uint32(0)
	i := uint32(0)
	b := uint32(len(key) - 1)
	u := w >> 3

	var c uint32
	if b%u > 0 {
		c = b/u + 1
	} else {
		c = b / u
	} // c = b % u > 0 ? b / u + 1 : b / u;

	t := 2 * (r + 1)
	n := 3 * uint32(math.Max(float64(t), float64(c))) // n = 3 * Math.Max(t, c);
	// for (int k = 0; k < n; k++)
	for k := uint32(0); k < n; k++ {
		s[i] = rotl(s[i]+x+y, w, 3)
		x = s[i]
		l[j] = rotl(l[j]+x+y, w, x+y)
		y = l[j]
		i = (i + 1) % t
		j = (j + 1) % c
	}
	return s
}

func bytes2u32(d []uint8) uint32 {
	return uint32(d[0]) + uint32(d[1])*256 + uint32(d[2])*256*256 + uint32(d[3])*256*256*256
}

func u32vec(d uint32) []uint8 {
	v := make([]uint8, 4)
	binary.LittleEndian.PutUint32(v, uint32(d))
	return v
}

func Encode(key []uint8, plaintext []uint8, r uint32, w uint32, p uint32, q uint32) []uint8 {
	c := len(plaintext) / 2
	pt := plaintext
	av := pt[0:c]
	bv := pt[c:len(pt)]
	a := bytes2u32(av)
	b := bytes2u32(bv)

	ak := aligne_key(key, w)
	sk := sub_keys(p, q, r)
	s := sub_keys_mix(key, ak, sk, r, w)
	a = a + s[0]
	b = b + s[1]

	for i := uint32(1); i < r+1; i++ {
		a = rotl(a^b, w, b) + s[2*i]
		b = rotl(b^a, w, a) + s[2*i+1]
	}

	ciphertext := make([]uint8, 0)

	ca := make([]uint8, 0)
	ca = u32vec(a)
	cb := make([]uint8, 0)
	cb = u32vec(b)

	ciphertext = append(ca, cb...)
	return ciphertext
}

func Decode(key []uint8, plaintext []uint8, r uint32, w uint32, p uint32, q uint32) []uint8 {
	c := len(plaintext) / 2
	pt := plaintext
	av := pt[0:c]
	bv := pt[c:len(pt)]
	a := bytes2u32(av)
	b := bytes2u32(bv)

	ak := aligne_key(key, w)
	sk := sub_keys(p, q, r)
	s := sub_keys_mix(key, ak, sk, r, w)

	i := r
	//for (int i = R; i > 0; i--) {
	for i > 0 {
		b = rotr(b-s[2*i+1], w, a) ^ a
		a = rotr(a-s[2*i], w, b) ^ b
		i = i - 1
	}

	b = b - s[1]
	a = a - s[0]

	ciphertext := make([]uint8, 0)

	ca := make([]uint8, 0)
	ca = u32vec(a)
	cb := make([]uint8, 0)
	cb = u32vec(b)

	ciphertext = append(ca, cb...)
	return ciphertext
}
