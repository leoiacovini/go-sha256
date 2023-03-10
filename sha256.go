package sha256

import (
	"encoding/binary"
	"math/bits"
)

const CHUNK_SIZE_BYTES = 64 // 512-bits

// Initialize array of round constants:
// (first 32 bits of the fractional parts of the cube roots of the first 64 primes 2..311):
var K [64]uint32 = [64]uint32{
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
	0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
	0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
	0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
	0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
	0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
}

func newHash() [8]uint32 {
	return [8]uint32{
		0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
		0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
	}
}

func paddedSize(size int) []byte {
	bs := [8]byte{}
	binary.BigEndian.PutUint64(bs[:], uint64(size))
	return bs[:]
}

func prepareInput(inputBytes []byte) []byte {
	messagesSizeBytes := len(inputBytes)
	const sizeConstantOneBytes = 9

	// append end single `1` bit
	inputBytes = append(inputBytes, 0b10000000)

	// ensure multiple of 512-bits (64 bytes)
	paddingSize := CHUNK_SIZE_BYTES - ((messagesSizeBytes + sizeConstantOneBytes) % CHUNK_SIZE_BYTES)

	// size in bits
	messageSizeBytes := paddedSize(messagesSizeBytes * 8)

	// add padding
	for i := 0; i < paddingSize; i++ {
		inputBytes = append(inputBytes, 0b0)
	}

	// add size in bits at the end
	inputBytes = append(inputBytes, messageSizeBytes...)
	return inputBytes
}

func copyDWord(b []byte) [4]byte {
	newArr := [4]byte{}
	copy(newArr[:], b)
	return newArr
}

func bytesToUint32(w [4]byte) uint32 {
	return binary.BigEndian.Uint32(w[:])
}

func calcS0(w uint32) uint32 {
	p1 := bits.RotateLeft32(w, -7)
	p2 := bits.RotateLeft32(w, -18)
	p3 := (w >> 3)
	return p1 ^ p2 ^ p3
}

func calcS1(w uint32) uint32 {
	p1 := bits.RotateLeft32(w, -17)
	p2 := bits.RotateLeft32(w, -19)
	p3 := w >> 10
	return p1 ^ p2 ^ p3
}

func calcW(n int, messageSchedule [64]uint32) uint32 {
	s0 := calcS0(messageSchedule[n-15])
	s1 := calcS1(messageSchedule[n-2])
	return messageSchedule[n-16] + s0 + messageSchedule[n-7] + s1
}

func newMessageSchedule(chunk []byte) [64]uint32 {
	messageSchedule := [64]uint32{}
	for i := 0; i < 16; i++ {
		messageSchedule[i] = bytesToUint32(copyDWord(chunk[4*i : 4*i+4]))
	}
	for i := 16; i < 64; i++ {
		w := calcW(i, messageSchedule)
		messageSchedule[i] = w
	}
	return messageSchedule
}

func toByteArray(arr []uint32) []byte {
	var bs []byte
	for _, v := range arr {
		bs = binary.BigEndian.AppendUint32(bs, v)
	}
	return bs
}

func compress(currentHash *[8]uint32, schedule [64]uint32) {
	// index mapping aliases
	const a, b, c, d, e, f, g, h = 0, 1, 2, 3, 4, 5, 6, 7
	// Copy to intialize the working set
	var ws [8]uint32 = *currentHash
	for i := 0; i < 64; i++ {
		sm1 := bits.RotateLeft32(ws[e], -6) ^ bits.RotateLeft32(ws[e], -11) ^ bits.RotateLeft32(ws[e], -25)
		sm0 := bits.RotateLeft32(ws[a], -2) ^ bits.RotateLeft32(ws[a], -13) ^ bits.RotateLeft32(ws[a], -22)
		choice := (ws[e] & ws[f]) ^ (^ws[e] & ws[g])
		maj := (ws[a] & ws[b]) ^ (ws[a] & ws[c]) ^ (ws[b] & ws[c])
		temp1 := ws[h] + sm1 + choice + K[i] + schedule[i]
		temp2 := sm0 + maj
		// apply rotations
		for i := 7; i >= 0; i-- {
			if i == a {
				ws[i] = temp1 + temp2
			} else if i == e {
				ws[i] = ws[d] + temp1
			} else {
				ws[i] = ws[i-1]
			}
		}
	}
	// append to current hash
	for i := 0; i < 8; i++ {
		currentHash[i] = currentHash[i] + ws[i]
	}
}

func Hash(bytes []byte) []byte {
	inputBytes := prepareInput(bytes)
	chunks := len(inputBytes) / CHUNK_SIZE_BYTES
	hash := newHash()

	for i := 0; i < chunks; i++ {
		start, end := i*CHUNK_SIZE_BYTES, (i+1)*CHUNK_SIZE_BYTES
		messageSchedule := newMessageSchedule(inputBytes[start:end])
		compress(&hash, messageSchedule)
	}

	return toByteArray(hash[:])
}
