// GoGOST -- Pure Go GOST cryptographic functions library
// Copyright (C) 2015-2019 Sergey Matveev <stargrave@stargrave.org>
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

// Multilinear Galois Mode (MGM) block cipher mode.
package mgm

import (
	"crypto/cipher"
	"crypto/hmac"
	"encoding/binary"
	"errors"
	"math/big"
)

var (
	R64  *big.Int = big.NewInt(0)
	R128 *big.Int = big.NewInt(0)
)

func init() {
	R64.SetBytes([]byte{
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1b,
	})
	R128.SetBytes([]byte{
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x87,
	})
}

type MGM struct {
	maxSize   uint64
	cipher    cipher.Block
	blockSize int
	tagSize   int
	icn       []byte
	bufP      []byte
	bufC      []byte
	padded    []byte
	sum       []byte

	x      *big.Int
	y      *big.Int
	z      *big.Int
	maxBit int
	r      *big.Int
	mulBuf []byte
}

func NewMGM(cipher cipher.Block, tagSize int) (cipher.AEAD, error) {
	blockSize := cipher.BlockSize()
	if !(blockSize == 8 || blockSize == 16) {
		return nil, errors.New("MGM supports only 64/128 blocksizes")
	}
	if tagSize < 4 || tagSize > blockSize {
		return nil, errors.New("invalid tag size")
	}
	mgm := MGM{
		maxSize:   uint64(1<<uint(blockSize*8/2) - 1),
		cipher:    cipher,
		blockSize: blockSize,
		tagSize:   tagSize,
		icn:       make([]byte, blockSize),
		bufP:      make([]byte, blockSize),
		bufC:      make([]byte, blockSize),
		padded:    make([]byte, blockSize),
		sum:       make([]byte, blockSize),
		x:         big.NewInt(0),
		y:         big.NewInt(0),
		z:         big.NewInt(0),
		mulBuf:    make([]byte, blockSize),
	}
	if blockSize == 8 {
		mgm.maxBit = 64 - 1
		mgm.r = R64
	} else {
		mgm.maxBit = 128 - 1
		mgm.r = R128
	}
	return &mgm, nil
}

func (mgm *MGM) NonceSize() int {
	return mgm.blockSize
}

func (mgm *MGM) Overhead() int {
	return mgm.tagSize
}

func incr(data []byte) {
	for i := len(data) - 1; i >= 0; i-- {
		data[i]++
		if data[i] != 0 {
			return
		}
	}
}

func xor(dst, src1, src2 []byte) {
	for i := 0; i < len(src1); i++ {
		dst[i] = src1[i] ^ src2[i]
	}
}

func (mgm *MGM) validateNonce(nonce []byte) {
	if len(nonce) != mgm.blockSize {
		panic("nonce length must be equal to cipher's blocksize")
	}
	if nonce[0]&0x80 > 0 {
		panic("nonce must not have higher bit set")
	}
}

func (mgm *MGM) validateSizes(text, additionalData []byte) {
	if len(text) == 0 && len(additionalData) == 0 {
		panic("at least either *text or additionalData must be provided")
	}
	if uint64(len(additionalData)) > mgm.maxSize {
		panic("additionalData is too big")
	}
	if uint64(len(text)+len(additionalData)) > mgm.maxSize {
		panic("*text with additionalData are too big")
	}
}

func (mgm *MGM) auth(out, text, ad []byte) {
	for i := 0; i < mgm.blockSize; i++ {
		mgm.sum[i] = 0
	}
	adLen := len(ad) * 8
	textLen := len(text) * 8
	mgm.icn[0] |= 0x80
	mgm.cipher.Encrypt(mgm.bufP, mgm.icn) // Z_1 = E_K(1 || ICN)
	for len(ad) >= mgm.blockSize {
		mgm.cipher.Encrypt(mgm.bufC, mgm.bufP) // H_i = E_K(Z_i)
		xor(                                   // sum (xor)= H_i (x) A_i
			mgm.sum,
			mgm.sum,
			mgm.mul(mgm.bufC, ad[:mgm.blockSize]),
		)
		incr(mgm.bufP[:mgm.blockSize/2]) // Z_{i+1} = incr_l(Z_i)
		ad = ad[mgm.blockSize:]
	}
	if len(ad) > 0 {
		copy(mgm.padded, ad)
		for i := len(ad); i < mgm.blockSize; i++ {
			mgm.padded[i] = 0
		}
		mgm.cipher.Encrypt(mgm.bufC, mgm.bufP)
		xor(mgm.sum, mgm.sum, mgm.mul(mgm.bufC, mgm.padded))
		incr(mgm.bufP[:mgm.blockSize/2])
	}

	for len(text) >= mgm.blockSize {
		mgm.cipher.Encrypt(mgm.bufC, mgm.bufP) // H_{h+j} = E_K(Z_{h+j})
		xor(                                   // sum (xor)= H_{h+j} (x) C_j
			mgm.sum,
			mgm.sum,
			mgm.mul(mgm.bufC, text[:mgm.blockSize]),
		)
		incr(mgm.bufP[:mgm.blockSize/2]) // Z_{h+j+1} = incr_l(Z_{h+j})
		text = text[mgm.blockSize:]
	}
	if len(text) > 0 {
		copy(mgm.padded, text)
		for i := len(text); i < mgm.blockSize; i++ {
			mgm.padded[i] = 0
		}
		mgm.cipher.Encrypt(mgm.bufC, mgm.bufP)
		xor(mgm.sum, mgm.sum, mgm.mul(mgm.bufC, mgm.padded))
		incr(mgm.bufP[:mgm.blockSize/2])
	}

	mgm.cipher.Encrypt(mgm.bufP, mgm.bufP) // H_{h+q+1} = E_K(Z_{h+q+1})
	// len(A) || len(C)
	if mgm.blockSize == 8 {
		binary.BigEndian.PutUint32(mgm.bufC, uint32(adLen))
		binary.BigEndian.PutUint32(mgm.bufC[mgm.blockSize/2:], uint32(textLen))
	} else {
		binary.BigEndian.PutUint64(mgm.bufC, uint64(adLen))
		binary.BigEndian.PutUint64(mgm.bufC[mgm.blockSize/2:], uint64(textLen))
	}
	// sum (xor)= H_{h+q+1} (x) (len(A) || len(C))
	xor(mgm.sum, mgm.sum, mgm.mul(mgm.bufP, mgm.bufC))
	mgm.cipher.Encrypt(mgm.bufP, mgm.sum) // E_K(sum)
	copy(out, mgm.bufP[:mgm.tagSize])     // MSB_S(E_K(sum))
}

func (mgm *MGM) crypt(out, in []byte) {
	mgm.icn[0] &= 0x7F
	mgm.cipher.Encrypt(mgm.bufP, mgm.icn) // Y_1 = E_K(0 || ICN)
	for len(in) >= mgm.blockSize {
		mgm.cipher.Encrypt(mgm.bufC, mgm.bufP) // E_K(Y_i)
		xor(out, mgm.bufC, in)                 // C_i = P_i (xor) E_K(Y_i)
		incr(mgm.bufP[mgm.blockSize/2:])       // Y_i = incr_r(Y_{i-1})
		out = out[mgm.blockSize:]
		in = in[mgm.blockSize:]
	}
	if len(in) > 0 {
		mgm.cipher.Encrypt(mgm.bufC, mgm.bufP)
		xor(out, in, mgm.bufC)
	}
}

func (mgm *MGM) Seal(dst, nonce, plaintext, additionalData []byte) []byte {
	mgm.validateNonce(nonce)
	mgm.validateSizes(plaintext, additionalData)
	if uint64(len(plaintext)) > mgm.maxSize {
		panic("plaintext is too big")
	}
	ret, out := sliceForAppend(dst, len(plaintext)+mgm.tagSize)
	copy(mgm.icn, nonce)
	mgm.crypt(out, plaintext)
	mgm.auth(
		out[len(plaintext):len(plaintext)+mgm.tagSize],
		out[:len(plaintext)],
		additionalData,
	)
	return ret
}

func (mgm *MGM) Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	mgm.validateNonce(nonce)
	mgm.validateSizes(ciphertext, additionalData)
	if uint64(len(ciphertext)-mgm.tagSize) > mgm.maxSize {
		panic("ciphertext is too big")
	}
	ret, out := sliceForAppend(dst, len(ciphertext)-mgm.tagSize)
	ct := ciphertext[:len(ciphertext)-mgm.tagSize]
	copy(mgm.icn, nonce)
	mgm.auth(mgm.sum, ct, additionalData)
	if !hmac.Equal(mgm.sum[:mgm.tagSize], ciphertext[len(ciphertext)-mgm.tagSize:]) {
		return nil, errors.New("invalid authentication tag")
	}
	mgm.crypt(out, ct)
	return ret, nil
}
