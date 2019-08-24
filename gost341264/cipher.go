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

// GOST 34.12-2015 64-bit (Магма (Magma)) block cipher.
package gost341264

import (
	"cypherpunks.ru/gogost/gost28147"
)

const (
	BlockSize = 8
	KeySize   = 32
)

type Cipher struct {
	c   *gost28147.Cipher
	blk *[BlockSize]byte
}

func NewCipher(key []byte) *Cipher {
	if len(key) != KeySize {
		panic("invalid key size")
	}
	keyCompatible := make([]byte, KeySize)
	for i := 0; i < KeySize/4; i++ {
		keyCompatible[i*4+0] = key[i*4+3]
		keyCompatible[i*4+1] = key[i*4+2]
		keyCompatible[i*4+2] = key[i*4+1]
		keyCompatible[i*4+3] = key[i*4+0]
	}
	return &Cipher{
		c:   gost28147.NewCipher(keyCompatible, &gost28147.SboxIdtc26gost28147paramZ),
		blk: new([BlockSize]byte),
	}
}

func (c *Cipher) BlockSize() int {
	return BlockSize
}

func (c *Cipher) Encrypt(dst, src []byte) {
	c.blk[0] = src[7]
	c.blk[1] = src[6]
	c.blk[2] = src[5]
	c.blk[3] = src[4]
	c.blk[4] = src[3]
	c.blk[5] = src[2]
	c.blk[6] = src[1]
	c.blk[7] = src[0]
	c.c.Encrypt(c.blk[:], c.blk[:])
	dst[0] = c.blk[7]
	dst[1] = c.blk[6]
	dst[2] = c.blk[5]
	dst[3] = c.blk[4]
	dst[4] = c.blk[3]
	dst[5] = c.blk[2]
	dst[6] = c.blk[1]
	dst[7] = c.blk[0]
}

func (c *Cipher) Decrypt(dst, src []byte) {
	c.blk[0] = src[7]
	c.blk[1] = src[6]
	c.blk[2] = src[5]
	c.blk[3] = src[4]
	c.blk[4] = src[3]
	c.blk[5] = src[2]
	c.blk[6] = src[1]
	c.blk[7] = src[0]
	c.c.Decrypt(c.blk[:], c.blk[:])
	dst[0] = c.blk[7]
	dst[1] = c.blk[6]
	dst[2] = c.blk[5]
	dst[3] = c.blk[4]
	dst[4] = c.blk[3]
	dst[5] = c.blk[2]
	dst[6] = c.blk[1]
	dst[7] = c.blk[0]
}
