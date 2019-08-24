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

package gost28147

type CFBEncrypter struct {
	c  *Cipher
	iv []byte
}

func (c *Cipher) NewCFBEncrypter(iv []byte) *CFBEncrypter {
	if len(iv) != BlockSize {
		panic("iv length is not equal to blocksize")
	}
	encrypter := CFBEncrypter{c: c, iv: make([]byte, BlockSize)}
	copy(encrypter.iv, iv)
	return &encrypter
}

func (c *CFBEncrypter) XORKeyStream(dst, src []byte) {
	var n int
	i := 0
MainLoop:
	for {
		c.c.Encrypt(c.iv, c.iv)
		for n = 0; n < BlockSize; n++ {
			if i*BlockSize+n == len(src) {
				break MainLoop
			}
			c.iv[n] ^= src[i*BlockSize+n]
			dst[i*BlockSize+n] = c.iv[n]
		}
		i++
	}
	return
}

type CFBDecrypter struct {
	c  *Cipher
	iv []byte
}

func (c *Cipher) NewCFBDecrypter(iv []byte) *CFBDecrypter {
	if len(iv) != BlockSize {
		panic("iv length is not equal to blocksize")
	}
	decrypter := CFBDecrypter{c: c, iv: make([]byte, BlockSize)}
	copy(decrypter.iv, iv)
	return &decrypter
}

func (c *CFBDecrypter) XORKeyStream(dst, src []byte) {
	var n int
	i := 0
MainLoop:
	for {
		c.c.Encrypt(c.iv, c.iv)
		for n = 0; n < BlockSize; n++ {
			if i*BlockSize+n == len(src) {
				break MainLoop
			}
			dst[i*BlockSize+n] = c.iv[n] ^ src[i*BlockSize+n]
			c.iv[n] = src[i*BlockSize+n]
		}
		i++
	}
	return
}
