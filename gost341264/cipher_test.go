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

package gost341264

import (
	"bytes"
	"crypto/cipher"
	"testing"
)

func TestCipherInterface(t *testing.T) {
	var _ cipher.Block = NewCipher(make([]byte, KeySize))
}

func TestVector(t *testing.T) {
	key := []byte{
		0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88,
		0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00,
		0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7,
		0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff,
	}
	pt := [BlockSize]byte{0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10}
	ct := [BlockSize]byte{0x4e, 0xe9, 0x01, 0xe5, 0xc2, 0xd8, 0xca, 0x3d}
	c := NewCipher(key)
	dst := make([]byte, BlockSize)
	c.Encrypt(dst, pt[:])
	if bytes.Compare(dst, ct[:]) != 0 {
		t.FailNow()
	}
	c.Decrypt(dst, dst)
	if bytes.Compare(dst, pt[:]) != 0 {
		t.FailNow()
	}
}
