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

package mgm

import (
	"crypto/rand"
	"math/big"
	"testing"

	"cypherpunks.ru/gogost/gost3412128"
	"cypherpunks.ru/gogost/gost341264"
)

func BenchmarkMul64(b *testing.B) {
	x := make([]byte, gost341264.BlockSize)
	y := make([]byte, gost341264.BlockSize)
	rand.Read(x)
	rand.Read(y)
	mgm := MGM{
		x:      big.NewInt(0),
		y:      big.NewInt(0),
		z:      big.NewInt(0),
		maxBit: 64 - 1,
		r:      R64,
		mulBuf: make([]byte, gost341264.BlockSize),
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		mgm.mul(x, y)
	}
}

func BenchmarkMul128(b *testing.B) {
	x := make([]byte, gost3412128.BlockSize)
	y := make([]byte, gost3412128.BlockSize)
	rand.Read(x)
	rand.Read(y)
	mgm := MGM{
		x:      big.NewInt(0),
		y:      big.NewInt(0),
		z:      big.NewInt(0),
		maxBit: 128 - 1,
		r:      R128,
		mulBuf: make([]byte, gost3412128.BlockSize),
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		mgm.mul(x, y)
	}
}
