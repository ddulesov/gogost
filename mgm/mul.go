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

func (mgm *MGM) mul(xBuf, yBuf []byte) []byte {
	mgm.x.SetBytes(xBuf)
	mgm.y.SetBytes(yBuf)
	mgm.z.SetInt64(0)
	var i int
	for mgm.y.BitLen() != 0 {
		if mgm.y.Bit(0) == 1 {
			mgm.z.Xor(mgm.z, mgm.x)
		}
		if mgm.x.Bit(mgm.maxBit) == 1 {
			mgm.x.SetBit(mgm.x, mgm.maxBit, 0)
			mgm.x.Lsh(mgm.x, 1)
			mgm.x.Xor(mgm.x, mgm.r)
		} else {
			mgm.x.Lsh(mgm.x, 1)
		}
		mgm.y.Rsh(mgm.y, 1)
	}
	zBytes := mgm.z.Bytes()
	rem := len(xBuf) - len(zBytes)
	for i = 0; i < rem; i++ {
		mgm.mulBuf[i] = 0
	}
	copy(mgm.mulBuf[rem:], zBytes)
	return mgm.mulBuf
}
