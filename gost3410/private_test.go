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

package gost3410

import (
	"crypto"
	"crypto/rand"
	"testing"
)

func TestSignerInterface(t *testing.T) {
	prvRaw := make([]byte, int(Mode2001))
	rand.Read(prvRaw)
	prv, err := NewPrivateKey(CurveIdGostR34102001TestParamSet(), Mode2001, prvRaw)
	if err != nil {
		t.FailNow()
	}
	var _ crypto.Signer = prv
}
