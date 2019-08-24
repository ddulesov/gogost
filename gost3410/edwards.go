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
	"math/big"
)

func (c *Curve) IsEdwards() bool {
	return c.E != nil
}

func (c *Curve) EdwardsST() (*big.Int, *big.Int) {
	if c.edS != nil {
		return c.edS, c.edT
	}
	c.edS = big.NewInt(0)
	c.edS.Set(c.E)
	c.edS.Sub(c.edS, c.D)
	c.pos(c.edS)
	c.t.SetUint64(4)
	c.t.ModInverse(c.t, c.P)
	c.edS.Mul(c.edS, c.t)
	c.edS.Mod(c.edS, c.P)
	c.edT = big.NewInt(0)
	c.edT.Set(c.E)
	c.edT.Add(c.edT, c.D)
	c.t.SetUint64(6)
	c.t.ModInverse(c.t, c.P)
	c.edT.Mul(c.edT, c.t)
	c.edT.Mod(c.edT, c.P)
	return c.edS, c.edT
}

// Convert Weierstrass X,Y coordinates to twisted Edwards U,V
func XY2UV(curve *Curve, x, y *big.Int) (*big.Int, *big.Int) {
	if !curve.IsEdwards() {
		panic("non twisted Edwards curve")
	}
	edS, edT := curve.EdwardsST()
	curve.t.Sub(x, edT)
	curve.pos(curve.t)
	u := big.NewInt(0)
	u.ModInverse(y, curve.P)
	u.Mul(u, curve.t)
	u.Mod(u, curve.P)
	v := big.NewInt(0).Set(curve.t)
	v.Sub(v, edS)
	curve.pos(v)
	curve.t.Add(curve.t, edS)
	curve.t.ModInverse(curve.t, curve.P)
	v.Mul(v, curve.t)
	v.Mod(v, curve.P)
	return u, v
}

// Convert twisted Edwards U,V coordinates to Weierstrass X,Y
func UV2XY(curve *Curve, u, v *big.Int) (*big.Int, *big.Int) {
	if !curve.IsEdwards() {
		panic("non twisted Edwards curve")
	}
	edS, edT := curve.EdwardsST()
	curve.tx.Add(bigInt1, v)
	curve.tx.Mul(curve.tx, edS)
	curve.tx.Mod(curve.tx, curve.P)
	curve.ty.Sub(bigInt1, v)
	curve.pos(curve.ty)
	x := big.NewInt(0)
	x.ModInverse(curve.ty, curve.P)
	x.Mul(x, curve.tx)
	x.Add(x, edT)
	x.Mod(x, curve.P)
	y := big.NewInt(0)
	y.Mul(u, curve.ty)
	y.ModInverse(y, curve.P)
	y.Mul(y, curve.tx)
	y.Mod(y, curve.P)
	return x, y
}
