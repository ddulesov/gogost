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
	"errors"
	"io"
	"math/big"
)

type PrivateKey struct {
	C    *Curve
	Mode Mode
	Key  *big.Int
}

func NewPrivateKey(curve *Curve, mode Mode, raw []byte) (*PrivateKey, error) {
	if len(raw) != int(mode) {
		return nil, errors.New("Invalid private key length")
	}
	key := make([]byte, int(mode))
	for i := 0; i < len(key); i++ {
		key[i] = raw[len(raw)-i-1]
	}
	k := bytes2big(key)
	if k.Cmp(zero) == 0 {
		return nil, errors.New("Zero private key")
	}
	return &PrivateKey{curve, mode, k}, nil
}

func GenPrivateKey(curve *Curve, mode Mode, rand io.Reader) (*PrivateKey, error) {
	raw := make([]byte, int(mode))
	if _, err := io.ReadFull(rand, raw); err != nil {
		return nil, err
	}
	return NewPrivateKey(curve, mode, raw)
}

func (prv *PrivateKey) Raw() []byte {
	raw := pad(prv.Key.Bytes(), int(prv.Mode))
	reverse(raw)
	return raw
}

func (prv *PrivateKey) PublicKey() (*PublicKey, error) {
	x, y, err := prv.C.Exp(prv.Key, prv.C.X, prv.C.Y)
	if err != nil {
		return nil, err
	}
	return &PublicKey{prv.C, prv.Mode, x, y}, nil
}

func (prv *PrivateKey) SignDigest(digest []byte, rand io.Reader) ([]byte, error) {
	e := bytes2big(digest)
	e.Mod(e, prv.C.Q)
	if e.Cmp(zero) == 0 {
		e = big.NewInt(1)
	}
	kRaw := make([]byte, int(prv.Mode))
	var err error
	var k *big.Int
	var r *big.Int
	d := big.NewInt(0)
	s := big.NewInt(0)
Retry:
	if _, err = io.ReadFull(rand, kRaw); err != nil {
		return nil, err
	}
	k = bytes2big(kRaw)
	k.Mod(k, prv.C.Q)
	if k.Cmp(zero) == 0 {
		goto Retry
	}
	r, _, err = prv.C.Exp(k, prv.C.X, prv.C.Y)
	if err != nil {
		return nil, err
	}
	r.Mod(r, prv.C.Q)
	if r.Cmp(zero) == 0 {
		goto Retry
	}
	d.Mul(prv.Key, r)
	k.Mul(k, e)
	s.Add(d, k)
	s.Mod(s, prv.C.Q)
	if s.Cmp(zero) == 0 {
		goto Retry
	}
	return append(
		pad(s.Bytes(), int(prv.Mode)),
		pad(r.Bytes(), int(prv.Mode))...,
	), nil
}

func (prv *PrivateKey) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	return prv.SignDigest(digest, rand)
}

func (prv *PrivateKey) Public() crypto.PublicKey {
	pub, err := prv.PublicKey()
	if err != nil {
		panic(err)
	}
	return pub
}
