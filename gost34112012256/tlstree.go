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

package gost34112012256

import (
	"encoding/binary"
)

type TLSTreeParams [3]uint64

var (
	TLSGOSTR341112256WithMagmaCTROMAC TLSTreeParams = TLSTreeParams{
		binary.BigEndian.Uint64([]byte{0xFF, 0xFF, 0xFF, 0xC0, 0x00, 0x00, 0x00, 0x00}),
		binary.BigEndian.Uint64([]byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFE, 0x00, 0x00, 0x00}),
		binary.BigEndian.Uint64([]byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xF0, 0x00}),
	}
	TLSGOSTR341112256WithKuznyechikCTROMAC TLSTreeParams = TLSTreeParams{
		binary.BigEndian.Uint64([]byte{0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00}),
		binary.BigEndian.Uint64([]byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xF8, 0x00, 0x00}),
		binary.BigEndian.Uint64([]byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xC0}),
	}
	TLSGOSTR341112256WithKuznyechikMGML TLSTreeParams = TLSTreeParams{
		binary.BigEndian.Uint64([]byte{0xF8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}),
		binary.BigEndian.Uint64([]byte{0xFF, 0xFF, 0xFF, 0xF0, 0x00, 0x00, 0x00, 0x00}),
		binary.BigEndian.Uint64([]byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xE0, 0x00}),
	}
	TLSGOSTR341112256WithMagmaMGML TLSTreeParams = TLSTreeParams{
		binary.BigEndian.Uint64([]byte{0xFF, 0xE0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}),
		binary.BigEndian.Uint64([]byte{0xFF, 0xFF, 0xFF, 0xFF, 0xC0, 0x00, 0x00, 0x00}),
		binary.BigEndian.Uint64([]byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x80}),
	}
	TLSGOSTR341112256WithKuznyechikMGMS TLSTreeParams = TLSTreeParams{
		binary.BigEndian.Uint64([]byte{0xFF, 0xFF, 0xFF, 0xFF, 0xE0, 0x00, 0x00, 0x00}),
		binary.BigEndian.Uint64([]byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00}),
		binary.BigEndian.Uint64([]byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xF8}),
	}
	TLSGOSTR341112256WithMagmaMGMS TLSTreeParams = TLSTreeParams{
		binary.BigEndian.Uint64([]byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFC, 0x00, 0x00, 0x00}),
		binary.BigEndian.Uint64([]byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xE0, 0x00}),
		binary.BigEndian.Uint64([]byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}),
	}
)

type TLSTree struct {
	params     TLSTreeParams
	keyRoot    []byte
	seqNumPrev uint64
	seq        []byte
	key        []byte
}

func NewTLSTree(params TLSTreeParams, keyRoot []byte) *TLSTree {
	key := make([]byte, len(keyRoot))
	copy(key, keyRoot)
	return &TLSTree{
		params:  params,
		keyRoot: key,
		seq:     make([]byte, 8),
		key:     make([]byte, Size),
	}
}

func (t *TLSTree) DeriveCached(seqNum uint64) ([]byte, bool) {
	if seqNum > 0 &&
		(seqNum&t.params[0]) == ((t.seqNumPrev)&t.params[0]) &&
		(seqNum&t.params[1]) == ((t.seqNumPrev)&t.params[1]) &&
		(seqNum&t.params[2]) == ((t.seqNumPrev)&t.params[2]) {
		return t.key, true
	}
	binary.BigEndian.PutUint64(t.seq, seqNum&t.params[0])
	kdf1 := NewKDF(t.keyRoot)
	kdf2 := NewKDF(kdf1.Derive(t.key[:0], []byte("level1"), t.seq))
	binary.BigEndian.PutUint64(t.seq, seqNum&t.params[1])
	kdf3 := NewKDF(kdf2.Derive(t.key[:0], []byte("level2"), t.seq))
	binary.BigEndian.PutUint64(t.seq, seqNum&t.params[2])
	kdf3.Derive(t.key[:0], []byte("level3"), t.seq)
	t.seqNumPrev = seqNum
	return t.key, false
}

func (t *TLSTree) Derive(seqNum uint64) []byte {
	keyDerived := make([]byte, Size)
	key, _ := t.DeriveCached(seqNum)
	copy(keyDerived, key)
	return keyDerived
}
