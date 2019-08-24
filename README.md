# Pure Go GOST cryptographic functions library.

## Fork of original gogost project https://git.cypherpunks.ru/cgit.cgi/gogost.git

GOST is GOvernment STandard of Russian Federation (and Soviet Union).
## Features
 * GOST 28147-89 (RFC 5830) block cipher with ECB, CNT (CTR), CFB, MAC CBC (RFC 4357) modes of operation
 * various 28147-89-related S-boxes included
 * GOST R 34.11-94 hash function (RFC 5831)
 * GOST R 34.11-2012 Стрибог (Streebog) hash function (RFC 6986)
 * GOST R 34.10-2001 (RFC 5832) public key signature function
 * GOST R 34.10-2012 (RFC 7091) public key signature function
 * various 34.10 curve parameters included
 * Coordinates conversion from twisted Edwards to Weierstrass form and vice versa
 * VKO GOST R 34.10-2001 key agreement function (RFC 4357)
 * VKO GOST R 34.10-2012 key agreement function (RFC 7836)
 * KDF_GOSTR3411_2012_256 KDF function (RFC 7836)
 * GOST R 34.12-2015 128-bit block cipher Кузнечик (Kuznechik) (RFC 7801)
 * GOST R 34.12-2015 64-bit block cipher Магма (Magma)
 * GOST R 34.13-2015 padding methods
 * MGM AEAD mode for 64 and 128 bit ciphers
 * TLSTREE keyscheduling function

## Requirements
 * Go 1.11 or higher.

## Known problems:

 * intermediate calculation values are not zeroed
 * 34.10 is not time constant and slow

GoGOST is free software: see the file COPYING for copying conditions.

GoGOST'es home page is: http://gogost.cypherpunks.ru/
You can read about GOST algorithms more: [project home](http://gost.cypherpunks.ru/) [GOST standards](https://tc26.ru/en/standards/standards/)

Please send questions, bug reports and patches to
https://lists.cypherpunks.ru/mailman/listinfo/gost
mailing list. Announcements also go to this mailing list.

Development Git source code repository currently is located here:
https://git.cypherpunks.ru/cgit.cgi/gogost.git/

## Installation

Install:

```shell
go get -u github.com/ddulesov/gogost
```

Import:

```go
import "github.com/ddulesov/gogost"
```

## Quickstart
```go
package main

import (
    "encoding/hex"
    "fmt"
    "github.com/ddulesov/gogost/gost34112012256"
)

func main() {
    h := gost34112012256.New()
    h.Write([]byte("hello world"))
    fmt.Println(hex.EncodeToString(h.Sum(nil)))
}
```