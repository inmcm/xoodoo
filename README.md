# Xoodoo/Xoodyak
Pure Go implementation of [Xoodoo](https://keccak.team/xoodoo.html) permutation used in the [Xoodyak](https://keccak.team/xoodyak.html) cryptographic scheme. Xoodyak implementation supports all specified Cyclist functions described in the [specification](https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/xoodyak-spec-final.pdf). In addition, higher level primitives are provided to support hashing and authenticated encryption modes described in [NIST's Lightweight Cryptography](https://csrc.nist.gov/Projects/lightweight-cryptography/finalists) competition. Go standard library interfaces are also support where applicable. Test vectors are generated from the [reference C code](https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-submissions/xoodyak.zip) provided to NIST as part of the
LWC competition.


## Installation
Install like any Go package:
```bash
go get -u github.com/inmcm/xoodoo
```
for versions of Go before 1.16 use:
```bash
GO111MODULE=on go get -u github.com/inmcm/xoodoo
```

## Quickstart
If you need to use the LWC defined hashing or AEAD operating modes

### Hashing
```go
package main

import (
	"fmt"

	"github.com/inmcm/xoodoo/xoodyak"
)

func main() {
	myMsg := []byte("hello xoodoo")
	myHash := xoodyak.HashXoodyak(myMsg)
	fmt.Printf("Msg:%s\nHash:%x", myMsg, myHash)
}
```