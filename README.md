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
If you just need to use the LWC defined Xoodyak hashing or AEAD operating modes, examples are given below. For other uses of this package, please consult the documentation.

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
	fmt.Printf("Msg:%s\nHash:%x\n", myMsg, myHash)
}
```
```sh
% go run main.go
Msg:hello xoodoo
Hash:5c9a95363d79b2157cbdfff49dddaf1f20562dc64644f2d28211478537e6b29a
```