[![Go Reference](https://pkg.go.dev/badge/github.com/inmcm/xoodoo.svg)](https://pkg.go.dev/github.com/inmcm/xoodoo)
[![Go Report Card](https://goreportcard.com/badge/github.com/inmcm/xoodoo)](https://goreportcard.com/report/github.com/inmcm/xoodoo)

# Xoodoo/Xoodyak
A pure Go implementation of the [Xoodyak](https://keccak.team/xoodyak.html) cryptographic scheme utilizing the [Xoodoo](https://keccak.team/xoodoo.html) permutation function. The Xoodyak implementation supports all specified Cyclist mode functions described in the [specification](https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/xoodyak-spec-final.pdf). 

In addition, higher level primitives are provided to support the hashing and authenticated encryption modes described in [NIST's LightWeight Cryptography (LWC)](https://csrc.nist.gov/Projects/lightweight-cryptography/finalists) competition. Go standard library interfaces are also supported where applicable. Test vectors are taken from or otherwise generated from the [reference C code](https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-submissions/xoodyak.zip) provided to NIST as part of the
LWC competition.

## Installation
Install like any Go package:
```bash
go get -u github.com/inmcm/xoodoo@latest
```
for versions of Go before `1.16` use:
```bash
GO111MODULE=on go get -u github.com/inmcm/xoodoo
```

## Quickstart
If you need just the LWC defined Xoodyak hashing or AEAD operating modes, examples are given below. For other uses of this package, please consult the documentation.

### Hashing
Xoodyak provides a default hashing function that will output a 256-bit digest provided an arbitrary number of input bytes.
```go
package main

import (
	"fmt"

	"github.com/inmcm/xoodoo/xoodyak"
)

func main() {
	myMsg := []byte("hello xoodoo")
	myHash := xoodyak.HashXoodyak(myMsg)
	fmt.Printf("Msg:'%s'\nHash:%x\n", myMsg, myHash)
}
```
```sh
% go run main.go
Msg:hello xoodoo
Hash:5c9a95363d79b2157cbdfff49dddaf1f20562dc64644f2d28211478537e6b29a
```
For more complicated hashing tasks that require multi-part input or streaming bytes via [io.Readers](https://pkg.go.dev/io#Reader), the standard library [hash.Hash](https://pkg.go.dev/hash#Hash) interface is also supported.
```go
package main

import (
	"bytes"
	"fmt"
	"io"

	"github.com/inmcm/xoodoo/xoodyak"
)

func main() {
	myMsg := []byte("hello xoodoo")
	msgBuf := bytes.NewBuffer(myMsg)
	xHash := xoodyak.NewXoodyakHash()
	io.Copy(xHash, msgBuf)
	myHash := xHash.Sum(nil)
	fmt.Printf("Msg:'%s'\nHash:%x\n", myMsg, myHash)
}
```
```sh
% go run main.go
Msg:'hello xoodoo'
Hash:5c9a95363d79b2157cbdfff49dddaf1f20562dc64644f2d28211478537e6b29a
```
### Authenticated Encryption
Xoodyak provides an Authenticated Encryption with Associated Data (AEAD) mode that requires a 128-bit key and 128-bit nonce to encrypt a message of arbitrary length. An optional number of associated data bytes may also be provided. A 128-bit authentication tag is also generated at encrypt time that can be used during decryption to verify the integrity of the resulting plaintext.
```go
package main

import (
	"fmt"
	"strings"

	"github.com/inmcm/xoodoo/xoodyak"
)

func main() {
	myMsg := []byte("hello xoodoo")
	// Normally, this is randomly generated and kept secret
	myKey := []byte{
		0x0F, 0x0E, 0x0D, 0x0C,
		0x0B, 0x0A, 0x09, 0x08,
		0x07, 0x06, 0x05, 0x04,
		0x03, 0x02, 0x01, 0x00,
	}
	// Normally, this is randomly generated and never repeated per key
	myNonce := []byte{
		0xF0, 0xE1, 0xD2, 0xC3,
		0xB4, 0xA5, 0x96, 0x87,
		0x78, 0x69, 0x5A, 0x4B,
		0x3C, 0x2D, 0x1E, 0x0F,
	}
	// Any sort of non-secret information about the plaintext or context of encryption
	myAD := []byte("33°59’39.51″N, 7°50’33.69″E")
	myCt, myTag, _ := xoodyak.CryptoEncryptAEAD(myMsg, myKey, myNonce, myAD)
	myPt, valid, _ := xoodyak.CryptoDecryptAEAD(myCt, myKey, myNonce, myAD, myTag)
	var output strings.Builder
	fmt.Fprintf(&output, "Msg:'%s'\n", myMsg)
	fmt.Fprintf(&output, "Key:%x\n", myKey)
	fmt.Fprintf(&output, "Nonce:%x\n", myNonce)
	fmt.Fprintf(&output, "Metadata:%x\n", myAD)
	fmt.Fprintf(&output, "Ciphertext:%x\n", myCt)
	fmt.Fprintf(&output, "AuthTag:%x\n", myTag)
	fmt.Fprintf(&output, "DecryptOK:%t\n", valid)
	fmt.Fprintf(&output, "Plaintext:'%s'", myPt)
	fmt.Println(output.String())
}
```
```sh
% go run main.go
Msg:'hello xoodoo'
Key:0f0e0d0c0b0a09080706050403020100
Nonce:f0e1d2c3b4a5968778695a4b3c2d1e0f
Metadata:3333c2b03539e2809933392e3531e280b34e2c2037c2b03530e2809933332e3639e280b345
Ciphertext:fffc82f88d8bb2ba4f38b85d
AuthTag:6ef42d19830b3f0ecd784be7f4d10f46
DecryptOK:true
Plaintext:'hello xoodoo'
```
For easier integration with existing AEAD code, the standard library [cipher.AEAD](https://pkg.go.dev/crypto/cipher#AEAD) interface is also supported:
```go
package main

import (
	"fmt"
	"log"
	"strings"

	"github.com/inmcm/xoodoo/xoodyak"
)

func main() {
	myMsg := []byte("hello xoodoo")
	// Normally, this is randomly generated and kept secret
	myKey := []byte{
		0x0F, 0x0E, 0x0D, 0x0C,
		0x0B, 0x0A, 0x09, 0x08,
		0x07, 0x06, 0x05, 0x04,
		0x03, 0x02, 0x01, 0x00,
	}
	// Normally, this is randomly generated and never repeated per key
	myNonce := []byte{
		0xF0, 0xE1, 0xD2, 0xC3,
		0xB4, 0xA5, 0x96, 0x87,
		0x78, 0x69, 0x5A, 0x4B,
		0x3C, 0x2D, 0x1E, 0x0F,
	}
	// Any sort of non-secret data
	myAD := []byte("33°59’39.51″N, 7°50’33.69″E")
	myXkAEAD, _ := xoodyak.NewXoodyakAEAD(myKey)

	myAuthCt := myXkAEAD.Seal(nil, myNonce, myMsg, myAD)
	myPt, err := myXkAEAD.Open(nil, myNonce, myAuthCt, myAD)
	// error is returned on decrypt authentication failure
	if err != nil {
		log.Fatal(err)
	}
	var output strings.Builder
	fmt.Fprintf(&output, "Msg:'%s'\n", myMsg)
	fmt.Fprintf(&output, "Key:%x\n", myKey)
	fmt.Fprintf(&output, "Nonce:%x\n", myNonce)
	fmt.Fprintf(&output, "Metadata:%x\n", myAD)
	fmt.Fprintf(&output, "Authenticated Ciphertext:%x\n", myAuthCt)
	fmt.Fprintf(&output, "Plaintext:'%s'", myPt)
	fmt.Println(output.String())
}
```
```sh
% go run main.go
Msg:'hello xoodoo'
Key:0f0e0d0c0b0a09080706050403020100
Nonce:f0e1d2c3b4a5968778695a4b3c2d1e0f
Metadata:3333c2b03539e2809933392e3531e280b34e2c2037c2b03530e2809933332e3639e280b345
Authenticated Ciphertext:fffc82f88d8bb2ba4f38b85d6ef42d19830b3f0ecd784be7f4d10f46
Plaintext:'hello xoodoo'
```

For applications that are better suited to streaming bytes via an [io.Reader](https://pkg.go.dev/io#Reader) or [io.Writer](https://pkg.go.dev/io#Writer), the DecryptStream and EncryptStream types are available. These types wrap an existing Writer or Reader to transparently encrypt or decrypt bytes respectively.
```go
package main

import (
	"bytes"
	"fmt"
	"io"
	"strings"

	"github.com/inmcm/xoodoo/xoodyak"
)

func main() {
	myMsg := []byte("hello xoodoo")
	// Normally, this is randomly generated and kept secret
	myKey := []byte{
		0x0F, 0x0E, 0x0D, 0x0C,
		0x0B, 0x0A, 0x09, 0x08,
		0x07, 0x06, 0x05, 0x04,
		0x03, 0x02, 0x01, 0x00,
	}
	// Normally, this is randomly generated and never repeated per key
	myNonce := []byte{
		0xF0, 0xE1, 0xD2, 0xC3,
		0xB4, 0xA5, 0x96, 0x87,
		0x78, 0x69, 0x5A, 0x4B,
		0x3C, 0x2D, 0x1E, 0x0F,
	}
	// Any sort of non-secret data
	myAD := []byte("33°59’39.51″N, 7°50’33.69″E")

	// We want to write our encrypted, authenticated message to this buffer
	encryptBuf := bytes.NewBuffer(nil)
	myES, _ := xoodyak.NewEncryptStream(encryptBuf, myKey, myNonce, myAD)

	// Write as many plaintext bytes, as many times, as needed
	_, err := myES.Write(myMsg)
	if err != nil {
		// handle any write errors
	}
	// Close must be called after all plaintext is written in order to finalize the encryption and 
	// generate the authentication tag
	myES.Close()
	if err != nil {
		// handle any final write errors
	}
	ciphertext := encryptBuf.Bytes()

	// Now read back the encrypted bytes and decrypt on the fly into another buffer
	plainTextBuf := bytes.NewBuffer(nil)
	myDS, _ := xoodyak.NewDecryptStream(encryptBuf, myKey, myNonce, myAD)

	// Read until EOF is reached
	io.Copy(plainTextBuf, myDS)
	if err != nil {
		// handle any read/authentication errors
	}

	var output strings.Builder
	fmt.Fprintf(&output, "Msg:'%s'\n", myMsg)
	fmt.Fprintf(&output, "Key:%x\n", myKey)
	fmt.Fprintf(&output, "Nonce:%x\n", myNonce)
	fmt.Fprintf(&output, "Metadata:%x\n", myAD)
	fmt.Fprintf(&output, "Authenticated Ciphertext:%x\n", ciphertext)
	fmt.Fprintf(&output, "Plaintext:'%s'", string(plainTextBuf.Bytes()))
	fmt.Println(output.String())
}
```
```sh
% go run main.go
Msg:'hello xoodoo'
Key:0f0e0d0c0b0a09080706050403020100
Nonce:f0e1d2c3b4a5968778695a4b3c2d1e0f
Metadata:3333c2b03539e2809933392e3531e280b34e2c2037c2b03530e2809933332e3639e280b345
Authenticated Ciphertext:fffc82f88d8bb2ba4f38b85d6ef42d19830b3f0ecd784be7f4d10f46
Plaintext:'hello xoodoo'
```

## Benchmarks
A collection of micro-benchmarks are provided within each sub-package to allow for performance comparisons between systems and other implementations. To run the entire suite:
```sh
% go test -bench=. ./...
goos: linux
goarch: amd64
pkg: github.com/inmcm/xoodoo/xoodoo
cpu: AMD EPYC 7601 32-Core Processor
BenchmarkXoodooPermutation 	 5036336	       247.1 ns/op
BenchmarkXorStateBytes     	155647138	         8.142 ns/op
BenchmarkUnmarshalBinary   	162885417	         7.921 ns/op
BenchmarkMarshalBinary     	22321699	        57.00 ns/op
PASS
ok  	github.com/inmcm/xoodoo/xoodoo	6.903s
goos: linux
goarch: amd64
pkg: github.com/inmcm/xoodoo/xoodyak
cpu: AMD EPYC 7601 32-Core Processor
BenchmarkEncryptAEAD        	   55347	     19244 ns/op
BenchmarkDecryptAEAD        	   66106	     19082 ns/op
BenchmarkHash               	   71767	     16448 ns/op
BenchmarkCryptoHash         	   76081	     17217 ns/op
BenchmarkHashInterface      	   72882	     16869 ns/op
BenchmarkMAC                	  172496	      7211 ns/op
BenchmarkHashInterfaceMAC   	  193495	      6746 ns/op
BenchmarkXoodyakCyclistDown 	81201373	        15.11 ns/op
BenchmarkXoodyakCyclistUp   	 4199320	       276.5 ns/op
PASS
ok  	github.com/inmcm/xoodoo/xoodyak	13.555s
```

## Caveats
While security was top of mind during development, this implementation has not been fully audited for timing attacks, side channel attacks, or other vulnerabilities. Other bugs not caught by the test cases may be present. Use in a production environment is not encouraged.

If any of above is of concern, please check out the official [KeccakTools](https://github.com/gvanas/KeccakTools) and [Keccak Code
Package](https://github.com/gvanas/KeccakCodePackage)
