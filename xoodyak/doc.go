// Package xoodyak implements the Xoodyak cryptographic suite. Xoodyak is the Cyclist operating mode
// utilizing the Xoodoo state permutation function to power a collection of building block functions. All
// functions described in the Xoodyak specification are implemented in this package:
// https://eprint.iacr.org/2018/767.pdf
// Xoodyak can operate in one of two modes: hashing or keyed mode  which is configured as part of the Xoodyak
// object. Some functions are only available in one particular mode and will panic if invoked while
// Xoodyak is configured incorrectly.
// Using the Cyclist functions, Xoodyak can be configured into a variety of more standard cryptographic
// primitives such as:
//    - Hashing
//    - Message Authentication Code generation
//    - Authenticated Encryption
// The hashing and AEAD primitives provided here are intended to be compatible with Xoodyak entry
// in NIST Lightweight Cryptography competition
// https://csrc.nist.gov/projects/lightweight-cryptography
//
package xoodyak
