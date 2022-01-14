// Package xoodoo implements the Xoodoo cryptographic permutation function from which a variety of
// other cryptographic primitives and modes can be built. Xoodoo operates on a 384-bit state, realized
// here as an array of twelve(12) 32-bit unsigned integers, to generate a new pseudo-random state each time
// the permutation is applied. In addition to the main constructor and permutation functions, a variety
// of other helper methods are provided to manipulate the underlying state bytes.
//
package xoodoo
