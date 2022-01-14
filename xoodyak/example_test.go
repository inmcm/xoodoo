package xoodyak_test

import (
	"fmt"

	"github.com/inmcm/xoodoo/xoodyak"
)

func ExampleHashXoodyak() {
	myMsg := []byte("hello xoodoo")
	myHash := xoodyak.HashXoodyak(myMsg)
	fmt.Printf("Msg:'%s'\nHash:%x\n", myMsg, myHash)
	// Output: Msg:hello xoodoo
	// Hash:5c9a95363d79b2157cbdfff49dddaf1f20562dc64644f2d28211478537e6b29a
}

func ExampleHashXoodyakLen() {
	myMsg := []byte("hello xoodoo")
	myHash := xoodyak.HashXoodyakLen(myMsg, 64)
	fmt.Printf("Msg:%s\nHash:%x\n", myMsg, myHash)
	// Output: Msg:hello xoodoo
	// Hash:5c9a95363d79b2157cbdfff49dddaf1f20562dc64644f2d28211478537e6b29a5675a6d4a3fe18b985e7ae018133c118a44c5f82b3672492a30408937e5712cb
}
