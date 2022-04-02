# rc5libgo

Golang library implementation of RC5 

# used links

https://www.geeksforgeeks.org/rc5-encryption-algorithm/

https://packetstormsecurity.com/files/20519/rc5ref.c.html


# usage example 	

package main

import (
	"bytes"
    "fmt"
    "github.com/yamukha/rc5libgo"
)

func main() {

	key1 := []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F}
	pt1 := []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77}
	ct1 := []byte{0x2D, 0xDC, 0x14, 0x9B, 0xCF, 0x08, 0x8B, 0x9E}

	pt3 := []byte{0x96, 0x95, 0x0D, 0xDA, 0x65, 0x4A, 0x3D, 0x62}
	ct3 := []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77}

	el1 := rc5libgo.Encode(key1, pt1, rc5libgo.R12, rc5libgo.W32, rc5libgo.P32, rc5libgo.Q32)
	fmt.Println("encoded:   ", el1)
	fmt.Println("expected:  ", ct1)
	if 0 == bytes.Compare(el1, ct1) {
		fmt.Println("Equal")
	} else {
		fmt.Println("Not Equal")
	}

	dl1 := rc5libgo.Decode(key1, ct3, rc5libgo.R12, rc5libgo.W32, rc5libgo.P32, rc5libgo.Q32)
	fmt.Println("decoded:  ", dl1)
	fmt.Println("expected: ", pt3)
	if 0 == bytes.Compare(dl1, pt3) {
		fmt.Println("Equal")
	} else {
		fmt.Println("Not Equal")
	}
}
