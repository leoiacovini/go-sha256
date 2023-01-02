package main

import (
	"fmt"

	"github.com/leoiacovini/go-sha256"
)

func main() {
	inputStr := "hfkhdkfhdskfhsdkjfhsdkjhfadhflahgfsdhg;hfdsghsdflghfdslghsshfgklhsdflgfhsldhfgl"
	digest := sha256.Hash([]byte(inputStr))
	fmt.Printf("SHA-256: %x\n\n", digest)
}
