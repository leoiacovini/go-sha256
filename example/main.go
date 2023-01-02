package main

import (
	"fmt"

	"github.com/leoiacovini/go-sha256"
)

func main() {
	segment := "hello world"
	inputStr := ""
	rounds := 15
	for i := 0; i < rounds; i++ {
		inputStr += segment
	}
	digest := sha256.Hash([]byte(inputStr))
	fmt.Printf("Input String: %v\n", inputStr)
	fmt.Println("-----")
	fmt.Printf("SHA-256: %x\n\n", digest)
}
