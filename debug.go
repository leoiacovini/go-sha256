package sha256

import "fmt"

//lint:ignore U1000 used just when debugging
func printBinary(bin []byte) {
	for i, b := range bin {
		fmt.Printf("%08b ", b)
		if (i+1)%4 == 0 {
			fmt.Println("")
		}
	}
	fmt.Println()
}

//lint:ignore U1000 used just when debugging
func printMessageSchedule(messageSchedule [64]uint32) {
	for i, v := range messageSchedule {
		fmt.Printf("w%02d ", i)
		fmt.Printf("%032b", v)
		fmt.Println("")
	}
	fmt.Println()
}
