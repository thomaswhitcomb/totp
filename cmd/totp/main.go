package main

import (
	"fmt"
	"os"

	"github.com/thomaswhitcomb/totp"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Missing secret")
		os.Exit(1)
	}

	otp, err := totp.New(os.Args[1])
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	code, duration := otp.Code()
	fmt.Println(code, duration)
}
