// Command gentoken prints a random bearer token suitable for SCIM_BEARER_TOKEN.
package main

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
)

func main() {
	b := make([]byte, 32) // 256 bits
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	fmt.Println(base64.RawURLEncoding.EncodeToString(b))
}
