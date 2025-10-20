
package main

import (
	"bytes"
	"crypto/sm4"
	"encoding/hex"
	"fmt"
	"os"
)

// From RFC8998
var _ = `A.1.  SM4-GCM Test Vectors

   Initialization Vector:   00001234567800000000ABCD
   Key:                     0123456789ABCDEFFEDCBA9876543210
   Plaintext:               AAAAAAAAAAAAAAAABBBBBBBBBBBBBBBB
                            CCCCCCCCCCCCCCCCDDDDDDDDDDDDDDDD
                            EEEEEEEEEEEEEEEEFFFFFFFFFFFFFFFF
                            EEEEEEEEEEEEEEEEAAAAAAAAAAAAAAAA
   Associated Data:         FEEDFACEDEADBEEFFEEDFACEDEADBEEFABADDAD2
   CipherText:              17F399F08C67D5EE19D0DC9969C4BB7D
                            5FD46FD3756489069157B282BB200735
                            D82710CA5C22F0CCFA7CBF93D496AC15
                            A56834CBCF98C397B4024A2691233B8D
   Authentication Tag:      83DE3541E4C2B58177E065A9BF7B62EC
`

func main() {
	key, _ := hex.DecodeString("0123456789ABCDEFFEDCBA9876543210")

	sm4gcm, err := sm4.NewSM4GCM(key)
	if err != nil {
		fmt.Printf("%v\n", err)
		os.Exit(1)
	}

	nonce, _ := hex.DecodeString("00001234567800000000ABCD")

	plaintext, _ := hex.DecodeString("AAAAAAAAAAAAAAAABBBBBBBBBBBBBBBBCCCCCCCCCCCCCCCCDDDDDDDDDDDDDDDDEEEEEEEEEEEEEEEEFFFFFFFFFFFFFFFFEEEEEEEEEEEEEEEEAAAAAAAAAAAAAAAA")

	ad, _ := hex.DecodeString("FEEDFACEDEADBEEFFEEDFACEDEADBEEFABADDAD2")

	ct := sm4gcm.Seal(nil, nonce, plaintext, ad)
	expected_ct, _ := hex.DecodeString("17F399F08C67D5EE19D0DC9969C4BB7D5FD46FD3756489069157B282BB200735D82710CA5C22F0CCFA7CBF93D496AC15A56834CBCF98C397B4024A2691233B8D83DE3541E4C2B58177E065A9BF7B62EC")
	if !bytes.Equal(ct, expected_ct) {
		fmt.Printf("SM4GCM Seal() failed\n")
		os.Exit(1)
	}

	plaintext2, err := sm4gcm.Open(nil, nonce, ct, ad)
	if err != nil {
		fmt.Printf("SM4GCM Open() failed: %v\n", err)
		os.Exit(1)
	}

	if !bytes.Equal(plaintext, plaintext2) {
		fmt.Printf("SM4GCM Open() failed\n")
		os.Exit(1)
	}

	fmt.Printf("SM4GCM ok\n")
}
