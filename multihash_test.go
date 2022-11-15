package multihash

import (
	"crypto"
	"log"
	"testing"

	_ "crypto/md5"
	_ "crypto/sha1"
	_ "crypto/sha256"
)

func Test_fromFile(t *testing.T) {
	f := "testing/text1.txt"
	m, err := FromFile(f, crypto.MD5.New(), crypto.SHA1.New(), crypto.SHA256.New())
	if err != nil {
		t.Fatal(err)
	}
	expected := []byte{0x55, 0x30, 0xde, 0x30, 0x71, 0xa1, 0xa9, 0x03, 0x54, 0x78, 0xde, 0xfc, 0xc1, 0xd5, 0x86, 0xe1}
	if !slicesEqual(m[0], expected) {
		t.Fatalf("MD5 for %v was %x, expected %x\n", f, m[0], expected)
	}

	expected = []byte{0x06, 0x5e, 0xd8, 0x25, 0x6d, 0xad, 0x31, 0x11, 0x25, 0xda, 0x74, 0xcc, 0x43, 0x57, 0x3f, 0x7d, 0xa6, 0xfa, 0xa5, 0x78}
	if !slicesEqual(m[1], expected) {
		t.Fatalf("SHA1 for %v was %x, expected %x\n", f, m[0], expected)
	}

	expected = []byte{0x8b, 0xb5, 0xbc, 0x05, 0x61, 0x8f, 0x10, 0x36, 0xa0, 0x63, 0xbb, 0xf8, 0x3c, 0xf7, 0x4c, 0xca, 0x16, 0x3a, 0x60, 0x34, 0x37, 0x91, 0xc0, 0xc9, 0x30, 0xac, 0xc3, 0x1b, 0xf0, 0xc0, 0x90, 0xea}
	if !slicesEqual(m[2], expected) {
		t.Fatalf("SHA256 for %v was %x, expected %x\n", f, m[0], expected)
	}
}

func Benchmark_fromFile(b *testing.B) {
	filenames := []string{
		"errors.go",
		"go.mod",
		"testing/text1.txt",
		"multihash.go",
		"multihash_test.go",
	}
	for _, filename := range filenames {
		hashes, err := FromFile(filename, crypto.SHA1.New(), crypto.MD5.New(), crypto.SHA256.New())
		if err != nil {
			log.Fatal(err)
		}
		for _, hash := range hashes {
			log.Printf("%x\n", hash)
		}
	}

}

func slicesEqual[T comparable](a, b []T) bool {
	if len(a) != len(b) {
		return false
	}
	for index := range a {
		if a[index] != b[index] {
			return false
		}
	}
	return true
}
