package multihash

import (
	"crypto"
	"errors"
)

var ErrBufferGetFailed = errors.New("buffer could not be asserted as *[]byte")
var ErrHashFunctionNotAvailable = errors.New("hash function not available")

type UnavailableHashFunctionError struct {
	Hash crypto.Hash
}

func (e UnavailableHashFunctionError) Error() string {
	return "hash function not available"
}

func (e UnavailableHashFunctionError) Is(target error) bool {
	return target == ErrHashFunctionNotAvailable
}
