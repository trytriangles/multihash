// package multihash provides mechanisms to efficiently obtain multiple hashes
// for pieces of data, by computing them in parallel during a single read of
// the data and by re-using buffers.
package multihash

import (
	"errors"
	"hash"
	"io"
	"os"
	"sync"
)

// A power-of-two buffer size minimizes unneccessary syscalls on most
// filesystems. The number 2 ** 16 was arrived at by comparing benchmarks on
// spinning disks, the medium benefiting most from this optimization, and still
// the medium most likely to be storing many large files.
const bufferSize = 65536 // 2 ** 16

var bufferPool = sync.Pool{
	New: func() any {
		b := make([]byte, bufferSize)
		return &b
	},
}

// FromFile takes a filename and any number of hash.Hash values, and returns
// a slice of the results. The results are in the same order as the arguments;
// that is, if one calls
//
//	fileHashes := fromFile("foo.txt", crypto.MD5.New(), crypto.SHA1.New())
//
// fileHashes[0] will be the MD5 digest and fileHashes[1] the SHA1 digest.
func FromFile(filename string, hashes ...hash.Hash) (hashset [][]byte, err error) {
	f, err := os.Open(filename)
	if err != nil {
		return
	}
	defer f.Close()
	return FromReader(f, hashes...)
}

// FromReader takes an io.Reader and any number of hash.Hash values, and
// returns a slice of the results. The results are in the same order as
// the arguments; that is, if one calls
//
//	hashes := fromReader(data, crypto.MD5.New(), crypto.SHA1.New())
//
// hashes[0] will be the MD5 digest and hashes[1] the SHA1 digest.
func FromReader(data io.Reader, hashFunctions ...hash.Hash) (hashset [][]byte, err error) {
	buffer, ok := (bufferPool.Get()).(*[]byte)
	if !ok {
		return hashset, ErrBufferGetFailed
	}
	defer bufferPool.Put(buffer)
	errorChannel := make(chan error)
	readySignals := make(chan int)
	returnChannels := make([]chan []byte, len(hashFunctions))
	for index, hash := range hashFunctions {
		returnChannel := make(chan []byte)
		go hashFeeder(hash, errorChannel, readySignals, returnChannel, buffer)
		returnChannels[index] = returnChannel
	}

	for {
		bytesRead, err := data.Read(*buffer)
		if err != nil {
			if bytesRead == 0 && errors.Is(err, io.EOF) {
				close(readySignals)
				break
			}
			return hashset, err
		}
		for i := 0; i < len(hashFunctions); i++ {
			readySignals <- bytesRead
		}
		for i := 0; i < len(hashFunctions); i++ {
			if err = <-errorChannel; err != nil {
				return hashset, err
			}
		}
	}

	for _, returnChannel := range returnChannels {
		hashset = append(hashset, <-returnChannel)
	}
	return hashset, nil
}

// hashFeeder writes to hash each time it receives a ready signal, and sends
// the final hash digest when readySignals closes. It is intended to be run
// in a goroutine as a subroutine of FromReader, once per hash it is producing.
func hashFeeder(
	hash hash.Hash,
	errorChannel chan error,
	// When the buffer has been populated with new data, readySignals will
	// receive the number of bytes that were written into it. When readySignals
	// closes, reading has ended, and hashFeeder should return.
	readySignals chan int,
	returnChannel chan []byte,
	// We use a pointer to a byte slice rather than a byte slice proper to
	// avoid allocations when retrieving it from and returning it to a
	// sync.Pool.
	buffer *[]byte,
) {
	for bytesRead := range readySignals {
		_, err := hash.Write((*buffer)[:bytesRead])
		errorChannel <- err
	}
	returnChannel <- hash.Sum(nil)
}
