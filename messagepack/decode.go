package messagepack

/* Decoder pool. */

import (
	"bytes"
	"sync"

	"github.com/vmihailenco/msgpack/v5"
)

var decPool = sync.Pool{
	New: func() any {
		dec := msgpack.NewDecoder(nil)
		dec.SetCustomStructTag("json")
		return dec
	},
}

func getDecoder() *msgpack.Decoder {
	return decPool.Get().(*msgpack.Decoder)
}

func putDecoder(dec *msgpack.Decoder) {
	dec.ResetReader(nil)
	decPool.Put(dec)
}

// Unmarshal parses the MessagePack-encoded data and stores the result
// in the value pointed to by v.
// Destination v must be a non-nil pointer.
func Unmarshal(data []byte, v any) error {
	dec := getDecoder()
	dec.UsePreallocateValues(true)
	dec.ResetReader(bytes.NewReader(data))
	err := dec.Decode(v)

	putDecoder(dec)

	return err
}
