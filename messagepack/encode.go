package messagepack

/* Encoder pool. */

import (
	"bytes"
	"sync"

	"github.com/vmihailenco/msgpack/v5"
)

var encPool = sync.Pool{
	New: func() interface{} {
		enc := msgpack.NewEncoder(nil)
		enc.SetCustomStructTag("json")
		enc.UseCompactInts(true)
		enc.UseCompactFloats(true)
		return enc
	},
}

func getEncoder() *msgpack.Encoder {
	return encPool.Get().(*msgpack.Encoder)
}

func putEncoder(enc *msgpack.Encoder) {
	enc.ResetWriter(nil)
	encPool.Put(enc)
}

// Marshal returns the MessagePack encoding of v.
func Marshal(v interface{}) ([]byte, error) {
	enc := getEncoder()

	var buf bytes.Buffer
	enc.ResetWriter(&buf)

	err := enc.Encode(v)

	putEncoder(enc)

	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
