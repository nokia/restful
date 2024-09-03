// Copyright 2021- Nokia
// Licensed under the BSD 3-Clause License.
// SPDX-License-Identifier: BSD-3-Clause

package messagepack

/* Provides Marshal/Unmarshal similar to msgpack's own. The major difference is that it uses `json` tags. */

import (
	"bytes"
	"io"

	"github.com/vmihailenco/msgpack/v5"
)

func resetEncoder(enc *msgpack.Encoder, w io.Writer) {
	enc.Reset(w)
	enc.SetCustomStructTag("json")
	enc.UseCompactInts(true)
	enc.UseCompactFloats(true)
}

func resetDecoder(dec *msgpack.Decoder, r io.Reader) {
	dec.Reset(r)
	dec.SetCustomStructTag("json")
}

// Marshal returns the MessagePack encoding of v.
func Marshal(v any) ([]byte, error) {
	enc := msgpack.GetEncoder()

	var buf bytes.Buffer
	resetEncoder(enc, &buf)

	err := enc.Encode(v)

	msgpack.PutEncoder(enc)

	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// Unmarshal parses the MessagePack-encoded data and stores the result
// in the value pointed to by v.
// Destination v must be a non-nil pointer.
func Unmarshal(data []byte, v any) error {
	dec := msgpack.GetDecoder()

	dec.UsePreallocateValues(true)
	resetDecoder(dec, bytes.NewReader(data))

	err := dec.Decode(v)

	msgpack.PutDecoder(dec)

	return err
}
