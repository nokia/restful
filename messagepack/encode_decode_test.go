package messagepack

import (
	"encoding/json"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
)

type innerStruct struct {
	String string            `json:"str,omitempty"`
	Array  []byte            `json:"arr"`
	Map    map[string]string `json:"map"`
	Number int               `json:"num,omitempty"`
}

type structType struct {
	Str    string      `json:"str,omitempty"`
	Struct innerStruct `json:"struct"`
}

var src = structType{Str: "hello", Struct: innerStruct{Number: 1, Array: []byte{1, 2, 3}}}

const parallelIters = 1000

func Test_MsgPack(t *testing.T) {
	bytes, err := Marshal(&src)
	assert.NoError(t, err)
	assert.Equal(t, 38, len(bytes))
	var dst structType
	assert.NoError(t, Unmarshal(bytes, &dst))
	assert.Equal(t, src, dst)
}

func Benchmark_MsgPack_Parallel(b *testing.B) {
	var wg sync.WaitGroup
	wg.Add(parallelIters)

	for i := 0; i < parallelIters; i++ {
		go func() {
			bytes, _ := Marshal(&src)
			var dst structType
			Unmarshal(bytes, &dst)
			wg.Done()
		}()
	}

	wg.Wait()
}

func Benchmark_Json(b *testing.B) {
	var wg sync.WaitGroup
	wg.Add(parallelIters)

	for i := 0; i < parallelIters; i++ {
		go func() {
			bytes, _ := json.Marshal(&src)
			var dst structType
			json.Unmarshal(bytes, &dst)
			wg.Done()
		}()
	}

	wg.Wait()
}
