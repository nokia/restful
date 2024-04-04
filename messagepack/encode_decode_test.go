package messagepack

import (
	"encoding/json"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
)

type innerStruct struct {
	String string            `json:"string,omitempty"`
	Array  []byte            `json:"array"`
	Map    map[string]string `json:"map"`
	Number int               `json:"number,omitempty"`
}

type structType struct {
	Str    string      `json:"str,omitempty"`
	Struct innerStruct `json:"struct"`
}

var src = structType{Str: "hello", Struct: innerStruct{Number: 1, Array: []byte{1, 2, 3}}}

const parallelItes = 1000

func Test_MsgPack(t *testing.T) {
	bytes, err := Marshal(&src)
	assert.NoError(t, err)
	var dst structType
	assert.NoError(t, Unmarshal(bytes, &dst))
	assert.Equal(t, src, dst)
}

func Benchmark_MsgPack_Parallel(b *testing.B) {
	var wg sync.WaitGroup
	wg.Add(parallelItes)

	for i := 0; i < parallelItes; i++ {
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
	wg.Add(parallelItes)

	for i := 0; i < parallelItes; i++ {
		go func() {
			bytes, _ := json.Marshal(&src)
			var dst structType
			json.Unmarshal(bytes, &dst)
			wg.Done()
		}()
	}

	wg.Wait()
}
