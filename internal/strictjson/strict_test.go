package strictjson

import "testing"

func TestLossless(t *testing.T) {
	for _, s := range []string{`{"text":"Привет 🌿"}`, `{"text":"\ud83c\udf3f"}`, `{"text":"\\ud800"}`, `[{"v":null},1,true]`} {
		if !Valid([]byte(s)) {
			t.Errorf("rejected valid JSON: %s", s)
		}
	}
	for _, s := range []string{`{"text":"\ud800"}`, `{"text":"\udc00"}`, `{"a":1,"\u0061":2}`, `{"x":{"a":1,"a":2}}`, "{\"x\":\"\xff\"}", `{} {}`, `{"text":"\ud800\u0041"}`} {
		if Valid([]byte(s)) {
			t.Errorf("accepted ambiguous JSON: %s", s)
		}
	}
}
func FuzzValid(f *testing.F) {
	f.Add([]byte(`{"x":"\ud800"}`))
	f.Add([]byte(`{"x":"😀"}`))
	f.Fuzz(func(t *testing.T, data []byte) { _ = Valid(data) })
}
