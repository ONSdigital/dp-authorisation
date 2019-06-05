package auth

import "net/http"

type ResponseWriterMoq struct {
	HeaderFunc       func() http.Header
	WriteCalls       []string
	WriteFunc        func([]byte) (int, error)
	WriteHeaderCalls []int
	WriteHeaderFunc  func(statusCode int)
}

func (w *ResponseWriterMoq) Header() http.Header {
	return w.HeaderFunc()
}

func (w *ResponseWriterMoq) Write(b []byte) (int, error) {
	w.WriteCalls = append(w.WriteCalls, string(b))
	return w.WriteFunc(b)
}

func (w *ResponseWriterMoq) WriteHeader(status int) {
	w.WriteHeaderCalls = append(w.WriteHeaderCalls, status)
	w.WriteHeaderFunc(status)
}
