package authv2

import "net/http"

type HandlerMock struct {
	count int
}

func (h *HandlerMock) handleFunc(http.ResponseWriter, *http.Request) {
	h.count += 1
}
