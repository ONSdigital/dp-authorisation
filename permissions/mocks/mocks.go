// mocks provide mock implementations for use in the permissions unit tests
package mocks

import (
	"context"
	"io"
	"net/http"
)

// ReadCloser is a mocked impl of an io.ReadCloser
type ReadCloser struct {
	GetEntityFunc func() ([]byte, error)
	done          bool
}

type HTTPClient struct {
	calls  []*http.Request
	DoFunc func() (*http.Response, error)
}

func (rc *ReadCloser) Read(p []byte) (n int, err error) {
	if rc.done {
		return 0, io.EOF
	}

	b, err := rc.GetEntityFunc()
	if err != nil {
		return 0, err
	}

	for i, b := range b {
		p[i] = b
	}
	rc.done = true
	return len(b), nil
}

func (rc *ReadCloser) Close() error {
	return nil
}

func (m *HTTPClient) Do(ctx context.Context, req *http.Request) (*http.Response, error) {
	m.calls = append(m.calls, req)
	return m.DoFunc()
}
