// mocks provide mock implementations for use in the permissions unit tests
package mocks

import "io"

// ReadCloser is a mocked impl of an io.ReadCloser
type ReadCloser struct {
	GetEntityFunc  func() ([]byte, error)
	done       bool
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
