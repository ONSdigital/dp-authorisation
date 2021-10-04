// Code generated by moq; DO NOT EDIT.
// github.com/matryer/moq

package mock

import (
	"context"
	"github.com/ONSdigital/dp-authorisation/v2/permissions"
	"sync"
)

// Ensure, that StoreMock does implement permissions.Store.
// If this is not the case, regenerate this file with moq.
var _ permissions.Store = &StoreMock{}

// StoreMock is a mock implementation of permissions.Store.
//
//     func TestSomethingThatUsesStore(t *testing.T) {
//
//         // make and configure a mocked permissions.Store
//         mockedStore := &StoreMock{
//             GetPermissionsBundleFunc: func(ctx context.Context) (permissions.Bundle, error) {
// 	               panic("mock out the GetPermissionsBundle method")
//             },
//         }
//
//         // use mockedStore in code that requires permissions.Store
//         // and then make assertions.
//
//     }
type StoreMock struct {
	// GetPermissionsBundleFunc mocks the GetPermissionsBundle method.
	GetPermissionsBundleFunc func(ctx context.Context) (permissions.Bundle, error)

	// calls tracks calls to the methods.
	calls struct {
		// GetPermissionsBundle holds details about calls to the GetPermissionsBundle method.
		GetPermissionsBundle []struct {
			// Ctx is the ctx argument value.
			Ctx context.Context
		}
	}
	lockGetPermissionsBundle sync.RWMutex
}

// GetPermissionsBundle calls GetPermissionsBundleFunc.
func (mock *StoreMock) GetPermissionsBundle(ctx context.Context) (permissions.Bundle, error) {
	if mock.GetPermissionsBundleFunc == nil {
		panic("StoreMock.GetPermissionsBundleFunc: method is nil but Store.GetPermissionsBundle was just called")
	}
	callInfo := struct {
		Ctx context.Context
	}{
		Ctx: ctx,
	}
	mock.lockGetPermissionsBundle.Lock()
	mock.calls.GetPermissionsBundle = append(mock.calls.GetPermissionsBundle, callInfo)
	mock.lockGetPermissionsBundle.Unlock()
	return mock.GetPermissionsBundleFunc(ctx)
}

// GetPermissionsBundleCalls gets all the calls that were made to GetPermissionsBundle.
// Check the length with:
//     len(mockedStore.GetPermissionsBundleCalls())
func (mock *StoreMock) GetPermissionsBundleCalls() []struct {
	Ctx context.Context
} {
	var calls []struct {
		Ctx context.Context
	}
	mock.lockGetPermissionsBundle.RLock()
	calls = mock.calls.GetPermissionsBundle
	mock.lockGetPermissionsBundle.RUnlock()
	return calls
}
