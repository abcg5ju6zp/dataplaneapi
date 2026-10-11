// Copyright 2026 HAProxy Technologies
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

package api_users

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/require"

	config "github.com/haproxytech/dataplaneapi/configuration"
	"github.com/haproxytech/dataplaneapi/storage"
	"github.com/haproxytech/dataplaneapi/storagetype"
)

const testUUID = "3fa85f64-5717-4562-b3fc-2c963f66afa6"

type fakeStore struct {
	enabled    bool
	list       config.APIUsersView
	users      map[string]config.APIUserView
	commitErr  error
	commitRes  config.APIUserCommitResult
	commits    []config.APIUserCommitInput
	commitHook func(config.APIUserCommitInput) (config.APIUserCommitResult, error)
}

func (f *fakeStore) Enabled() bool { return f.enabled }

func (f *fakeStore) List() config.APIUsersView { return f.list }

func (f *fakeStore) Get(username string) (config.APIUserView, bool) {
	v, ok := f.users[username]
	return v, ok
}

func (f *fakeStore) Commit(in config.APIUserCommitInput) (config.APIUserCommitResult, error) {
	f.commits = append(f.commits, in)
	if f.commitHook != nil {
		return f.commitHook(in)
	}
	return f.commitRes, f.commitErr
}

func newTestRouter(t *testing.T, store Store) http.Handler {
	t.Helper()
	r := chi.NewRouter()
	require.NoError(t, RegisterRouter(r, store))
	return r
}

func enabledStore() *fakeStore {
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	return &fakeStore{
		enabled: true,
		list: config.APIUsersView{
			Generation: 2,
			Users: []config.APIUserView{
				{Username: "alice", Source: "managed"},
				{Username: "root", Source: "config"},
			},
			LastFailure: &config.APIUserFailureView{
				OperationID: "op-old", Phase: storagetype.PhasePersist,
				Message: "disk full", Generation: 1, Timestamp: now,
			},
		},
		users: map[string]config.APIUserView{
			"alice": {Username: "alice", Source: "managed"},
			"root":  {Username: "root", Source: "config"},
		},
	}
}

func doRequest(t *testing.T, handler http.Handler, method, target string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var reader io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		require.NoError(t, err)
		reader = bytes.NewReader(raw)
	}
	req := httptest.NewRequest(method, target, reader)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

func TestGetAPIUsers(t *testing.T) {
	store := enabledStore()
	rec := doRequest(t, newTestRouter(t, store), http.MethodGet, "/services/haproxy/api_users", nil)
	require.Equal(t, http.StatusOK, rec.Code)

	var out ApiUsers
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &out))
	require.Equal(t, int64(2), out.Generation)
	require.Len(t, out.Users, 2)
	require.Equal(t, "alice", out.Users[0].Username)
	require.Equal(t, Managed, out.Users[0].Source)
	require.Equal(t, "disk full", out.LastFailure.Message)
}

func TestGetOneAPIUser(t *testing.T) {
	store := enabledStore()
	router := newTestRouter(t, store)

	rec := doRequest(t, router, http.MethodGet, "/services/haproxy/api_users/alice", nil)
	require.Equal(t, http.StatusOK, rec.Code)
	var user ApiUser
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &user))
	require.Equal(t, "alice", user.Username)

	rec = doRequest(t, router, http.MethodGet, "/services/haproxy/api_users/ghost", nil)
	require.Equal(t, http.StatusNotFound, rec.Code)
}

func TestCreateAPIUser(t *testing.T) {
	store := enabledStore()
	store.commitRes = config.APIUserCommitResult{
		OperationID: testUUID, Kind: config.APIUserAdd, Username: "bob",
		Generation: 3, Status: config.StatusCommitted,
	}
	rec := doRequest(t, newTestRouter(t, store), http.MethodPost,
		"/services/haproxy/api_users?operation_id="+testUUID+"&generation=2",
		map[string]string{"username": "bob", "password": "secret"})
	require.Equal(t, http.StatusCreated, rec.Code, rec.Body.String())

	require.Len(t, store.commits, 1)
	require.Equal(t, "bob", store.commits[0].Username)
	require.Equal(t, "secret", store.commits[0].Password)
	require.Equal(t, uint64(2), store.commits[0].BaseGeneration)

	var op ApiUserOperation
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &op))
	require.Equal(t, Committed, op.Status)
	require.Equal(t, int64(3), op.Generation)
}

func TestDeleteAPIUser(t *testing.T) {
	store := enabledStore()
	store.commitRes = config.APIUserCommitResult{
		OperationID: testUUID, Kind: config.APIUserDelete, Username: "alice",
		Generation: 3, Status: config.StatusReplayed,
	}
	rec := doRequest(t, newTestRouter(t, store), http.MethodDelete,
		"/services/haproxy/api_users/alice?operation_id="+testUUID+"&generation=2", nil)
	require.Equal(t, http.StatusOK, rec.Code)
	require.Equal(t, config.APIUserDelete, store.commits[0].Kind)
	require.Equal(t, "alice", store.commits[0].Username)

	var op ApiUserOperation
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &op))
	require.Equal(t, Replayed, op.Status)
}

func TestReplaceAPIUserPassword(t *testing.T) {
	store := enabledStore()
	store.commitRes = config.APIUserCommitResult{
		OperationID: testUUID, Kind: config.APIUserRotate, Username: "alice",
		Generation: 3, Status: config.StatusCommitted,
	}
	rec := doRequest(t, newTestRouter(t, store), http.MethodPut,
		"/services/haproxy/api_users/alice/password?operation_id="+testUUID+"&generation=2",
		map[string]string{"password": "newsecret"})
	require.Equal(t, http.StatusOK, rec.Code)
	require.Equal(t, "newsecret", store.commits[0].Password)
	require.Equal(t, config.APIUserRotate, store.commits[0].Kind)
}

func TestCommitErrorStatusMapping(t *testing.T) {
	tests := []struct {
		name       string
		err        error
		wantStatus int
	}{
		{"not found", config.ErrManagedUserNotFound, http.StatusNotFound},
		{"stale generation", config.ErrStaleGeneration, http.StatusConflict},
		{"operation conflict", config.ErrOperationIDConflict, http.StatusConflict},
		{"user exists", config.ErrUserAlreadyExists, http.StatusConflict},
		{"config collision", config.ErrConfigUserCollision, http.StatusConflict},
		{"cannot manage config user", config.ErrCannotManageConfigUser, http.StatusConflict},
		{"persist error", &storage.PersistError{OperationID: "op", Err: io.ErrClosedPipe}, http.StatusServiceUnavailable},
		{"publish error", &config.PublishError{OperationID: "op", Err: io.ErrClosedPipe}, http.StatusInternalServerError},
		{"other", io.ErrClosedPipe, http.StatusInternalServerError},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := enabledStore()
			store.commitErr = tt.err
			rec := doRequest(t, newTestRouter(t, store), http.MethodPost,
				"/services/haproxy/api_users?operation_id="+testUUID+"&generation=2",
				map[string]string{"username": "bob", "password": "secret"})
			require.Equal(t, tt.wantStatus, rec.Code)
		})
	}
}

func TestDisabledDeployment(t *testing.T) {
	store := &fakeStore{enabled: false}
	router := newTestRouter(t, store)

	rec := doRequest(t, router, http.MethodGet, "/services/haproxy/api_users", nil)
	require.Equal(t, http.StatusServiceUnavailable, rec.Code)

	rec = doRequest(t, router, http.MethodPost,
		"/services/haproxy/api_users?operation_id="+testUUID+"&generation=0",
		map[string]string{"username": "bob", "password": "secret"})
	require.Equal(t, http.StatusServiceUnavailable, rec.Code)
}

func TestRequestValidation(t *testing.T) {
	store := enabledStore()
	router := newTestRouter(t, store)

	// missing operation_id and generation
	rec := doRequest(t, router, http.MethodPost,
		"/services/haproxy/api_users",
		map[string]string{"username": "bob", "password": "secret"})
	require.Equal(t, http.StatusBadRequest, rec.Code)

	// malformed operation id
	rec = doRequest(t, router, http.MethodPost,
		"/services/haproxy/api_users?operation_id=not-a-uuid&generation=0",
		map[string]string{"username": "bob", "password": "secret"})
	require.Equal(t, http.StatusBadRequest, rec.Code)

	// body schema violations (missing required field / minLength) are 422
	rec = doRequest(t, router, http.MethodPost,
		"/services/haproxy/api_users?operation_id="+testUUID+"&generation=0",
		map[string]string{"username": "bob"})
	require.Equal(t, http.StatusUnprocessableEntity, rec.Code)

	rec = doRequest(t, router, http.MethodPost,
		"/services/haproxy/api_users?operation_id="+testUUID+"&generation=0",
		map[string]string{"username": "bob", "password": ""})
	require.Equal(t, http.StatusUnprocessableEntity, rec.Code)

	// no commit reached the store through any rejected request
	require.Empty(t, store.commits)
}
