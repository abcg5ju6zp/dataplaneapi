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
	"errors"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/haproxytech/client-native/v6/models"
	openapi_types "github.com/oapi-codegen/runtime/types"

	config "github.com/haproxytech/dataplaneapi/configuration"
	"github.com/haproxytech/dataplaneapi/handlers/middleware"
	"github.com/haproxytech/dataplaneapi/handlers/respond"
	"github.com/haproxytech/dataplaneapi/storage"
)

// Store is the subset of *configuration.Users used by these handlers.
type Store interface {
	Enabled() bool
	List() config.APIUsersView
	Get(username string) (config.APIUserView, bool)
	Commit(in config.APIUserCommitInput) (config.APIUserCommitResult, error)
}

// RegisterRouter registers all API user management routes onto r using
// spec-based request validation.
func RegisterRouter(r chi.Router, store Store) error {
	spec, err := GetSpec()
	if err != nil {
		return err
	}
	HandlerWithOptions(&HandlerImpl{Store: store}, ChiServerOptions{
		BaseRouter:       r,
		Middlewares:      []MiddlewareFunc{middleware.NewValidator(spec)},
		ErrorHandlerFunc: middleware.ErrorHandler,
	})
	return nil
}

// HandlerImpl implements ServerInterface for API user management.
type HandlerImpl struct {
	Store Store
}

func (h *HandlerImpl) GetAPIUsers(w http.ResponseWriter, r *http.Request) {
	if !h.requireEnabled(w) {
		return
	}
	view := h.Store.List()
	respond.JSON(w, http.StatusOK, toAPIUsers(view))
}

func (h *HandlerImpl) GetOneAPIUser(w http.ResponseWriter, r *http.Request, username string) {
	if !h.requireEnabled(w) {
		return
	}
	user, ok := h.Store.Get(username)
	if !ok {
		respond.JSON(w, http.StatusNotFound, errorModel(http.StatusNotFound, "user not found"))
		return
	}
	respond.JSON(w, http.StatusOK, toAPIUser(user))
}

func (h *HandlerImpl) CreateAPIUser(w http.ResponseWriter, r *http.Request, params CreateAPIUserParams) {
	if !h.requireEnabled(w) {
		return
	}
	var body CreateAPIUserJSONRequestBody
	if !respond.DecodeJSON(r, w, &body) {
		return
	}
	result, err := h.Store.Commit(config.APIUserCommitInput{
		OperationID:    params.OperationId.String(),
		Kind:           config.APIUserAdd,
		Username:       body.Username,
		Password:       body.Password,
		BaseGeneration: uint64(params.Generation),
	})
	if err != nil {
		writeCommitError(w, err)
		return
	}
	respond.JSON(w, http.StatusCreated, toOperation(params.OperationId, result))
}

func (h *HandlerImpl) DeleteAPIUser(w http.ResponseWriter, r *http.Request, username string, params DeleteAPIUserParams) {
	if !h.requireEnabled(w) {
		return
	}
	result, err := h.Store.Commit(config.APIUserCommitInput{
		OperationID:    params.OperationId.String(),
		Kind:           config.APIUserDelete,
		Username:       username,
		BaseGeneration: uint64(params.Generation),
	})
	if err != nil {
		writeCommitError(w, err)
		return
	}
	respond.JSON(w, http.StatusOK, toOperation(params.OperationId, result))
}

func (h *HandlerImpl) ReplaceAPIUserPassword(w http.ResponseWriter, r *http.Request, username string, params ReplaceAPIUserPasswordParams) {
	if !h.requireEnabled(w) {
		return
	}
	var body ReplaceAPIUserPasswordJSONRequestBody
	if !respond.DecodeJSON(r, w, &body) {
		return
	}
	result, err := h.Store.Commit(config.APIUserCommitInput{
		OperationID:    params.OperationId.String(),
		Kind:           config.APIUserRotate,
		Username:       username,
		Password:       body.Password,
		BaseGeneration: uint64(params.Generation),
	})
	if err != nil {
		writeCommitError(w, err)
		return
	}
	respond.JSON(w, http.StatusOK, toOperation(params.OperationId, result))
}

func (h *HandlerImpl) requireEnabled(w http.ResponseWriter) bool {
	if h.Store != nil && h.Store.Enabled() {
		return true
	}
	writeCommitError(w, config.ErrAPIUsersDisabled)
	return false
}

func toAPIUsers(view config.APIUsersView) ApiUsers {
	out := ApiUsers{
		Generation: int64(view.Generation),
		Users:      make([]ApiUser, 0, len(view.Users)),
	}
	for _, user := range view.Users {
		out.Users = append(out.Users, toAPIUser(user))
	}
	if view.LastFailure != nil {
		out.LastFailure = toLastFailure(view.LastFailure)
	}
	return out
}

func toAPIUser(user config.APIUserView) ApiUser {
	source := Config
	if user.Source == "managed" {
		source = Managed
	}
	return ApiUser{Username: user.Username, Source: source}
}

func toLastFailure(failure *config.APIUserFailureView) ApiUserLastFailure {
	return ApiUserLastFailure{
		OperationId: failure.OperationID,
		Phase:       ApiUserLastFailurePhase(failure.Phase),
		Message:     failure.Message,
		Generation:  int64(failure.Generation),
		Timestamp:   failure.Timestamp,
	}
}

func toOperation(operationID openapi_types.UUID, result config.APIUserCommitResult) ApiUserOperation {
	status := Replayed
	if result.Status == config.StatusCommitted {
		status = Committed
	}
	return ApiUserOperation{
		OperationId: operationID,
		Generation:  int64(result.Generation),
		Status:      status,
		Username:    result.Username,
	}
}

// writeCommitError maps the commit layer's sentinel errors to HTTP status
// codes. Error messages only ever carry operation id, username, generation and
// OS errors — never passwords or hashes.
func writeCommitError(w http.ResponseWriter, err error) {
	var (
		persistErr *storage.PersistError
		publishErr *config.PublishError
	)
	switch {
	case errors.Is(err, config.ErrManagedUserNotFound):
		respond.JSON(w, http.StatusNotFound, errorModel(http.StatusNotFound, err.Error()))
	case errors.Is(err, config.ErrStaleGeneration),
		errors.Is(err, config.ErrOperationIDConflict),
		errors.Is(err, config.ErrUserAlreadyExists),
		errors.Is(err, config.ErrConfigUserCollision),
		errors.Is(err, config.ErrCannotManageConfigUser):
		respond.JSON(w, http.StatusConflict, errorModel(http.StatusConflict, err.Error()))
	case errors.Is(err, config.ErrAPIUsersDisabled):
		respond.JSON(w, http.StatusServiceUnavailable, errorModel(http.StatusServiceUnavailable, err.Error()))
	case errors.As(err, &persistErr):
		// The old snapshot keeps serving; the same operation is safe to retry.
		respond.JSON(w, http.StatusServiceUnavailable, errorModel(http.StatusServiceUnavailable, err.Error()))
	case errors.As(err, &publishErr):
		respond.JSON(w, http.StatusInternalServerError, errorModel(http.StatusInternalServerError, err.Error()))
	default:
		respond.JSON(w, http.StatusInternalServerError, errorModel(http.StatusInternalServerError, err.Error()))
	}
}

func errorModel(code int64, message string) *models.Error {
	return &models.Error{Code: &code, Message: &message}
}
