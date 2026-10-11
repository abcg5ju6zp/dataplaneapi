// Copyright 2019 HAProxy Technologies
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

package configuration

import (
	"crypto/subtle"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/GehirnInc/crypt"
	_ "github.com/GehirnInc/crypt/sha512_crypt" // register SHA-512 crypt used to hash API user passwords
	api_errors "github.com/go-openapi/errors"
	parser "github.com/haproxytech/client-native/v6/config-parser"
	"github.com/haproxytech/client-native/v6/config-parser/options"
	"github.com/haproxytech/client-native/v6/config-parser/types"

	"github.com/haproxytech/dataplaneapi/misc"
	"github.com/haproxytech/dataplaneapi/storage"
	"github.com/haproxytech/dataplaneapi/storagetype"
)

// mockPass is checked for unknown users so that failing logins cost the same
// crypt work whether the user exists or not (no user enumeration by timing).
// It must use a scheme checkPassword verifies: SHA-512 crypt, 5000 rounds.
const mockPass = "$6$dpapimocksalt$FSE7SwigtSN4i6osmN/I33cU2morawJ5dN9MTzCvyG29Ri7J4uc5tmxFmYCLMz8uH19sKNHo4A4k4dWF2SVky0"

var usersStore *Users

var syncUserStore sync.Once

// authSnapshot is an immutable view of everything authentication needs for a
// single published user-set generation. It is built wholesale and published
// with a single atomic store, so concurrent authentication requests observe
// either the complete previous generation or the complete next one, never a
// slice being modified.
type authSnapshot struct {
	generation uint64
	// users is the merged managed+config-file user list used by authentication.
	users []types.User
	// managed are the dataplane-storage users materializing generation.
	managed []storagetype.User
	// overlay are users coming from the configuration file / CLI / HAProxy
	// userlist; they can never be modified through the API.
	overlay     []types.User
	configNames map[string]struct{}
}

// Users is the process-wide API user store. Mutations go through Commit's
// persist-then-publish pipeline; reads (authentication) are lock-free through
// current.
type Users struct {
	// storage is nil in deployments without dataplane storage loaded, where
	// API user management endpoints stay disabled.
	storage storage.ClusterModeStorage

	// commitMu serializes user changes, snapshot repairs and config overlay
	// reloads.
	commitMu sync.Mutex

	current     atomic.Pointer[authSnapshot]
	lastFailure atomic.Pointer[APIUserFailureView]

	now func() time.Time

	// hooks exists for tests that need to simulate the process window between
	// a durable write and snapshot publication.
	hooks commitHooks
}

type commitHooks struct {
	// afterDurablePersist runs after the change was durably written but
	// before the active snapshot is published. Returning an error simulates a
	// persisted-but-unpublished generation. Hook errors must never contain
	// passwords or hashes.
	afterDurablePersist func(next storagetype.ClusterModeData) error
}

func GetUsersStore() *Users {
	syncUserStore.Do(func() {
		usersStore = &Users{
			now: func() time.Time { return time.Now().UTC() },
		}
	})
	return usersStore
}

// Init (re)builds the active snapshot: durable managed users (reconciled with
// the persisted journal at startup) merged over users from the configuration
// file, CLI flags or the HAProxy userlist section, preserving the historical
// fallback order.
func (u *Users) Init() error {
	cfg := Get()
	st := cfg.GetClusterModeStorage()

	u.commitMu.Lock()
	defer u.commitMu.Unlock()

	u.storage = st

	var (
		managed    storagetype.Users
		generation uint64
	)
	if st != nil {
		data, err := st.Reconcile()
		if err != nil {
			// Non-fatal: the normalized in-memory data is returned and auth
			// still works; the next successful commit converges the file.
			apiErr := u.failureView("", storagetype.PhaseReconcile, data.Generation, err)
			u.lastFailure.Store(&apiErr)
		} else if data.LastFailure != nil {
			view := failureViewFromRecord(data.LastFailure)
			u.lastFailure.Store(&view)
		}
		managed = data.Users
		generation = data.Generation
	}

	overlay, err := u.buildConfigOverlay(cfg, managed)
	if err != nil {
		return err
	}
	u.current.Store(buildSnapshot(generation, managed, overlay))
	return nil
}

// ReloadOverlay re-reads users from the configuration sources (SIGUSR2 /
// inotify) without touching durable state: the managed set, generation and
// journal stay untouched, only the config overlay is republished.
func (u *Users) ReloadOverlay() error {
	cfg := Get()

	u.commitMu.Lock()
	defer u.commitMu.Unlock()

	snap := u.current.Load()
	var (
		managed    storagetype.Users
		generation uint64
	)
	if snap != nil {
		managed = snap.managed
		generation = snap.generation
	}

	overlay, err := u.buildConfigOverlay(cfg, managed)
	if err != nil {
		return err
	}
	u.current.Store(buildSnapshot(generation, managed, overlay))
	return nil
}

// buildConfigOverlay preserves the historical source selection: managed users
// or --user/configuration-file users win over the HAProxy userlist section;
// the userlist is only parsed when neither is configured.
func (u *Users) buildConfigOverlay(cfg *Configuration, managed storagetype.Users) ([]types.User, error) {
	if len(managed) > 0 || len(cfg.Users) > 0 {
		return configUsers(cfg.Users), nil
	}
	if cfg.HAProxy.UserListFile != "" {
		return u.usersFromUsersListSection(cfg.HAProxy.UserListFile, cfg.HAProxy.Userlist)
	}
	return u.usersFromUsersListSection(cfg.HAProxy.ConfigFile, cfg.HAProxy.Userlist)
}

func configUsers(users []User) []types.User {
	out := make([]types.User, 0, len(users))
	for _, cu := range users {
		out = append(out, types.User{
			Name:       cu.Name,
			Password:   cu.Password,
			IsInsecure: cu.Insecure,
		})
	}
	return out
}

func (u *Users) usersFromUsersListSection(filename, userlistSection string) ([]types.User, error) {
	// if file doesn't exists
	if _, err := os.Stat(filename); errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("cannot read %s, file does not exist", filename)
	}
	p, errP := parser.New(options.Path(filename))
	if errP != nil {
		return nil, errP
	}
	data, err := p.Get(parser.UserList, userlistSection, "user")
	if err != nil {
		return nil, fmt.Errorf("no users configured in %v, error: %w", filename, err)
	}
	if data == nil {
		return nil, fmt.Errorf("no users configured in %s", filename)
	}
	users, ok := data.([]types.User)
	if !ok {
		return nil, fmt.Errorf("error reading users from %s", filename)
	}
	if len(users) == 0 {
		return nil, fmt.Errorf("no users configured in %s", filename)
	}
	return users, nil
}

// buildSnapshot merges managed users first and appends config users only when
// the name is not already managed, matching the previous GetUsers() precedence
// (storage users win on collision).
func buildSnapshot(generation uint64, managed storagetype.Users, overlay []types.User) *authSnapshot {
	snap := &authSnapshot{
		generation:  generation,
		overlay:     overlay,
		configNames: make(map[string]struct{}, len(overlay)),
	}
	for _, storageUser := range managed {
		user := types.User{Name: storageUser.Name}
		if storageUser.Password != nil {
			user.Password = *storageUser.Password
		}
		if storageUser.Insecure != nil {
			user.IsInsecure = *storageUser.Insecure
		}
		snap.managed = append(snap.managed, storageUser)
		snap.users = append(snap.users, user)
	}
	for _, cfgUser := range overlay {
		snap.configNames[cfgUser.Name] = struct{}{}
		if managedUserByName(snap.managed, cfgUser.Name) != nil {
			continue
		}
		snap.users = append(snap.users, cfgUser)
	}
	return snap
}

func (u *Users) publish(generation uint64, managed storagetype.Users, previous *authSnapshot) {
	var overlay []types.User
	if previous != nil {
		overlay = previous.overlay
	}
	u.current.Store(buildSnapshot(generation, managed, overlay))
}

func managedUserByName(users storagetype.Users, name string) *storagetype.User {
	for i := range users {
		if users[i].Name == name {
			return &users[i]
		}
	}
	return nil
}

// findUser searches user by its name. If found, returns user, otherwise returns an error.
func findUser(userName string, users []types.User) (*types.User, error) {
	for _, u := range users {
		if u.Name == userName {
			return &u, nil
		}
	}
	return nil, api_errors.New(401, "no configured users")
}

func AuthenticateUser(user string, pass string) (any, error) {
	snap := GetUsersStore().current.Load()
	if snap == nil || len(snap.users) == 0 {
		return nil, api_errors.New(http.StatusUnauthorized, "no configured users")
	}
	users := snap.users

	unatuhorized := false
	u, err := findUser(user, users)
	if err != nil {
		unatuhorized = true
	}

	userPass := mockPass
	if u != nil {
		userPass = u.Password
	}

	if strings.HasPrefix(userPass, "\"${") && strings.HasSuffix(userPass, "}\"") {
		userPass = os.Getenv(misc.ExtractEnvVar(userPass))
		if userPass == "" {
			unatuhorized = true
			userPass = mockPass
		}
	}

	if u != nil && u.IsInsecure {
		if subtle.ConstantTimeCompare([]byte(pass), []byte(userPass)) != 1 {
			unatuhorized = true
		}
	} else {
		if !checkPassword(pass, userPass) {
			unatuhorized = true
		}
	}
	if unatuhorized {
		return nil, api_errors.New(http.StatusUnauthorized, "unauthorized")
	}
	return user, nil
}

func checkPassword(pass, storedPass string) bool {
	parts := strings.Split(storedPass, "$")
	if len(parts) == 4 {
		var c crypt.Crypter
		switch parts[1] {
		case "1":
			c = crypt.MD5.New()
		case "5":
			c = crypt.SHA256.New()
		case "6":
			c = crypt.SHA512.New()
		default:
			return false
		}
		if err := c.Verify(storedPass, []byte(pass)); err == nil {
			return true
		}
	}

	return false
}
