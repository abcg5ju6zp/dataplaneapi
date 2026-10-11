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

package configuration

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	parser "github.com/haproxytech/client-native/v6/config-parser"
	"github.com/haproxytech/client-native/v6/config-parser/options"
	"github.com/haproxytech/client-native/v6/config-parser/types"
	native_misc "github.com/haproxytech/client-native/v6/misc"
	"github.com/haproxytech/dataplaneapi/storage"
	"github.com/haproxytech/dataplaneapi/storagetype"
)

// DependencyChecker is gate 4: it verifies the external resources the next
// restart needs (certificates, userlist source, writable directories).
// Failure semantics differ from field failures: the candidate is rolled back
// to the previous active generation instead of waiting on disk.
type DependencyChecker interface {
	Check(ctx context.Context, v *ValidatedCandidate) *GateError
}

type productionDependencyChecker struct{}

func NewProductionDependencyChecker() DependencyChecker {
	return &productionDependencyChecker{}
}

func (d *productionDependencyChecker) Check(ctx context.Context, v *ValidatedCandidate) *GateError {
	if err := d.checkListeners(ctx, v); err != nil {
		return err
	}
	if err := d.checkUsers(ctx, v); err != nil {
		return err
	}
	if err := d.checkDirectories(ctx, v); err != nil {
		return err
	}
	return nil
}

func (d *productionDependencyChecker) checkListeners(ctx context.Context, v *ValidatedCandidate) *GateError {
	if hasScheme(v.Listen.Schemes, schemeHTTPS) {
		if ctxDone(ctx) {
			return &GateError{Stage: GateDependency, Err: ctx.Err()}
		}
		// Exactly what server.Serve does: tls.LoadX509KeyPair parses the
		// certificate and matches the private key.
		if _, err := tls.LoadX509KeyPair(v.Listen.TLSCertificate, v.Listen.TLSKey); err != nil {
			return &GateError{Stage: GateDependency, Err: fmt.Errorf("cannot load TLS certificate/key: %w", err)}
		}
		if v.Listen.TLSCACertificate != "" {
			ca, err := os.ReadFile(v.Listen.TLSCACertificate)
			if err != nil {
				return &GateError{Stage: GateDependency, Err: fmt.Errorf("cannot read TLS CA certificate: %w", err)}
			}
			pool := x509.NewCertPool()
			if !pool.AppendCertsFromPEM(ca) {
				return &GateError{Stage: GateDependency, Err: errors.New("cannot parse TLS CA certificate")}
			}
		}
	}
	if hasScheme(v.Listen.Schemes, schemeUnix) && v.Listen.SocketPath != "" {
		if err := assertWritableDir(filepath.Dir(string(v.Listen.SocketPath))); err != nil {
			return &GateError{Stage: GateDependency, Err: fmt.Errorf("unix socket directory: %w", err)}
		}
	}
	return nil
}

func (d *productionDependencyChecker) checkUsers(ctx context.Context, v *ValidatedCandidate) *GateError {
	if ctxDone(ctx) {
		return &GateError{Stage: GateDependency, Err: ctx.Err()}
	}
	// Users defined in the candidate YAML were already field-validated.
	if len(v.Users) > 0 {
		return nil
	}
	// Dataplane-managed users persisted in cluster.json are merged ahead of
	// the userlist fallback (see Configuration.GetUsers / Users.Init).
	// cluster.json is read directly: the storage constructor treats an
	// unwritable directory as fatal, which must never happen from a gate.
	if v.Effective.DataplaneStorageDir != "" {
		clusterPath := filepath.Join(v.Effective.DataplaneStorageDir, storage.ClusterModeDataFileName)
		if data, err := os.ReadFile(clusterPath); err == nil {
			var cluster storagetype.ClusterModeData
			if json.Unmarshal(data, &cluster) == nil && len(cluster.Users) > 0 {
				return nil
			}
		}
	}
	filename := v.Effective.UserListFile
	if filename == "" {
		filename = v.Effective.ConfigFile
	}
	if _, err := os.Stat(filename); errors.Is(err, fs.ErrNotExist) {
		return &GateError{Stage: GateDependency, Err: fmt.Errorf("cannot read %s, file does not exist", filename)}
	}
	p, err := parser.New(options.Path(filename))
	if err != nil {
		return &GateError{Stage: GateDependency, Err: fmt.Errorf("cannot parse userlist source %s: %w", filename, err)}
	}
	data, err := p.Get(parser.UserList, v.Effective.Userlist, "user")
	if err != nil {
		return &GateError{Stage: GateDependency, Err: fmt.Errorf("no users configured in %s: %w", filename, err)}
	}
	users, ok := data.([]types.User)
	if !ok || len(users) == 0 {
		return &GateError{Stage: GateDependency, Err: fmt.Errorf("no users configured in %s", filename)}
	}
	return nil
}

func (d *productionDependencyChecker) checkDirectories(ctx context.Context, v *ValidatedCandidate) *GateError {
	dirs := []string{
		v.Effective.DataplaneStorageDir,
		v.Effective.MapsDir,
		v.Effective.SSLCertsDir,
		v.Effective.GeneralStorageDir,
		v.Effective.SpoeDir,
		v.Effective.SpoeTransactionDir,
		v.Effective.TransactionDir,
		v.Effective.BackupsDir,
	}
	for _, dir := range dirs {
		if ctxDone(ctx) {
			return &GateError{Stage: GateDependency, Err: ctx.Err()}
		}
		if dir == "" {
			continue
		}
		if err := assertWritableDir(dir); err != nil {
			return &GateError{Stage: GateDependency, Err: fmt.Errorf("required directory %s: %w", dir, err)}
		}
	}
	return nil
}

// assertWritableDir uses the same helper as production boot
// (initDataplaneStorage/storage init): missing directories are created, so a
// candidate that passes has paid the same idempotent cost a successful restart
// would pay.
func assertWritableDir(dir string) error {
	if _, err := native_misc.CheckOrCreateWritableDirectory(dir); err != nil {
		return err
	}
	return nil
}
