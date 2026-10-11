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

package aws

import (
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRequireWritable(t *testing.T) {
	t.Run("isolated returns 503", func(t *testing.T) {
		h := &HandlerImpl{Writable: func() bool { return false }}
		rec := httptest.NewRecorder()
		require.False(t, h.requireWritable(rec))
		require.Equal(t, 503, rec.Code)
	})
	t.Run("healthy passes", func(t *testing.T) {
		h := &HandlerImpl{Writable: func() bool { return true }}
		rec := httptest.NewRecorder()
		require.True(t, h.requireWritable(rec))
		require.Equal(t, 200, rec.Code)
	})
	t.Run("missing check defaults to writable", func(t *testing.T) {
		h := &HandlerImpl{}
		rec := httptest.NewRecorder()
		require.True(t, h.requireWritable(rec))
		require.Equal(t, 200, rec.Code)
	})
}
