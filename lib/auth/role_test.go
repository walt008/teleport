/*
Copyright 2015-2020 Gravitational, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package auth

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strconv"
	"testing"
	"time"

	"github.com/gravitational/teleport"
	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/teleport/lib/defaults"
	"github.com/gravitational/teleport/lib/utils"

	"github.com/gravitational/trace"

	"github.com/pborman/uuid"
	"github.com/stretchr/testify/require"
	"gopkg.in/check.v1"
)

// TestConnAndSessLimits verifies that role sets correctly calculate
// a user's MaxConnections and MaxSessions values from multiple
// roles with different individual values.  These are tested together since
// both values use the same resolution rules.
func TestConnAndSessLimits(t *testing.T) {
	utils.InitLoggerForTests(testing.Verbose())
	tts := []struct {
		desc string
		vals []int64
		want int64
	}{
		{
			desc: "smallest nonzero value is selected from mixed values",
			vals: []int64{8, 6, 7, 5, 3, 0, 9},
			want: 3,
		},
		{
			desc: "smallest value selected from all nonzero values",
			vals: []int64{5, 6, 7, 8},
			want: 5,
		},
		{
			desc: "all zero values results in a zero value",
			vals: []int64{0, 0, 0, 0, 0, 0, 0},
			want: 0,
		},
	}
	for ti, tt := range tts {
		cmt := fmt.Sprintf("test case %d: %s", ti, tt.desc)
		var set RoleSet
		for i, val := range tt.vals {
			role := &types.RoleV3{
				Kind:    types.KindRole,
				Version: types.V3,
				Metadata: types.Metadata{
					Name:      fmt.Sprintf("role-%d", i),
					Namespace: defaults.Namespace,
				},
				Spec: types.RoleSpecV3{
					Options: types.RoleOptions{
						MaxConnections: val,
						MaxSessions:    val,
					},
				},
			}
			require.NoError(t, role.CheckAndSetDefaults(), cmt)
			set = append(set, role)
		}
		require.Equal(t, tt.want, set.MaxConnections(), cmt)
		require.Equal(t, tt.want, set.MaxSessions(), cmt)
	}
}

func TestValidateRole(t *testing.T) {
	var tests = []struct {
		name         string
		spec         types.RoleSpecV3
		err          error
		matchMessage string
	}{
		{
			name: "valid syntax",
			spec: types.RoleSpecV3{
				Allow: types.RoleConditions{
					Logins: []string{`{{external["http://schemas.microsoft.com/ws/2008/06/identity/claims/windowsaccountname"]}}`},
				},
			},
		},
		{
			name: "invalid role condition login syntax",
			spec: types.RoleSpecV3{
				Allow: types.RoleConditions{
					Logins: []string{"{{foo"},
				},
			},
			err:          trace.BadParameter(""),
			matchMessage: "invalid login found",
		},
		{
			name: "unsupported function in actions",
			spec: types.RoleSpecV3{
				Allow: types.RoleConditions{
					Logins: []string{`{{external["http://schemas.microsoft.com/ws/2008/06/identity/claims/windowsaccountname"]}}`},
					Rules: []types.Rule{
						{
							Resources: []string{"role"},
							Verbs:     []string{"read", "list"},
							Where:     "containz(user.spec.traits[\"groups\"], \"prod\")",
						},
					},
				},
			},
			err:          trace.BadParameter(""),
			matchMessage: "unsupported function: containz",
		},
		{
			name: "unsupported function in where",
			spec: types.RoleSpecV3{
				Allow: types.RoleConditions{
					Logins: []string{`{{external["http://schemas.microsoft.com/ws/2008/06/identity/claims/windowsaccountname"]}}`},
					Rules: []types.Rule{
						{
							Resources: []string{"role"},
							Verbs:     []string{"read", "list"},
							Where:     "contains(user.spec.traits[\"groups\"], \"prod\")",
							Actions:   []string{"zzz(\"info\", \"log entry\")"},
						},
					},
				},
			},
			err:          trace.BadParameter(""),
			matchMessage: "unsupported function: zzz",
		},
	}

	for _, tc := range tests {
		err := ValidateRole(&types.RoleV3{
			Metadata: types.Metadata{
				Name:      "name1",
				Namespace: defaults.Namespace,
			},
			Spec: tc.spec,
		})
		if tc.err != nil {
			require.Error(t, err, tc.name)
			if tc.matchMessage != "" {
				require.Contains(t, err.Error(), tc.matchMessage)
			}
		} else {
			require.NoError(t, err, tc.name)
		}
	}
}

// TestLabelCompatibility makes sure that labels
// are serialized in format understood by older servers with
// scalar labels
func TestLabelCompatibility(t *testing.T) {
	labels := types.Labels{
		"key": []string{"val"},
	}
	data, err := json.Marshal(labels)
	require.NoError(t, err)

	var out map[string]string
	err = json.Unmarshal(data, &out)
	require.NoError(t, err)
	require.Equal(t, map[string]string{"key": "val"}, out)
}

func TestCheckAccessToServer(t *testing.T) {
	type check struct {
		server    types.Server
		hasAccess bool
		login     string
	}
	serverNoLabels := &types.ServerV2{
		Metadata: types.Metadata{
			Name: "a",
		},
	}
	serverWorker := &types.ServerV2{
		Metadata: types.Metadata{
			Name:      "b",
			Namespace: defaults.Namespace,
			Labels:    map[string]string{"role": "worker", "status": "follower"},
		},
	}
	namespaceC := "namespace-c"
	serverDB := &types.ServerV2{
		Metadata: types.Metadata{
			Name:      "c",
			Namespace: namespaceC,
			Labels:    map[string]string{"role": "db", "status": "follower"},
		},
	}
	serverDBWithSuffix := &types.ServerV2{
		Metadata: types.Metadata{
			Name:      "c2",
			Namespace: namespaceC,
			Labels:    map[string]string{"role": "db01", "status": "follower01"},
		},
	}
	testCases := []struct {
		name        string
		roles       []types.RoleV3
		checks      []check
		mfaVerified bool
	}{
		{
			name:  "empty role set has access to nothing",
			roles: []types.RoleV3{},
			checks: []check{
				{server: serverNoLabels, login: "root", hasAccess: false},
				{server: serverWorker, login: "root", hasAccess: false},
				{server: serverDB, login: "root", hasAccess: false},
			},
		},
		{
			name: "role is limited to default namespace",
			roles: []types.RoleV3{
				{
					Metadata: types.Metadata{
						Name:      "name1",
						Namespace: defaults.Namespace,
					},
					Spec: types.RoleSpecV3{
						Options: types.RoleOptions{
							MaxSessionTTL: types.Duration(20 * time.Hour),
						},
						Allow: types.RoleConditions{
							Namespaces: []string{defaults.Namespace},
							Logins:     []string{"admin"},
							NodeLabels: types.Labels{types.Wildcard: []string{types.Wildcard}},
						},
					},
				},
			},
			checks: []check{
				{server: serverNoLabels, login: "root", hasAccess: false},
				{server: serverNoLabels, login: "admin", hasAccess: true},
				{server: serverWorker, login: "root", hasAccess: false},
				{server: serverWorker, login: "admin", hasAccess: true},
				{server: serverDB, login: "root", hasAccess: false},
				{server: serverDB, login: "admin", hasAccess: false},
			},
		},
		{
			name: "role is limited to labels in default namespace",
			roles: []types.RoleV3{
				{
					Metadata: types.Metadata{
						Name:      "name1",
						Namespace: defaults.Namespace,
					},
					Spec: types.RoleSpecV3{
						Options: types.RoleOptions{
							MaxSessionTTL: types.Duration(20 * time.Hour),
						},
						Allow: types.RoleConditions{
							Logins:     []string{"admin"},
							NodeLabels: types.Labels{"role": []string{"worker"}},
							Namespaces: []string{defaults.Namespace},
						},
					},
				},
			},
			checks: []check{
				{server: serverNoLabels, login: "root", hasAccess: false},
				{server: serverNoLabels, login: "admin", hasAccess: false},
				{server: serverWorker, login: "root", hasAccess: false},
				{server: serverWorker, login: "admin", hasAccess: true},
				{server: serverDB, login: "root", hasAccess: false},
				{server: serverDB, login: "admin", hasAccess: false},
			},
		},
		{
			name: "role matches any label out of multiple labels",
			roles: []types.RoleV3{
				{
					Metadata: types.Metadata{
						Name:      "name1",
						Namespace: defaults.Namespace,
					},
					Spec: types.RoleSpecV3{
						Options: types.RoleOptions{
							MaxSessionTTL: types.Duration(20 * time.Hour),
						},
						Allow: types.RoleConditions{
							Logins:     []string{"admin"},
							NodeLabels: types.Labels{"role": []string{"worker2", "worker"}},
							Namespaces: []string{defaults.Namespace},
						},
					},
				},
			},
			checks: []check{
				{server: serverNoLabels, login: "root", hasAccess: false},
				{server: serverNoLabels, login: "admin", hasAccess: false},
				{server: serverWorker, login: "root", hasAccess: false},
				{server: serverWorker, login: "admin", hasAccess: true},
				{server: serverDB, login: "root", hasAccess: false},
				{server: serverDB, login: "admin", hasAccess: false},
			},
		},
		{
			name: "node_labels with empty list value matches nothing",
			roles: []types.RoleV3{
				{
					Metadata: types.Metadata{
						Name:      "name1",
						Namespace: defaults.Namespace,
					},
					Spec: types.RoleSpecV3{
						Options: types.RoleOptions{
							MaxSessionTTL: types.Duration(20 * time.Hour),
						},
						Allow: types.RoleConditions{
							Logins:     []string{"admin"},
							NodeLabels: types.Labels{"role": []string{}},
							Namespaces: []string{defaults.Namespace},
						},
					},
				},
			},
			checks: []check{
				{server: serverNoLabels, login: "root", hasAccess: false},
				{server: serverNoLabels, login: "admin", hasAccess: false},
				{server: serverWorker, login: "root", hasAccess: false},
				{server: serverWorker, login: "admin", hasAccess: false},
				{server: serverDB, login: "root", hasAccess: false},
				{server: serverDB, login: "admin", hasAccess: false},
			},
		},
		{
			name: "one role is more permissive than another",
			roles: []types.RoleV3{
				{
					Metadata: types.Metadata{
						Name:      "name1",
						Namespace: defaults.Namespace,
					},
					Spec: types.RoleSpecV3{
						Options: types.RoleOptions{
							MaxSessionTTL: types.Duration(20 * time.Hour),
						},
						Allow: types.RoleConditions{
							Logins:     []string{"admin"},
							NodeLabels: types.Labels{"role": []string{"worker"}},
							Namespaces: []string{defaults.Namespace},
						},
					},
				},
				{
					Metadata: types.Metadata{
						Name:      "name1",
						Namespace: defaults.Namespace,
					},
					Spec: types.RoleSpecV3{
						Options: types.RoleOptions{
							MaxSessionTTL: types.Duration(20 * time.Hour),
						},
						Allow: types.RoleConditions{
							Logins:     []string{"root", "admin"},
							NodeLabels: types.Labels{types.Wildcard: []string{types.Wildcard}},
							Namespaces: []string{types.Wildcard},
						},
					},
				},
			},
			checks: []check{
				{server: serverNoLabels, login: "root", hasAccess: true},
				{server: serverNoLabels, login: "admin", hasAccess: true},
				{server: serverWorker, login: "root", hasAccess: true},
				{server: serverWorker, login: "admin", hasAccess: true},
				{server: serverDB, login: "root", hasAccess: true},
				{server: serverDB, login: "admin", hasAccess: true},
			},
		},
		{
			name: "one role needs to access servers sharing the partially same label value",
			roles: []types.RoleV3{
				{
					Metadata: types.Metadata{
						Name:      "name1",
						Namespace: namespaceC,
					},
					Spec: types.RoleSpecV3{
						Options: types.RoleOptions{
							MaxSessionTTL: types.Duration(20 * time.Hour),
						},
						Allow: types.RoleConditions{
							Logins:     []string{"admin"},
							NodeLabels: types.Labels{"role": []string{"^db(.*)$"}, "status": []string{"follow*"}},
							Namespaces: []string{namespaceC},
						},
					},
				},
			},
			checks: []check{
				{server: serverNoLabels, login: "root", hasAccess: false},
				{server: serverNoLabels, login: "admin", hasAccess: false},
				{server: serverWorker, login: "root", hasAccess: false},
				{server: serverWorker, login: "admin", hasAccess: false},
				{server: serverDB, login: "root", hasAccess: false},
				{server: serverDB, login: "admin", hasAccess: true},
				{server: serverDBWithSuffix, login: "root", hasAccess: false},
				{server: serverDBWithSuffix, login: "admin", hasAccess: true},
			},
		},
		{
			name: "no logins means no access",
			roles: []types.RoleV3{
				{
					Metadata: types.Metadata{
						Name:      "somerole",
						Namespace: defaults.Namespace,
					},
					Spec: types.RoleSpecV3{
						Options: types.RoleOptions{
							MaxSessionTTL: types.Duration(20 * time.Hour),
						},
						Allow: types.RoleConditions{
							Logins:     nil,
							NodeLabels: types.Labels{types.Wildcard: []string{types.Wildcard}},
							Namespaces: []string{types.Wildcard},
						},
					},
				},
			},
			checks: []check{
				{server: serverNoLabels, login: "root", hasAccess: false},
				{server: serverNoLabels, login: "admin", hasAccess: false},
				{server: serverWorker, login: "root", hasAccess: false},
				{server: serverWorker, login: "admin", hasAccess: false},
				{server: serverDB, login: "root", hasAccess: false},
				{server: serverDB, login: "admin", hasAccess: false},
			},
		},
		{
			name: "one role requires MFA but MFA was not verified",
			roles: []types.RoleV3{
				{
					Metadata: types.Metadata{
						Name:      "name1",
						Namespace: defaults.Namespace,
					},
					Spec: types.RoleSpecV3{
						Options: types.RoleOptions{
							MaxSessionTTL:     types.Duration(20 * time.Hour),
							RequireSessionMFA: true,
						},
						Allow: types.RoleConditions{
							Logins:     []string{"root"},
							NodeLabels: types.Labels{"role": []string{"worker"}},
							Namespaces: []string{types.Wildcard},
						},
					},
				},
				{
					Metadata: types.Metadata{
						Name:      "name1",
						Namespace: defaults.Namespace,
					},
					Spec: types.RoleSpecV3{
						Options: types.RoleOptions{
							MaxSessionTTL: types.Duration(20 * time.Hour),
						},
						Allow: types.RoleConditions{
							Logins:     []string{"root"},
							NodeLabels: types.Labels{types.Wildcard: []string{types.Wildcard}},
							Namespaces: []string{types.Wildcard},
						},
					},
				},
			},
			mfaVerified: false,
			checks: []check{
				{server: serverNoLabels, login: "root", hasAccess: true},
				{server: serverWorker, login: "root", hasAccess: false},
				{server: serverDB, login: "root", hasAccess: true},
			},
		},
		{
			name: "one role requires MFA and MFA was verified",
			roles: []types.RoleV3{
				{
					Metadata: types.Metadata{
						Name:      "name1",
						Namespace: defaults.Namespace,
					},
					Spec: types.RoleSpecV3{
						Options: types.RoleOptions{
							MaxSessionTTL:     types.Duration(20 * time.Hour),
							RequireSessionMFA: true,
						},
						Allow: types.RoleConditions{
							Logins:     []string{"root"},
							NodeLabels: types.Labels{"role": []string{"worker"}},
							Namespaces: []string{types.Wildcard},
						},
					},
				},
				{
					Metadata: types.Metadata{
						Name:      "name1",
						Namespace: defaults.Namespace,
					},
					Spec: types.RoleSpecV3{
						Options: types.RoleOptions{
							MaxSessionTTL: types.Duration(20 * time.Hour),
						},
						Allow: types.RoleConditions{
							Logins:     []string{"root"},
							NodeLabels: types.Labels{types.Wildcard: []string{types.Wildcard}},
							Namespaces: []string{types.Wildcard},
						},
					},
				},
			},
			mfaVerified: true,
			checks: []check{
				{server: serverNoLabels, login: "root", hasAccess: true},
				{server: serverWorker, login: "root", hasAccess: true},
				{server: serverDB, login: "root", hasAccess: true},
			},
		},
	}
	for i, tc := range testCases {

		var set RoleSet
		for i := range tc.roles {
			set = append(set, &tc.roles[i])
		}
		for j, check := range tc.checks {
			comment := fmt.Sprintf("test case %v '%v', check %v", i, tc.name, j)
			result := set.CheckAccessToServer(check.login, check.server, tc.mfaVerified)
			if check.hasAccess {
				require.NoError(t, result, comment)
			} else {
				require.True(t, trace.IsAccessDenied(result), comment)
			}
		}
	}
}

func TestCheckAccessToRemoteCluster(t *testing.T) {
	type check struct {
		rc        types.RemoteCluster
		hasAccess bool
	}
	rcA := &types.RemoteClusterV3{
		Metadata: types.Metadata{
			Name: "a",
		},
	}
	rcB := &types.RemoteClusterV3{
		Metadata: types.Metadata{
			Name:   "b",
			Labels: map[string]string{"role": "worker", "status": "follower"},
		},
	}
	rcC := &types.RemoteClusterV3{
		Metadata: types.Metadata{
			Name:   "c",
			Labels: map[string]string{"role": "db", "status": "follower"},
		},
	}
	testCases := []struct {
		name   string
		roles  []types.RoleV3
		checks []check
	}{
		{
			name:  "empty role set has access to nothing",
			roles: []types.RoleV3{},
			checks: []check{
				{rc: rcA, hasAccess: false},
				{rc: rcB, hasAccess: false},
				{rc: rcC, hasAccess: false},
			},
		},
		{
			name: "role matches any label out of multiple labels",
			roles: []types.RoleV3{
				{
					Metadata: types.Metadata{
						Name:      "name1",
						Namespace: defaults.Namespace,
					},
					Spec: types.RoleSpecV3{
						Options: types.RoleOptions{
							MaxSessionTTL: types.Duration(20 * time.Hour),
						},
						Allow: types.RoleConditions{
							Logins:        []string{"admin"},
							ClusterLabels: types.Labels{"role": []string{"worker2", "worker"}},
							Namespaces:    []string{defaults.Namespace},
						},
					},
				},
			},
			checks: []check{
				{rc: rcA, hasAccess: false},
				{rc: rcB, hasAccess: true},
				{rc: rcC, hasAccess: false},
			},
		},
		{
			name: "wildcard matches anything",
			roles: []types.RoleV3{
				{
					Metadata: types.Metadata{
						Name:      "name1",
						Namespace: defaults.Namespace,
					},
					Spec: types.RoleSpecV3{
						Options: types.RoleOptions{
							MaxSessionTTL: types.Duration(20 * time.Hour),
						},
						Allow: types.RoleConditions{
							Logins:        []string{"admin"},
							ClusterLabels: types.Labels{types.Wildcard: []string{types.Wildcard}},
							Namespaces:    []string{defaults.Namespace},
						},
					},
				},
			},
			checks: []check{
				{rc: rcA, hasAccess: true},
				{rc: rcB, hasAccess: true},
				{rc: rcC, hasAccess: true},
			},
		},
		{
			name: "role with no labels will match clusters with no labels, but no others",
			roles: []types.RoleV3{
				{
					Metadata: types.Metadata{
						Name:      "name1",
						Namespace: defaults.Namespace,
					},
					Spec: types.RoleSpecV3{
						Options: types.RoleOptions{
							MaxSessionTTL: types.Duration(20 * time.Hour),
						},
						Allow: types.RoleConditions{
							Namespaces: []string{defaults.Namespace},
						},
					},
				},
			},
			checks: []check{
				{rc: rcA, hasAccess: true},
				{rc: rcB, hasAccess: false},
				{rc: rcC, hasAccess: false},
			},
		},
		{
			name: "any role in the set with labels in the set makes the set to match labels",
			roles: []types.RoleV3{
				{
					Metadata: types.Metadata{
						Name:      "name1",
						Namespace: defaults.Namespace,
					},
					Spec: types.RoleSpecV3{
						Options: types.RoleOptions{
							MaxSessionTTL: types.Duration(20 * time.Hour),
						},
						Allow: types.RoleConditions{
							ClusterLabels: types.Labels{"role": []string{"worker"}},
							Namespaces:    []string{defaults.Namespace},
						},
					},
				},
				{
					Metadata: types.Metadata{
						Name:      "name2",
						Namespace: defaults.Namespace,
					},
					Spec: types.RoleSpecV3{
						Options: types.RoleOptions{
							MaxSessionTTL: types.Duration(20 * time.Hour),
						},
						Allow: types.RoleConditions{
							Namespaces: []string{defaults.Namespace},
						},
					},
				},
			},
			checks: []check{
				{rc: rcA, hasAccess: false},
				{rc: rcB, hasAccess: true},
				{rc: rcC, hasAccess: false},
			},
		},
		{
			name: "cluster_labels with empty list value matches nothing",
			roles: []types.RoleV3{
				{
					Metadata: types.Metadata{
						Name:      "name1",
						Namespace: defaults.Namespace,
					},
					Spec: types.RoleSpecV3{
						Options: types.RoleOptions{
							MaxSessionTTL: types.Duration(20 * time.Hour),
						},
						Allow: types.RoleConditions{
							Logins:        []string{"admin"},
							ClusterLabels: types.Labels{"role": []string{}},
							Namespaces:    []string{defaults.Namespace},
						},
					},
				},
			},
			checks: []check{
				{rc: rcA, hasAccess: false},
				{rc: rcB, hasAccess: false},
				{rc: rcC, hasAccess: false},
			},
		},
		{
			name: "one role is more permissive than another",
			roles: []types.RoleV3{
				{
					Metadata: types.Metadata{
						Name:      "name1",
						Namespace: defaults.Namespace,
					},
					Spec: types.RoleSpecV3{
						Options: types.RoleOptions{
							MaxSessionTTL: types.Duration(20 * time.Hour),
						},
						Allow: types.RoleConditions{
							Logins:        []string{"admin"},
							ClusterLabels: types.Labels{"role": []string{"worker"}},
							Namespaces:    []string{defaults.Namespace},
						},
					},
				},
				{
					Metadata: types.Metadata{
						Name:      "name2",
						Namespace: defaults.Namespace,
					},
					Spec: types.RoleSpecV3{
						Options: types.RoleOptions{
							MaxSessionTTL: types.Duration(20 * time.Hour),
						},
						Allow: types.RoleConditions{
							Logins:        []string{"root", "admin"},
							ClusterLabels: types.Labels{types.Wildcard: []string{types.Wildcard}},
							Namespaces:    []string{types.Wildcard},
						},
					},
				},
			},
			checks: []check{
				{rc: rcA, hasAccess: true},
				{rc: rcB, hasAccess: true},
				{rc: rcC, hasAccess: true},
			},
		},
		{
			name: "regexp label match",
			roles: []types.RoleV3{
				{
					Metadata: types.Metadata{
						Name:      "name1",
						Namespace: defaults.Namespace,
					},
					Spec: types.RoleSpecV3{
						Options: types.RoleOptions{
							MaxSessionTTL: types.Duration(20 * time.Hour),
						},
						Allow: types.RoleConditions{
							Logins:        []string{"admin"},
							ClusterLabels: types.Labels{"role": []string{"^db(.*)$"}, "status": []string{"follow*"}},
							Namespaces:    []string{defaults.Namespace},
						},
					},
				},
			},
			checks: []check{
				{rc: rcA, hasAccess: false},
				{rc: rcB, hasAccess: false},
				{rc: rcC, hasAccess: true},
			},
		},
	}
	for i, tc := range testCases {
		var set RoleSet
		for i := range tc.roles {
			set = append(set, &tc.roles[i])
		}
		for j, check := range tc.checks {
			comment := fmt.Sprintf("test case %v '%v', check %v", i, tc.name, j)
			result := set.CheckAccessToRemoteCluster(check.rc)
			if check.hasAccess {
				require.NoError(t, result, comment)
			} else {
				require.True(t, trace.IsAccessDenied(result), fmt.Sprintf("%v: %v", comment, result))
			}
		}
	}
}

// testContext overrides context and captures log writes in action
type testContext struct {
	Context
	// Buffer captures log writes
	buffer *bytes.Buffer
}

// Write is implemented explicitly to avoid collision
// of String methods when embedding
func (t *testContext) Write(data []byte) (int, error) {
	return t.buffer.Write(data)
}

func TestCheckRuleAccess(t *testing.T) {
	type check struct {
		hasAccess   bool
		verb        string
		namespace   string
		rule        string
		context     testContext
		matchBuffer string
	}
	testCases := []struct {
		name   string
		roles  []types.RoleV3
		checks []check
	}{
		{
			name:  "0 - empty role set has access to nothing",
			roles: []types.RoleV3{},
			checks: []check{
				{rule: types.KindUser, verb: types.ActionWrite, namespace: defaults.Namespace, hasAccess: false},
			},
		},
		{
			name: "1 - user can read session but can't list in default namespace",
			roles: []types.RoleV3{
				{
					Metadata: types.Metadata{
						Name:      "name1",
						Namespace: defaults.Namespace,
					},
					Spec: types.RoleSpecV3{
						Allow: types.RoleConditions{
							Namespaces: []string{defaults.Namespace},
							Rules: []types.Rule{
								types.NewRule(types.KindSSHSession, []string{types.VerbRead}),
							},
						},
					},
				},
			},
			checks: []check{
				{rule: types.KindSSHSession, verb: types.VerbRead, namespace: defaults.Namespace, hasAccess: true},
				{rule: types.KindSSHSession, verb: types.VerbList, namespace: defaults.Namespace, hasAccess: false},
			},
		},
		{
			name: "2 - user can read sessions in system namespace and create stuff in default namespace",
			roles: []types.RoleV3{
				{
					Metadata: types.Metadata{
						Name:      "name1",
						Namespace: defaults.Namespace,
					},
					Spec: types.RoleSpecV3{
						Allow: types.RoleConditions{
							Namespaces: []string{"system"},
							Rules: []types.Rule{
								types.NewRule(types.KindSSHSession, []string{types.VerbRead}),
							},
						},
					},
				},
				{
					Metadata: types.Metadata{
						Name:      "name2",
						Namespace: defaults.Namespace,
					},
					Spec: types.RoleSpecV3{
						Allow: types.RoleConditions{
							Namespaces: []string{defaults.Namespace},
							Rules: []types.Rule{
								types.NewRule(types.KindSSHSession, []string{types.VerbCreate, types.VerbRead}),
							},
						},
					},
				},
			},
			checks: []check{
				{rule: types.KindSSHSession, verb: types.VerbRead, namespace: defaults.Namespace, hasAccess: true},
				{rule: types.KindSSHSession, verb: types.VerbCreate, namespace: defaults.Namespace, hasAccess: true},
				{rule: types.KindSSHSession, verb: types.VerbCreate, namespace: "system", hasAccess: false},
				{rule: types.KindRole, verb: types.VerbRead, namespace: defaults.Namespace, hasAccess: false},
			},
		},
		{
			name: "3 - deny rules override allow rules",
			roles: []types.RoleV3{
				{
					Metadata: types.Metadata{
						Name:      "name1",
						Namespace: defaults.Namespace,
					},
					Spec: types.RoleSpecV3{
						Deny: types.RoleConditions{
							Namespaces: []string{defaults.Namespace},
							Rules: []types.Rule{
								types.NewRule(types.KindSSHSession, []string{types.VerbCreate}),
							},
						},
						Allow: types.RoleConditions{
							Namespaces: []string{defaults.Namespace},
							Rules: []types.Rule{
								types.NewRule(types.KindSSHSession, []string{types.VerbCreate}),
							},
						},
					},
				},
			},
			checks: []check{
				{rule: types.KindSSHSession, verb: types.VerbCreate, namespace: defaults.Namespace, hasAccess: false},
			},
		},
		{
			name: "4 - user can read sessions if trait matches",
			roles: []types.RoleV3{
				{
					Metadata: types.Metadata{
						Name:      "name1",
						Namespace: defaults.Namespace,
					},
					Spec: types.RoleSpecV3{
						Allow: types.RoleConditions{
							Namespaces: []string{defaults.Namespace},
							Rules: []types.Rule{
								{
									Resources: []string{types.KindSession},
									Verbs:     []string{types.VerbRead},
									Where:     `contains(user.spec.traits["group"], "prod")`,
									Actions: []string{
										`log("info", "4 - tc match for user %v", user.metadata.name)`,
									},
								},
							},
						},
					},
				},
			},
			checks: []check{
				{rule: types.KindSession, verb: types.VerbRead, namespace: defaults.Namespace, hasAccess: false},
				{rule: types.KindSession, verb: types.VerbList, namespace: defaults.Namespace, hasAccess: false},
				{
					context: testContext{
						buffer: &bytes.Buffer{},
						Context: Context{
							User: &types.UserV2{
								Metadata: types.Metadata{
									Name: "bob",
								},
								Spec: types.UserSpecV2{
									Traits: map[string][]string{
										"group": {"dev", "prod"},
									},
								},
							},
						},
					},
					rule:      types.KindSession,
					verb:      types.VerbRead,
					namespace: defaults.Namespace,
					hasAccess: true,
				},
				{
					context: testContext{
						buffer: &bytes.Buffer{},
						Context: Context{
							User: &types.UserV2{
								Spec: types.UserSpecV2{
									Traits: map[string][]string{
										"group": {"dev"},
									},
								},
							},
						},
					},
					rule:      types.KindSession,
					verb:      types.VerbRead,
					namespace: defaults.Namespace,
					hasAccess: false,
				},
			},
		},
		{
			name: "5 - user can read role if role has label",
			roles: []types.RoleV3{
				{
					Metadata: types.Metadata{
						Name:      "name1",
						Namespace: defaults.Namespace,
					},
					Spec: types.RoleSpecV3{
						Allow: types.RoleConditions{
							Namespaces: []string{defaults.Namespace},
							Rules: []types.Rule{
								{
									Resources: []string{types.KindRole},
									Verbs:     []string{types.VerbRead},
									Where:     `equals(resource.metadata.labels["team"], "dev")`,
									Actions: []string{
										`log("error", "4 - tc match")`,
									},
								},
							},
						},
					},
				},
			},
			checks: []check{
				{rule: types.KindRole, verb: types.VerbRead, namespace: defaults.Namespace, hasAccess: false},
				{rule: types.KindRole, verb: types.VerbList, namespace: defaults.Namespace, hasAccess: false},
				{
					context: testContext{
						buffer: &bytes.Buffer{},
						Context: Context{
							Resource: &types.RoleV3{
								Metadata: types.Metadata{
									Labels: map[string]string{"team": "dev"},
								},
							},
						},
					},
					rule:      types.KindRole,
					verb:      types.VerbRead,
					namespace: defaults.Namespace,
					hasAccess: true,
				},
			},
		},
		{
			name: "More specific rule wins",
			roles: []types.RoleV3{
				{
					Metadata: types.Metadata{
						Name:      "name1",
						Namespace: defaults.Namespace,
					},
					Spec: types.RoleSpecV3{
						Allow: types.RoleConditions{
							Namespaces: []string{defaults.Namespace},
							Rules: []types.Rule{
								{
									Resources: []string{types.Wildcard},
									Verbs:     []string{types.Wildcard},
								},
								{
									Resources: []string{types.KindRole},
									Verbs:     []string{types.VerbRead},
									Where:     `equals(resource.metadata.labels["team"], "dev")`,
									Actions: []string{
										`log("info", "matched more specific rule")`,
									},
								},
							},
						},
					},
				},
			},
			checks: []check{
				{
					context: testContext{
						buffer: &bytes.Buffer{},
						Context: Context{
							Resource: &types.RoleV3{
								Metadata: types.Metadata{
									Labels: map[string]string{"team": "dev"},
								},
							},
						},
					},
					rule:        types.KindRole,
					verb:        types.VerbRead,
					namespace:   defaults.Namespace,
					hasAccess:   true,
					matchBuffer: "more specific rule",
				},
			},
		},
	}
	for i, tc := range testCases {
		var set RoleSet
		for i := range tc.roles {
			set = append(set, &tc.roles[i])
		}
		for j, check := range tc.checks {
			comment := fmt.Sprintf("test case %v '%v', check %v", i, tc.name, j)
			result := set.CheckAccessToRule(&check.context, check.namespace, check.rule, check.verb, false)
			if check.hasAccess {
				require.NoError(t, result, comment)
			} else {
				require.True(t, trace.IsAccessDenied(result), comment)
			}
			if check.matchBuffer != "" {
				require.Contains(t, check.context.buffer.String(), check.matchBuffer, comment)
			}
		}
	}
}

func TestCheckRuleSorting(t *testing.T) {
	testCases := []struct {
		name  string
		rules []types.Rule
		set   RuleSet
	}{
		{
			name: "single rule set sorts OK",
			rules: []types.Rule{
				{
					Resources: []string{types.KindUser},
					Verbs:     []string{types.VerbCreate},
				},
			},
			set: RuleSet{
				types.KindUser: []types.Rule{
					{
						Resources: []string{types.KindUser},
						Verbs:     []string{types.VerbCreate},
					},
				},
			},
		},
		{
			name: "rule with where section is more specific",
			rules: []types.Rule{
				{
					Resources: []string{types.KindUser},
					Verbs:     []string{types.VerbCreate},
				},
				{
					Resources: []string{types.KindUser},
					Verbs:     []string{types.VerbCreate},
					Where:     "contains(user.spec.traits[\"groups\"], \"prod\")",
				},
			},
			set: RuleSet{
				types.KindUser: []types.Rule{
					{
						Resources: []string{types.KindUser},
						Verbs:     []string{types.VerbCreate},
						Where:     "contains(user.spec.traits[\"groups\"], \"prod\")",
					},
					{
						Resources: []string{types.KindUser},
						Verbs:     []string{types.VerbCreate},
					},
				},
			},
		},
		{
			name: "rule with action is more specific",
			rules: []types.Rule{
				{
					Resources: []string{types.KindUser},
					Verbs:     []string{types.VerbCreate},

					Where: "contains(user.spec.traits[\"groups\"], \"prod\")",
				},
				{
					Resources: []string{types.KindUser},
					Verbs:     []string{types.VerbCreate},
					Where:     "contains(user.spec.traits[\"groups\"], \"prod\")",
					Actions: []string{
						"log(\"info\", \"log entry\")",
					},
				},
			},
			set: RuleSet{
				types.KindUser: []types.Rule{
					{
						Resources: []string{types.KindUser},
						Verbs:     []string{types.VerbCreate},
						Where:     "contains(user.spec.traits[\"groups\"], \"prod\")",
						Actions: []string{
							"log(\"info\", \"log entry\")",
						},
					},
					{
						Resources: []string{types.KindUser},
						Verbs:     []string{types.VerbCreate},
						Where:     "contains(user.spec.traits[\"groups\"], \"prod\")",
					},
				},
			},
		},
	}
	for i, tc := range testCases {
		comment := fmt.Sprintf("test case %v '%v'", i, tc.name)
		out := MakeRuleSet(tc.rules)
		require.Equal(t, tc.set, out, comment)
	}
}

func TestApplyTraits(t *testing.T) {
	type rule struct {
		inLogins      []string
		outLogins     []string
		inLabels      types.Labels
		outLabels     types.Labels
		inKubeLabels  types.Labels
		outKubeLabels types.Labels
		inKubeGroups  []string
		outKubeGroups []string
		inKubeUsers   []string
		outKubeUsers  []string
		inAppLabels   types.Labels
		outAppLabels  types.Labels
		inDBLabels    types.Labels
		outDBLabels   types.Labels
		inDBNames     []string
		outDBNames    []string
		inDBUsers     []string
		outDBUsers    []string
	}
	var tests = []struct {
		comment  string
		inTraits map[string][]string
		allow    rule
		deny     rule
	}{

		{
			comment: "logins substitute in allow rule",
			inTraits: map[string][]string{
				"foo": {"bar"},
			},
			allow: rule{
				inLogins:  []string{`{{external.foo}}`, "root"},
				outLogins: []string{"bar", "root"},
			},
		},
		{
			comment: "logins substitute in allow rule with function",
			inTraits: map[string][]string{
				"foo": {"Bar <bar@example.com>"},
			},
			allow: rule{
				inLogins:  []string{`{{email.local(external.foo)}}`, "root"},
				outLogins: []string{"bar", "root"},
			},
		},
		{
			comment: "logins substitute in deny rule",
			inTraits: map[string][]string{
				"foo": {"bar"},
			},
			deny: rule{
				inLogins:  []string{`{{external.foo}}`},
				outLogins: []string{"bar"},
			},
		},
		{
			comment: "kube group substitute in allow rule",
			inTraits: map[string][]string{
				"foo": {"bar"},
			},
			allow: rule{
				inKubeGroups:  []string{`{{external.foo}}`, "root"},
				outKubeGroups: []string{"bar", "root"},
			},
		},
		{
			comment: "kube group substitute in deny rule",
			inTraits: map[string][]string{
				"foo": {"bar"},
			},
			deny: rule{
				inKubeGroups:  []string{`{{external.foo}}`, "root"},
				outKubeGroups: []string{"bar", "root"},
			},
		},
		{
			comment: "kube user interpolation in allow rule",
			inTraits: map[string][]string{
				"foo": {"bar"},
			},
			allow: rule{
				inKubeUsers:  []string{`IAM#{{external.foo}};`},
				outKubeUsers: []string{"IAM#bar;"},
			},
		},
		{
			comment: "kube users interpolation in deny rule",
			inTraits: map[string][]string{
				"foo": {"bar"},
			},
			deny: rule{
				inKubeUsers:  []string{`IAM#{{external.foo}};`},
				outKubeUsers: []string{"IAM#bar;"},
			},
		},
		{
			comment: "database name/user external vars in allow rule",
			inTraits: map[string][]string{
				"foo": {"bar"},
			},
			allow: rule{
				inDBNames:  []string{"{{external.foo}}", "{{external.baz}}", "postgres"},
				outDBNames: []string{"bar", "postgres"},
				inDBUsers:  []string{"{{external.foo}}", "{{external.baz}}", "postgres"},
				outDBUsers: []string{"bar", "postgres"},
			},
		},
		{
			comment: "database name/user external vars in deny rule",
			inTraits: map[string][]string{
				"foo": {"bar"},
			},
			deny: rule{
				inDBNames:  []string{"{{external.foo}}", "{{external.baz}}", "postgres"},
				outDBNames: []string{"bar", "postgres"},
				inDBUsers:  []string{"{{external.foo}}", "{{external.baz}}", "postgres"},
				outDBUsers: []string{"bar", "postgres"},
			},
		},
		{
			comment: "database name/user internal vars in allow rule",
			inTraits: map[string][]string{
				"db_names": {"db1", "db2"},
				"db_users": {"alice"},
			},
			allow: rule{
				inDBNames:  []string{"{{internal.db_names}}", "{{internal.foo}}", "postgres"},
				outDBNames: []string{"db1", "db2", "postgres"},
				inDBUsers:  []string{"{{internal.db_users}}", "{{internal.foo}}", "postgres"},
				outDBUsers: []string{"alice", "postgres"},
			},
		},
		{
			comment: "database name/user internal vars in deny rule",
			inTraits: map[string][]string{
				"db_names": {"db1", "db2"},
				"db_users": {"alice"},
			},
			deny: rule{
				inDBNames:  []string{"{{internal.db_names}}", "{{internal.foo}}", "postgres"},
				outDBNames: []string{"db1", "db2", "postgres"},
				inDBUsers:  []string{"{{internal.db_users}}", "{{internal.foo}}", "postgres"},
				outDBUsers: []string{"alice", "postgres"},
			},
		},
		{
			comment: "no variable in logins",
			inTraits: map[string][]string{
				"foo": {"bar"},
			},
			allow: rule{
				inLogins:  []string{"root"},
				outLogins: []string{"root"},
			},
		},
		{
			comment: "invalid variable in logins does not get passed along",
			inTraits: map[string][]string{
				"foo": {"bar"},
			},
			allow: rule{
				inLogins: []string{`external.foo}}`},
			},
		},
		{
			comment: "invalid function call in logins does not get passed along",
			inTraits: map[string][]string{
				"foo": {"bar"},
			},
			allow: rule{
				inLogins: []string{`{{email.local(external.foo, 1)}}`},
			},
		},
		{
			comment: "invalid function call in logins does not get passed along",
			inTraits: map[string][]string{
				"foo": {"bar"},
			},
			allow: rule{
				inLogins: []string{`{{email.local()}}`},
			},
		},
		{
			comment: "invalid function call in logins does not get passed along",
			inTraits: map[string][]string{
				"foo": {"bar"},
			},
			allow: rule{
				inLogins: []string{`{{email.local(email.local)}}`, `{{email.local(email.local())}}`},
			},
		},
		{
			comment: "variable in logins, none in traits",
			inTraits: map[string][]string{
				"foo": {"bar"},
			},
			allow: rule{
				inLogins:  []string{`{{internal.bar}}`, "root"},
				outLogins: []string{"root"},
			},
		},
		{
			comment: "multiple variables in traits",
			inTraits: map[string][]string{
				"logins": {"bar", "baz"},
			},
			allow: rule{
				inLogins:  []string{`{{internal.logins}}`, "root"},
				outLogins: []string{"bar", "baz", "root"},
			},
		},
		{
			comment: "deduplicate",
			inTraits: map[string][]string{
				"foo": {"bar"},
			},
			allow: rule{
				inLogins:  []string{`{{external.foo}}`, "bar"},
				outLogins: []string{"bar"},
			},
		},
		{
			comment: "invalid unix login",
			inTraits: map[string][]string{
				"foo": {"-foo"},
			},
			allow: rule{
				inLogins:  []string{`{{external.foo}}`, "bar"},
				outLogins: []string{"bar"},
			},
		},
		{
			comment: "label substitute in allow and deny rule",
			inTraits: map[string][]string{
				"foo":   {"bar"},
				"hello": {"there"},
			},
			allow: rule{
				inLabels:  types.Labels{`{{external.foo}}`: []string{"{{external.hello}}"}},
				outLabels: types.Labels{`bar`: []string{"there"}},
			},
			deny: rule{
				inLabels:  types.Labels{`{{external.hello}}`: []string{"{{external.foo}}"}},
				outLabels: types.Labels{`there`: []string{"bar"}},
			},
		},

		{
			comment: "missing node variables are set to empty during substitution",
			inTraits: map[string][]string{
				"foo": {"bar"},
			},
			allow: rule{
				inLabels: types.Labels{
					`{{external.foo}}`:     []string{"value"},
					`{{external.missing}}`: []string{"missing"},
					`missing`:              []string{"{{external.missing}}", "othervalue"},
				},
				outLabels: types.Labels{
					`bar`:     []string{"value"},
					"missing": []string{"", "othervalue"},
					"":        []string{"missing"},
				},
			},
		},

		{
			comment: "the first variable value is picked for label keys",
			inTraits: map[string][]string{
				"foo": {"bar", "baz"},
			},
			allow: rule{
				inLabels:  types.Labels{`{{external.foo}}`: []string{"value"}},
				outLabels: types.Labels{`bar`: []string{"value"}},
			},
		},

		{
			comment: "all values are expanded for label values",
			inTraits: map[string][]string{
				"foo": {"bar", "baz"},
			},
			allow: rule{
				inLabels:  types.Labels{`key`: []string{`{{external.foo}}`}},
				outLabels: types.Labels{`key`: []string{"bar", "baz"}},
			},
		},
		{
			comment: "values are expanded in kube labels",
			inTraits: map[string][]string{
				"foo": {"bar", "baz"},
			},
			allow: rule{
				inKubeLabels:  types.Labels{`key`: []string{`{{external.foo}}`}},
				outKubeLabels: types.Labels{`key`: []string{"bar", "baz"}},
			},
		},
		{
			comment: "values are expanded in app labels",
			inTraits: map[string][]string{
				"foo": {"bar", "baz"},
			},
			allow: rule{
				inAppLabels:  types.Labels{`key`: []string{`{{external.foo}}`}},
				outAppLabels: types.Labels{`key`: []string{"bar", "baz"}},
			},
		},
		{
			comment: "values are expanded in database labels",
			inTraits: map[string][]string{
				"foo": {"bar", "baz"},
			},
			allow: rule{
				inDBLabels:  types.Labels{`key`: []string{`{{external.foo}}`}},
				outDBLabels: types.Labels{`key`: []string{"bar", "baz"}},
			},
		},
	}

	for i, tt := range tests {
		comment := fmt.Sprintf("Test %v %v", i, tt.comment)

		role := &types.RoleV3{
			Kind:    types.KindRole,
			Version: types.V3,
			Metadata: types.Metadata{
				Name:      "name1",
				Namespace: defaults.Namespace,
			},
			Spec: types.RoleSpecV3{
				Allow: types.RoleConditions{
					Logins:           tt.allow.inLogins,
					NodeLabels:       tt.allow.inLabels,
					ClusterLabels:    tt.allow.inLabels,
					KubernetesLabels: tt.allow.inKubeLabels,
					KubeGroups:       tt.allow.inKubeGroups,
					KubeUsers:        tt.allow.inKubeUsers,
					AppLabels:        tt.allow.inAppLabels,
					DatabaseLabels:   tt.allow.inDBLabels,
					DatabaseNames:    tt.allow.inDBNames,
					DatabaseUsers:    tt.allow.inDBUsers,
				},
				Deny: types.RoleConditions{
					Logins:           tt.deny.inLogins,
					NodeLabels:       tt.deny.inLabels,
					ClusterLabels:    tt.deny.inLabels,
					KubernetesLabels: tt.deny.inKubeLabels,
					KubeGroups:       tt.deny.inKubeGroups,
					KubeUsers:        tt.deny.inKubeUsers,
					AppLabels:        tt.deny.inAppLabels,
					DatabaseLabels:   tt.deny.inDBLabels,
					DatabaseNames:    tt.deny.inDBNames,
					DatabaseUsers:    tt.deny.inDBUsers,
				},
			},
		}

		outRole := ApplyTraits(role, tt.inTraits)
		require.Equal(t, outRole.GetLogins(types.Allow), tt.allow.outLogins, comment)
		require.Equal(t, outRole.GetNodeLabels(types.Allow), tt.allow.outLabels, comment)
		require.Equal(t, outRole.GetClusterLabels(types.Allow), tt.allow.outLabels, comment)
		require.Equal(t, outRole.GetKubernetesLabels(types.Allow), tt.allow.outKubeLabels, comment)
		require.Equal(t, outRole.GetKubeGroups(types.Allow), tt.allow.outKubeGroups, comment)
		require.Equal(t, outRole.GetKubeUsers(types.Allow), tt.allow.outKubeUsers, comment)
		require.Equal(t, outRole.GetAppLabels(types.Allow), tt.allow.outAppLabels, comment)
		require.Equal(t, outRole.GetDatabaseLabels(types.Allow), tt.allow.outDBLabels, comment)
		require.Equal(t, outRole.GetDatabaseNames(types.Allow), tt.allow.outDBNames, comment)
		require.Equal(t, outRole.GetDatabaseUsers(types.Allow), tt.allow.outDBUsers, comment)

		require.Equal(t, outRole.GetLogins(types.Deny), tt.deny.outLogins, comment)
		require.Equal(t, outRole.GetNodeLabels(types.Deny), tt.deny.outLabels, comment)
		require.Equal(t, outRole.GetClusterLabels(types.Deny), tt.deny.outLabels, comment)
		require.Equal(t, outRole.GetKubernetesLabels(types.Deny), tt.deny.outKubeLabels, comment)
		require.Equal(t, outRole.GetKubeGroups(types.Deny), tt.deny.outKubeGroups, comment)
		require.Equal(t, outRole.GetKubeUsers(types.Deny), tt.deny.outKubeUsers, comment)
		require.Equal(t, outRole.GetAppLabels(types.Deny), tt.deny.outAppLabels, comment)
		require.Equal(t, outRole.GetDatabaseLabels(types.Deny), tt.deny.outDBLabels, comment)
		require.Equal(t, outRole.GetDatabaseNames(types.Deny), tt.deny.outDBNames, comment)
		require.Equal(t, outRole.GetDatabaseUsers(types.Deny), tt.deny.outDBUsers, comment)
	}
}

// TestBoolOptions makes sure that bool options (like agent forwarding and
// port forwarding) can be disabled in a role.
func TestBoolOptions(t *testing.T) {
	var tests = []struct {
		inOptions           types.RoleOptions
		outCanPortForward   bool
		outCanForwardAgents bool
	}{
		// Setting options explicitly off should remain off.
		{
			inOptions: types.RoleOptions{
				ForwardAgent:   types.NewBool(false),
				PortForwarding: types.NewBoolOption(false),
			},
			outCanPortForward:   false,
			outCanForwardAgents: false,
		},
		// Not setting options should set port forwarding to true (default enabled)
		// and agent forwarding false (default disabled).
		{
			inOptions:           types.RoleOptions{},
			outCanPortForward:   true,
			outCanForwardAgents: false,
		},
		// Explicitly enabling should enable them.
		{
			inOptions: types.RoleOptions{
				ForwardAgent:   types.NewBool(true),
				PortForwarding: types.NewBoolOption(true),
			},
			outCanPortForward:   true,
			outCanForwardAgents: true,
		},
	}
	for _, tt := range tests {
		set := NewRoleSet(&types.RoleV3{
			Kind:    types.KindRole,
			Version: types.V3,
			Metadata: types.Metadata{
				Name:      "role-name",
				Namespace: defaults.Namespace,
			},
			Spec: types.RoleSpecV3{
				Options: tt.inOptions,
			},
		})
		require.Equal(t, tt.outCanPortForward, set.CanPortForward())
		require.Equal(t, tt.outCanForwardAgents, set.CanForwardAgents())
	}
}

func TestCheckAccessToDatabase(t *testing.T) {
	utils.InitLoggerForTests(testing.Verbose())
	dbStage := types.NewDatabaseServerV3("stage",
		map[string]string{"env": "stage"},
		types.DatabaseServerSpecV3{})
	dbProd := types.NewDatabaseServerV3("prod",
		map[string]string{"env": "prod"},
		types.DatabaseServerSpecV3{})
	roleDevStage := &types.RoleV3{
		Metadata: types.Metadata{Name: "dev-stage", Namespace: defaults.Namespace},
		Spec: types.RoleSpecV3{
			Allow: types.RoleConditions{
				Namespaces:     []string{defaults.Namespace},
				DatabaseLabels: types.Labels{"env": []string{"stage"}},
				DatabaseNames:  []string{types.Wildcard},
				DatabaseUsers:  []string{types.Wildcard},
			},
			Deny: types.RoleConditions{
				Namespaces:    []string{defaults.Namespace},
				DatabaseNames: []string{"supersecret"},
			},
		},
	}
	roleDevProd := &types.RoleV3{
		Metadata: types.Metadata{Name: "dev-prod", Namespace: defaults.Namespace},
		Spec: types.RoleSpecV3{
			Allow: types.RoleConditions{
				Namespaces:     []string{defaults.Namespace},
				DatabaseLabels: types.Labels{"env": []string{"prod"}},
				DatabaseNames:  []string{"test"},
				DatabaseUsers:  []string{"dev"},
			},
		},
	}
	roleDevProdWithMFA := &types.RoleV3{
		Metadata: types.Metadata{Name: "dev-prod", Namespace: defaults.Namespace},
		Spec: types.RoleSpecV3{
			Options: types.RoleOptions{
				RequireSessionMFA: true,
			},
			Allow: types.RoleConditions{
				Namespaces:     []string{defaults.Namespace},
				DatabaseLabels: types.Labels{"env": []string{"prod"}},
				DatabaseNames:  []string{"test"},
				DatabaseUsers:  []string{"dev"},
			},
		},
	}
	// Database labels are not set in allow/deny rules on purpose to test
	// that they're set during check and set defaults below.
	roleDeny := &types.RoleV3{
		Metadata: types.Metadata{Name: "deny", Namespace: defaults.Namespace},
		Spec: types.RoleSpecV3{
			Allow: types.RoleConditions{
				Namespaces:    []string{defaults.Namespace},
				DatabaseNames: []string{types.Wildcard},
				DatabaseUsers: []string{types.Wildcard},
			},
			Deny: types.RoleConditions{
				Namespaces:    []string{defaults.Namespace},
				DatabaseNames: []string{"postgres"},
				DatabaseUsers: []string{"postgres"},
			},
		},
	}
	require.NoError(t, roleDeny.CheckAndSetDefaults())
	type access struct {
		server types.DatabaseServer
		dbName string
		dbUser string
		access bool
	}
	testCases := []struct {
		name        string
		roles       RoleSet
		access      []access
		mfaVerified bool
	}{
		{
			name:  "developer allowed any username/database in stage database except one database",
			roles: RoleSet{roleDevStage, roleDevProd},
			access: []access{
				{server: dbStage, dbName: "superdb", dbUser: "superuser", access: true},
				{server: dbStage, dbName: "test", dbUser: "dev", access: true},
				{server: dbStage, dbName: "supersecret", dbUser: "dev", access: false},
			},
		},
		{
			name:  "developer allowed only specific username/database in prod database",
			roles: RoleSet{roleDevStage, roleDevProd},
			access: []access{
				{server: dbProd, dbName: "superdb", dbUser: "superuser", access: false},
				{server: dbProd, dbName: "test", dbUser: "dev", access: true},
				{server: dbProd, dbName: "superdb", dbUser: "dev", access: false},
				{server: dbProd, dbName: "test", dbUser: "superuser", access: false},
			},
		},
		{
			name:  "deny role denies access to specific database and user",
			roles: RoleSet{roleDeny},
			access: []access{
				{server: dbProd, dbName: "test", dbUser: "test", access: true},
				{server: dbProd, dbName: "postgres", dbUser: "test", access: false},
				{server: dbProd, dbName: "test", dbUser: "postgres", access: false},
			},
		},
		{
			name:        "prod database requires MFA, no MFA provided",
			roles:       RoleSet{roleDevStage, roleDevProdWithMFA, roleDevProd},
			mfaVerified: false,
			access: []access{
				{server: dbStage, dbName: "test", dbUser: "dev", access: true},
				{server: dbProd, dbName: "test", dbUser: "dev", access: false},
			},
		},
		{
			name:        "prod database requires MFA, MFA provided",
			roles:       RoleSet{roleDevStage, roleDevProdWithMFA, roleDevProd},
			mfaVerified: true,
			access: []access{
				{server: dbStage, dbName: "test", dbUser: "dev", access: true},
				{server: dbProd, dbName: "test", dbUser: "dev", access: true},
			},
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			for _, access := range tc.access {
				err := tc.roles.CheckAccessToDatabase(access.server, tc.mfaVerified,
					&DatabaseLabelsMatcher{Labels: access.server.GetAllLabels()},
					&DatabaseUserMatcher{User: access.dbUser},
					&DatabaseNameMatcher{Name: access.dbName})
				if access.access {
					require.NoError(t, err)
				} else {
					require.Error(t, err)
					require.True(t, trace.IsAccessDenied(err))
				}
			}
		})
	}
}

func TestCheckAccessToDatabaseUser(t *testing.T) {
	utils.InitLoggerForTests(testing.Verbose())
	dbStage := types.NewDatabaseServerV3("stage",
		map[string]string{"env": "stage"},
		types.DatabaseServerSpecV3{})
	dbProd := types.NewDatabaseServerV3("prod",
		map[string]string{"env": "prod"},
		types.DatabaseServerSpecV3{})
	roleDevStage := &types.RoleV3{
		Metadata: types.Metadata{Name: "dev-stage", Namespace: defaults.Namespace},
		Spec: types.RoleSpecV3{
			Allow: types.RoleConditions{
				Namespaces:     []string{defaults.Namespace},
				DatabaseLabels: types.Labels{"env": []string{"stage"}},
				DatabaseUsers:  []string{types.Wildcard},
			},
			Deny: types.RoleConditions{
				Namespaces:    []string{defaults.Namespace},
				DatabaseUsers: []string{"superuser"},
			},
		},
	}
	roleDevProd := &types.RoleV3{
		Metadata: types.Metadata{Name: "dev-prod", Namespace: defaults.Namespace},
		Spec: types.RoleSpecV3{
			Allow: types.RoleConditions{
				Namespaces:     []string{defaults.Namespace},
				DatabaseLabels: types.Labels{"env": []string{"prod"}},
				DatabaseUsers:  []string{"dev"},
			},
		},
	}
	type access struct {
		server types.DatabaseServer
		dbUser string
		access bool
	}
	testCases := []struct {
		name   string
		roles  RoleSet
		access []access
	}{
		{
			name:  "developer allowed any username in stage database except superuser",
			roles: RoleSet{roleDevStage, roleDevProd},
			access: []access{
				{server: dbStage, dbUser: "superuser", access: false},
				{server: dbStage, dbUser: "dev", access: true},
				{server: dbStage, dbUser: "test", access: true},
			},
		},
		{
			name:  "developer allowed only specific username/database in prod database",
			roles: RoleSet{roleDevStage, roleDevProd},
			access: []access{
				{server: dbProd, dbUser: "superuser", access: false},
				{server: dbProd, dbUser: "dev", access: true},
			},
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			for _, access := range tc.access {
				err := tc.roles.CheckAccessToDatabase(access.server, false,
					&DatabaseLabelsMatcher{Labels: access.server.GetAllLabels()},
					&DatabaseUserMatcher{User: access.dbUser})
				if access.access {
					require.NoError(t, err)
				} else {
					require.Error(t, err)
					require.True(t, trace.IsAccessDenied(err))
				}
			}
		})
	}
}

func TestCheckDatabaseNamesAndUsers(t *testing.T) {
	roleEmpty := &types.RoleV3{
		Metadata: types.Metadata{Name: "roleA", Namespace: defaults.Namespace},
		Spec: types.RoleSpecV3{
			Options: types.RoleOptions{MaxSessionTTL: types.Duration(time.Hour)},
			Allow: types.RoleConditions{
				Namespaces: []string{defaults.Namespace},
			},
		},
	}
	roleA := &types.RoleV3{
		Metadata: types.Metadata{Name: "roleA", Namespace: defaults.Namespace},
		Spec: types.RoleSpecV3{
			Options: types.RoleOptions{MaxSessionTTL: types.Duration(2 * time.Hour)},
			Allow: types.RoleConditions{
				Namespaces:    []string{defaults.Namespace},
				DatabaseNames: []string{"postgres", "main"},
				DatabaseUsers: []string{"postgres", "alice"},
			},
		},
	}
	roleB := &types.RoleV3{
		Metadata: types.Metadata{Name: "roleB", Namespace: defaults.Namespace},
		Spec: types.RoleSpecV3{
			Options: types.RoleOptions{MaxSessionTTL: types.Duration(time.Hour)},
			Allow: types.RoleConditions{
				Namespaces:    []string{defaults.Namespace},
				DatabaseNames: []string{"metrics"},
				DatabaseUsers: []string{"bob"},
			},
			Deny: types.RoleConditions{
				Namespaces:    []string{defaults.Namespace},
				DatabaseNames: []string{"postgres"},
				DatabaseUsers: []string{"postgres"},
			},
		},
	}
	testCases := []struct {
		name         string
		roles        RoleSet
		ttl          time.Duration
		overrideTTL  bool
		namesOut     []string
		usersOut     []string
		accessDenied bool
		notFound     bool
	}{
		{
			name:     "single role",
			roles:    RoleSet{roleA},
			ttl:      time.Hour,
			namesOut: []string{"postgres", "main"},
			usersOut: []string{"postgres", "alice"},
		},
		{
			name:     "combined roles",
			roles:    RoleSet{roleA, roleB},
			ttl:      time.Hour,
			namesOut: []string{"main", "metrics"},
			usersOut: []string{"alice", "bob"},
		},
		{
			name:         "ttl doesn't match",
			roles:        RoleSet{roleA},
			ttl:          5 * time.Hour,
			accessDenied: true,
		},
		{
			name:     "empty role",
			roles:    RoleSet{roleEmpty},
			ttl:      time.Hour,
			notFound: true,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			names, users, err := tc.roles.CheckDatabaseNamesAndUsers(tc.ttl, tc.overrideTTL)
			if tc.accessDenied {
				require.Error(t, err)
				require.True(t, trace.IsAccessDenied(err))
			} else if tc.notFound {
				require.Error(t, err)
				require.True(t, trace.IsNotFound(err))
			} else {
				require.NoError(t, err)
				require.ElementsMatch(t, tc.namesOut, names)
				require.ElementsMatch(t, tc.usersOut, users)
			}
		})
	}
}

func TestCheckAccessToDatabaseService(t *testing.T) {
	utils.InitLoggerForTests(testing.Verbose())
	dbNoLabels := types.NewDatabaseServerV3("test",
		nil,
		types.DatabaseServerSpecV3{})
	dbStage := types.NewDatabaseServerV3("stage",
		map[string]string{"env": "stage"},
		types.DatabaseServerSpecV3{
			DynamicLabels: map[string]types.CommandLabelV2{"arch": {Result: "x86"}},
		})
	dbStage2 := types.NewDatabaseServerV3("stage2",
		map[string]string{"env": "stage"},
		types.DatabaseServerSpecV3{
			DynamicLabels: map[string]types.CommandLabelV2{"arch": {Result: "amd64"}},
		})
	dbProd := types.NewDatabaseServerV3("prod",
		map[string]string{"env": "prod"},
		types.DatabaseServerSpecV3{})
	roleAdmin := &types.RoleV3{
		Metadata: types.Metadata{Name: "admin", Namespace: defaults.Namespace},
		Spec: types.RoleSpecV3{
			Allow: types.RoleConditions{
				Namespaces:     []string{defaults.Namespace},
				DatabaseLabels: types.Labels{types.Wildcard: []string{types.Wildcard}},
			},
		},
	}
	roleDev := &types.RoleV3{
		Metadata: types.Metadata{Name: "dev", Namespace: defaults.Namespace},
		Spec: types.RoleSpecV3{
			Allow: types.RoleConditions{
				Namespaces:     []string{defaults.Namespace},
				DatabaseLabels: types.Labels{"env": []string{"stage"}},
			},
			Deny: types.RoleConditions{
				Namespaces:     []string{defaults.Namespace},
				DatabaseLabels: types.Labels{"arch": []string{"amd64"}},
			},
		},
	}
	roleIntern := &types.RoleV3{
		Metadata: types.Metadata{Name: "intern", Namespace: defaults.Namespace},
		Spec: types.RoleSpecV3{
			Allow: types.RoleConditions{
				Namespaces: []string{defaults.Namespace},
			},
		},
	}
	type access struct {
		server types.DatabaseServer
		access bool
	}
	testCases := []struct {
		name   string
		roles  RoleSet
		access []access
	}{
		{
			name:  "empty role doesn't have access to any databases",
			roles: nil,
			access: []access{
				{server: dbNoLabels, access: false},
				{server: dbStage, access: false},
				{server: dbStage2, access: false},
				{server: dbProd, access: false},
			},
		},
		{
			name:  "intern doesn't have access to any databases",
			roles: RoleSet{roleIntern},
			access: []access{
				{server: dbNoLabels, access: false},
				{server: dbStage, access: false},
				{server: dbStage2, access: false},
				{server: dbProd, access: false},
			},
		},
		{
			name:  "developer only has access to one of stage database",
			roles: RoleSet{roleDev},
			access: []access{
				{server: dbNoLabels, access: false},
				{server: dbStage, access: true},
				{server: dbStage2, access: false},
				{server: dbProd, access: false},
			},
		},
		{
			name:  "admin has access to all databases",
			roles: RoleSet{roleAdmin},
			access: []access{
				{server: dbNoLabels, access: true},
				{server: dbStage, access: true},
				{server: dbStage2, access: true},
				{server: dbProd, access: true},
			},
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			for _, access := range tc.access {
				err := tc.roles.CheckAccessToDatabase(access.server, false,
					&DatabaseLabelsMatcher{Labels: access.server.GetAllLabels()})
				if access.access {
					require.NoError(t, err)
				} else {
					require.Error(t, err)
					require.True(t, trace.IsAccessDenied(err))
				}
			}
		})
	}
}

func TestCheckAccessToKubernetes(t *testing.T) {
	clusterNoLabels := &types.KubernetesCluster{
		Name: "no-labels",
	}
	clusterWithLabels := &types.KubernetesCluster{
		Name:          "no-labels",
		StaticLabels:  map[string]string{"foo": "bar"},
		DynamicLabels: map[string]types.CommandLabelV2{"baz": {Result: "qux"}},
	}
	wildcardRole := &types.RoleV3{
		Metadata: types.Metadata{
			Name:      "wildcard-labels",
			Namespace: defaults.Namespace,
		},
		Spec: types.RoleSpecV3{
			Allow: types.RoleConditions{
				Namespaces:       []string{defaults.Namespace},
				KubernetesLabels: types.Labels{types.Wildcard: []string{types.Wildcard}},
			},
		},
	}
	matchingLabelsRole := &types.RoleV3{
		Metadata: types.Metadata{
			Name:      "matching-labels",
			Namespace: defaults.Namespace,
		},
		Spec: types.RoleSpecV3{
			Allow: types.RoleConditions{
				Namespaces: []string{defaults.Namespace},
				KubernetesLabels: types.Labels{
					"foo": utils.Strings{"bar"},
					"baz": utils.Strings{"qux"},
				},
			},
		},
	}
	matchingLabelsRoleWithMFA := &types.RoleV3{
		Metadata: types.Metadata{
			Name:      "matching-labels",
			Namespace: defaults.Namespace,
		},
		Spec: types.RoleSpecV3{
			Options: types.RoleOptions{
				RequireSessionMFA: true,
			},
			Allow: types.RoleConditions{
				Namespaces: []string{defaults.Namespace},
				KubernetesLabels: types.Labels{
					"foo": utils.Strings{"bar"},
					"baz": utils.Strings{"qux"},
				},
			},
		},
	}
	noLabelsRole := &types.RoleV3{
		Metadata: types.Metadata{
			Name:      "no-labels",
			Namespace: defaults.Namespace,
		},
		Spec: types.RoleSpecV3{
			Allow: types.RoleConditions{
				Namespaces: []string{defaults.Namespace},
			},
		},
	}
	mismatchingLabelsRole := &types.RoleV3{
		Metadata: types.Metadata{
			Name:      "mismatching-labels",
			Namespace: defaults.Namespace,
		},
		Spec: types.RoleSpecV3{
			Allow: types.RoleConditions{
				Namespaces: []string{defaults.Namespace},
				KubernetesLabels: types.Labels{
					"qux": utils.Strings{"baz"},
					"bar": utils.Strings{"foo"},
				},
			},
		},
	}
	testCases := []struct {
		name        string
		roles       []*types.RoleV3
		cluster     *types.KubernetesCluster
		mfaVerified bool
		hasAccess   bool
	}{
		{
			name:      "empty role set has access to nothing",
			roles:     nil,
			cluster:   clusterNoLabels,
			hasAccess: false,
		},
		{
			name:      "role with no labels has access to nothing",
			roles:     []*types.RoleV3{noLabelsRole},
			cluster:   clusterNoLabels,
			hasAccess: false,
		},
		{
			name:      "role with wildcard labels matches cluster without labels",
			roles:     []*types.RoleV3{wildcardRole},
			cluster:   clusterNoLabels,
			hasAccess: true,
		},
		{
			name:      "role with wildcard labels matches cluster with labels",
			roles:     []*types.RoleV3{wildcardRole},
			cluster:   clusterWithLabels,
			hasAccess: true,
		},
		{
			name:      "role with labels does not match cluster with no labels",
			roles:     []*types.RoleV3{matchingLabelsRole},
			cluster:   clusterNoLabels,
			hasAccess: false,
		},
		{
			name:      "role with labels matches cluster with labels",
			roles:     []*types.RoleV3{matchingLabelsRole},
			cluster:   clusterWithLabels,
			hasAccess: true,
		},
		{
			name:      "role with mismatched labels does not match cluster with labels",
			roles:     []*types.RoleV3{mismatchingLabelsRole},
			cluster:   clusterWithLabels,
			hasAccess: false,
		},
		{
			name:      "one role in the roleset matches",
			roles:     []*types.RoleV3{mismatchingLabelsRole, noLabelsRole, matchingLabelsRole},
			cluster:   clusterWithLabels,
			hasAccess: true,
		},
		{
			name:        "role requires MFA but MFA not verified",
			roles:       []*types.RoleV3{matchingLabelsRole, matchingLabelsRoleWithMFA},
			cluster:     clusterWithLabels,
			mfaVerified: false,
			hasAccess:   false,
		},
		{
			name:        "role requires MFA and MFA verified",
			roles:       []*types.RoleV3{matchingLabelsRole, matchingLabelsRoleWithMFA},
			cluster:     clusterWithLabels,
			mfaVerified: true,
			hasAccess:   true,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var set RoleSet
			for _, r := range tc.roles {
				set = append(set, r)
			}
			err := set.CheckAccessToKubernetes(defaults.Namespace, tc.cluster, tc.mfaVerified)
			if tc.hasAccess {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
				require.True(t, trace.IsAccessDenied(err))
			}
		})
	}
}

// BenchmarkCheckAccessToServer tests how long it takes to run
// CheckAccessToServer across 4,000 nodes for 5 roles each with 5 logins each.
//
// To run benchmark:
//
//    go test -bench=.
//
// To run benchmark and obtain CPU and memory profiling:
//
//    go test -bench=. -cpuprofile=cpu.prof -memprofile=mem.prof
//
// To use the command line tool to read the profile:
//
//   go tool pprof cpu.prof
//   go tool pprof cpu.prof
//
// To generate a graph:
//
//   go tool pprof --pdf cpu.prof > cpu.pdf
//   go tool pprof --pdf mem.prof > mem.pdf
//
func BenchmarkCheckAccessToServer(b *testing.B) {
	servers := make([]*types.ServerV2, 0, 4000)

	// Create 4,000 servers with random IDs.
	for i := 0; i < 4000; i++ {
		hostname := uuid.NewUUID().String()
		servers = append(servers, &types.ServerV2{
			Kind:    types.KindNode,
			Version: types.V2,
			Metadata: types.Metadata{
				Name:      hostname,
				Namespace: defaults.Namespace,
			},
			Spec: types.ServerSpecV2{
				Addr:     "127.0.0.1:3022",
				Hostname: hostname,
			},
		})
	}

	// Create RoleSet with five roles: one admin role and four generic roles
	// that have five logins each and only have access to the foo:bar label.
	var set RoleSet
	set = append(set, NewAdminRole())
	for i := 0; i < 4; i++ {
		set = append(set, &types.RoleV3{
			Kind:    types.KindRole,
			Version: types.V3,
			Metadata: types.Metadata{
				Name:      strconv.Itoa(i),
				Namespace: defaults.Namespace,
			},
			Spec: types.RoleSpecV3{
				Allow: types.RoleConditions{
					Logins:     []string{"admin", "one", "two", "three", "four"},
					NodeLabels: types.Labels{"a": []string{"b"}},
				},
			},
		})
	}

	// Initialization is complete, start the benchmark timer.
	b.ResetTimer()

	// Build a map of all allowed logins.
	allowLogins := map[string]bool{}
	for _, role := range set {
		for _, login := range role.GetLogins(types.Allow) {
			allowLogins[login] = true
		}
	}

	// Check access to all 4,000 nodes.
	for n := 0; n < b.N; n++ {
		for i := 0; i < 4000; i++ {
			for login := range allowLogins {
				if err := set.CheckAccessToServer(login, servers[i], false); err != nil {
					b.Error(err)
				}
			}
		}
	}
}

type RoleMapSuite struct{}

var _ = check.Suite(&RoleMapSuite{})

func (s *RoleMapSuite) SetUpSuite(c *check.C) {
	utils.InitLoggerForTests(testing.Verbose())
}

func (s *RoleMapSuite) TestRoleParsing(c *check.C) {
	testCases := []struct {
		roleMap types.RoleMap
		err     error
	}{
		{
			roleMap: nil,
		},
		{
			roleMap: types.RoleMap{
				{Remote: types.Wildcard, Local: []string{"local-devs", "local-admins"}},
			},
		},
		{
			roleMap: types.RoleMap{
				{Remote: "remote-devs", Local: []string{"local-devs"}},
			},
		},
		{
			roleMap: types.RoleMap{
				{Remote: "remote-devs", Local: []string{"local-devs"}},
				{Remote: "remote-devs", Local: []string{"local-devs"}},
			},
			err: trace.BadParameter(""),
		},
		{
			roleMap: types.RoleMap{
				{Remote: types.Wildcard, Local: []string{"local-devs"}},
				{Remote: types.Wildcard, Local: []string{"local-devs"}},
			},
			err: trace.BadParameter(""),
		},
	}

	for i, tc := range testCases {
		comment := check.Commentf("test case '%v'", i)
		_, err := parseRoleMap(tc.roleMap)
		if tc.err != nil {
			c.Assert(err, check.NotNil, comment)
			c.Assert(err, check.FitsTypeOf, tc.err)
		} else {
			c.Assert(err, check.IsNil)
		}
	}
}

func (s *RoleMapSuite) TestRoleMap(c *check.C) {
	testCases := []struct {
		remote  []string
		local   []string
		roleMap types.RoleMap
		name    string
		err     error
	}{
		{
			name:    "all empty",
			remote:  nil,
			local:   nil,
			roleMap: nil,
		},
		{
			name:   "wildcard matches empty as well",
			remote: nil,
			local:  []string{"local-devs", "local-admins"},
			roleMap: types.RoleMap{
				{Remote: types.Wildcard, Local: []string{"local-devs", "local-admins"}},
			},
		},
		{
			name:   "direct match",
			remote: []string{"remote-devs"},
			local:  []string{"local-devs"},
			roleMap: types.RoleMap{
				{Remote: "remote-devs", Local: []string{"local-devs"}},
			},
		},
		{
			name:   "direct match for multiple roles",
			remote: []string{"remote-devs", "remote-logs"},
			local:  []string{"local-devs", "local-logs"},
			roleMap: types.RoleMap{
				{Remote: "remote-devs", Local: []string{"local-devs"}},
				{Remote: "remote-logs", Local: []string{"local-logs"}},
			},
		},
		{
			name:   "direct match and wildcard",
			remote: []string{"remote-devs"},
			local:  []string{"local-devs", "local-logs"},
			roleMap: types.RoleMap{
				{Remote: "remote-devs", Local: []string{"local-devs"}},
				{Remote: types.Wildcard, Local: []string{"local-logs"}},
			},
		},
		{
			name:   "glob capture match",
			remote: []string{"remote-devs"},
			local:  []string{"local-devs"},
			roleMap: types.RoleMap{
				{Remote: "remote-*", Local: []string{"local-$1"}},
			},
		},
		{
			name:   "passthrough match",
			remote: []string{"remote-devs"},
			local:  []string{"remote-devs"},
			roleMap: types.RoleMap{
				{Remote: "^(.*)$", Local: []string{"$1"}},
			},
		},
		{
			name:   "passthrough match ignores implicit role",
			remote: []string{"remote-devs", teleport.DefaultImplicitRole},
			local:  []string{"remote-devs"},
			roleMap: types.RoleMap{
				{Remote: "^(.*)$", Local: []string{"$1"}},
			},
		},
		{
			name:   "partial match",
			remote: []string{"remote-devs", "something-else"},
			local:  []string{"remote-devs"},
			roleMap: types.RoleMap{
				{Remote: "^(remote-.*)$", Local: []string{"$1"}},
			},
		},
		{
			name:   "partial empty expand section is removed",
			remote: []string{"remote-devs"},
			local:  []string{"remote-devs", "remote-"},
			roleMap: types.RoleMap{
				{Remote: "^(remote-.*)$", Local: []string{"$1", "remote-$2", "$2"}},
			},
		},
		{
			name:   "multiple matches yield different results",
			remote: []string{"remote-devs"},
			local:  []string{"remote-devs", "test"},
			roleMap: types.RoleMap{
				{Remote: "^(remote-.*)$", Local: []string{"$1"}},
				{Remote: `^\Aremote-.*$`, Local: []string{"test"}},
			},
		},
		{
			name:   "different expand groups can be referred",
			remote: []string{"remote-devs"},
			local:  []string{"remote-devs", "devs"},
			roleMap: types.RoleMap{
				{Remote: "^(remote-(.*))$", Local: []string{"$1", "$2"}},
			},
		},
	}

	for _, tc := range testCases {
		comment := check.Commentf("test case '%v'", tc.name)
		local, err := MapRoles(tc.roleMap, tc.remote)
		if tc.err != nil {
			c.Assert(err, check.NotNil, comment)
			c.Assert(err, check.FitsTypeOf, tc.err)
		} else {
			c.Assert(err, check.IsNil, comment)
			c.Assert(local, check.DeepEquals, tc.local, comment)
		}
	}
}
