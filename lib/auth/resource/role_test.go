package resource

import (
	"encoding/json"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/gravitational/teleport"
	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/teleport/api/types/wrappers"
	"github.com/gravitational/teleport/lib/auth"
	"github.com/gravitational/teleport/lib/defaults"
	"github.com/gravitational/teleport/lib/fixtures"
	"github.com/gravitational/teleport/lib/tlsca"
	"github.com/gravitational/teleport/lib/utils"

	"github.com/gravitational/trace"

	"github.com/stretchr/testify/require"
)

func TestRoleParse(t *testing.T) {
	utils.InitLoggerForTests(testing.Verbose())
	testCases := []struct {
		name         string
		in           string
		role         types.RoleV3
		error        error
		matchMessage string
	}{
		{
			name:  "no input, should not parse",
			in:    ``,
			role:  types.RoleV3{},
			error: trace.BadParameter("empty input"),
		},
		{
			name:  "validation error, no name",
			in:    `{}`,
			role:  types.RoleV3{},
			error: trace.BadParameter("failed to validate: name: name is required"),
		},
		{
			name:  "validation error, no name",
			in:    `{"kind": "role"}`,
			role:  types.RoleV3{},
			error: trace.BadParameter("failed to validate: name: name is required"),
		},

		{
			name: "validation error, missing resources",
			in: `{
							   		      "kind": "role",
							   		      "version": "v3",
							   		      "metadata": {"name": "name1"},
							   		      "spec": {
							                    "allow": {
							                      "node_labels": {"a": "b"},
							                      "namespaces": ["default"],
							                      "rules": [
							                        {
							                          "verbs": ["read", "list"]
							                        }
							                      ]
							                    }
							   		      }
							   		    }`,
			error:        trace.BadParameter(""),
			matchMessage: "missing resources",
		},
		{
			name: "validation error, missing verbs",
			in: `{
							   		      "kind": "role",
							   		      "version": "v3",
							   		      "metadata": {"name": "name1"},
							   		      "spec": {
							                    "allow": {
							                      "node_labels": {"a": "b"},
							                      "namespaces": ["default"],
							                      "rules": [
							                        {
							                          "resources": ["role"]
							                        }
							                      ]
							                    }
							   		      }
							   		    }`,
			error:        trace.BadParameter(""),
			matchMessage: "missing verbs",
		},
		{
			name: "role with no spec still gets defaults",
			in:   `{"kind": "role", "version": "v3", "metadata": {"name": "defrole"}, "spec": {}}`,
			role: types.RoleV3{
				Kind:    types.KindRole,
				Version: types.V3,
				Metadata: types.Metadata{
					Name:      "defrole",
					Namespace: defaults.Namespace,
				},
				Spec: types.RoleSpecV3{
					Options: types.RoleOptions{
						CertificateFormat: teleport.CertificateFormatStandard,
						MaxSessionTTL:     types.NewDuration(defaults.MaxCertDuration),
						PortForwarding:    types.NewBoolOption(true),
						BPF:               defaults.EnhancedEvents(),
					},
					Allow: types.RoleConditions{
						NodeLabels:       types.Labels{},
						AppLabels:        types.Labels{types.Wildcard: []string{types.Wildcard}},
						KubernetesLabels: types.Labels{types.Wildcard: []string{types.Wildcard}},
						DatabaseLabels:   types.Labels{types.Wildcard: []string{types.Wildcard}},
						Namespaces:       []string{defaults.Namespace},
					},
					Deny: types.RoleConditions{
						Namespaces: []string{defaults.Namespace},
					},
				},
			},
			error: nil,
		},
		{
			name: "full valid role",
			in: `{
					   		      "kind": "role",
					   		      "version": "v3",
					   		      "metadata": {"name": "name1", "labels": {"a-b": "c"}},
					   		      "spec": {
					                    "options": {
					                      "cert_format": "standard",
					                      "max_session_ttl": "20h",
					                      "port_forwarding": true,
					                      "client_idle_timeout": "17m",
					                      "disconnect_expired_cert": "yes",
			                              "enhanced_recording": ["command", "network"]
					                    },
					                    "allow": {
					                      "node_labels": {"a": "b", "c-d": "e"},
					                      "app_labels": {"a": "b", "c-d": "e"},
					                      "kubernetes_labels": {"a": "b", "c-d": "e"},
										  "db_labels": {"a": "b", "c-d": "e"},
										  "db_names": ["postgres"],
										  "db_users": ["postgres"],
					                      "namespaces": ["default"],
					                      "rules": [
					                        {
					                          "resources": ["role"],
					                          "verbs": ["read", "list"],
					                          "where": "contains(user.spec.traits[\"groups\"], \"prod\")",
					                          "actions": [
					                             "log(\"info\", \"log entry\")"
					                          ]
					                        }
					                      ]
					                    },
					                    "deny": {
					                      "logins": ["c"]
					                    }
					   		      }
					   		    }`,
			role: types.RoleV3{
				Kind:    types.KindRole,
				Version: types.V3,
				Metadata: types.Metadata{
					Name:      "name1",
					Namespace: defaults.Namespace,
					Labels:    map[string]string{"a-b": "c"},
				},
				Spec: types.RoleSpecV3{
					Options: types.RoleOptions{
						CertificateFormat:     teleport.CertificateFormatStandard,
						MaxSessionTTL:         types.NewDuration(20 * time.Hour),
						PortForwarding:        types.NewBoolOption(true),
						ClientIdleTimeout:     types.NewDuration(17 * time.Minute),
						DisconnectExpiredCert: types.NewBool(true),
						BPF:                   defaults.EnhancedEvents(),
					},
					Allow: types.RoleConditions{
						NodeLabels:       types.Labels{"a": []string{"b"}, "c-d": []string{"e"}},
						AppLabels:        types.Labels{"a": []string{"b"}, "c-d": []string{"e"}},
						KubernetesLabels: types.Labels{"a": []string{"b"}, "c-d": []string{"e"}},
						DatabaseLabels:   types.Labels{"a": []string{"b"}, "c-d": []string{"e"}},
						DatabaseNames:    []string{"postgres"},
						DatabaseUsers:    []string{"postgres"},
						Namespaces:       []string{"default"},
						Rules: []types.Rule{
							{
								Resources: []string{types.KindRole},
								Verbs:     []string{types.VerbRead, types.VerbList},
								Where:     "contains(user.spec.traits[\"groups\"], \"prod\")",
								Actions: []string{
									"log(\"info\", \"log entry\")",
								},
							},
						},
					},
					Deny: types.RoleConditions{
						Namespaces: []string{defaults.Namespace},
						Logins:     []string{"c"},
					},
				},
			},
			error: nil,
		},
		{
			name: "alternative options form",
			in: `{
		   		      "kind": "role",
		   		      "version": "v3",
		   		      "metadata": {"name": "name1"},
		   		      "spec": {
		                    "options": {
		                      "cert_format": "standard",
		                      "max_session_ttl": "20h",
		                      "port_forwarding": "yes",
		                      "forward_agent": "yes",
		                      "client_idle_timeout": "never",
		                      "disconnect_expired_cert": "no",
		                      "enhanced_recording": ["command", "network"]
		                    },
		                    "allow": {
		                      "node_labels": {"a": "b"},
		                      "app_labels": {"a": "b"},
		                      "kubernetes_labels": {"c": "d"},
		                      "db_labels": {"e": "f"},
		                      "namespaces": ["default"],
		                      "rules": [
		                        {
		                          "resources": ["role"],
		                          "verbs": ["read", "list"],
		                          "where": "contains(user.spec.traits[\"groups\"], \"prod\")",
		                          "actions": [
		                             "log(\"info\", \"log entry\")"
		                          ]
		                        }
		                      ]
		                    },
		                    "deny": {
		                      "logins": ["c"]
		                    }
		   		      }
		   		    }`,
			role: types.RoleV3{
				Kind:    types.KindRole,
				Version: types.V3,
				Metadata: types.Metadata{
					Name:      "name1",
					Namespace: defaults.Namespace,
				},
				Spec: types.RoleSpecV3{
					Options: types.RoleOptions{
						CertificateFormat:     teleport.CertificateFormatStandard,
						ForwardAgent:          types.NewBool(true),
						MaxSessionTTL:         types.NewDuration(20 * time.Hour),
						PortForwarding:        types.NewBoolOption(true),
						ClientIdleTimeout:     types.NewDuration(0),
						DisconnectExpiredCert: types.NewBool(false),
						BPF:                   defaults.EnhancedEvents(),
					},
					Allow: types.RoleConditions{
						NodeLabels:       types.Labels{"a": []string{"b"}},
						AppLabels:        types.Labels{"a": []string{"b"}},
						KubernetesLabels: types.Labels{"c": []string{"d"}},
						DatabaseLabels:   types.Labels{"e": []string{"f"}},
						Namespaces:       []string{"default"},
						Rules: []types.Rule{
							{
								Resources: []string{types.KindRole},
								Verbs:     []string{types.VerbRead, types.VerbList},
								Where:     "contains(user.spec.traits[\"groups\"], \"prod\")",
								Actions: []string{
									"log(\"info\", \"log entry\")",
								},
							},
						},
					},
					Deny: types.RoleConditions{
						Namespaces: []string{defaults.Namespace},
						Logins:     []string{"c"},
					},
				},
			},
			error: nil,
		},
		{
			name: "non-scalar and scalar values of labels",
			in: `{
		   		      "kind": "role",
		   		      "version": "v3",
		   		      "metadata": {"name": "name1"},
		   		      "spec": {
		                    "options": {
		                      "cert_format": "standard",
		                      "max_session_ttl": "20h",
		                      "port_forwarding": "yes",
		                      "forward_agent": "yes",
		                      "client_idle_timeout": "never",
		                      "disconnect_expired_cert": "no",
		                      "enhanced_recording": ["command", "network"]
		                    },
		                    "allow": {
		                      "node_labels": {"a": "b", "key": ["val"], "key2": ["val2", "val3"]},
		                      "app_labels": {"a": "b", "key": ["val"], "key2": ["val2", "val3"]},
		                      "kubernetes_labels": {"a": "b", "key": ["val"], "key2": ["val2", "val3"]},
		                      "db_labels": {"a": "b", "key": ["val"], "key2": ["val2", "val3"]}
		                    },
		                    "deny": {
		                      "logins": ["c"]
		                    }
		   		      }
		   		    }`,
			role: types.RoleV3{
				Kind:    types.KindRole,
				Version: types.V3,
				Metadata: types.Metadata{
					Name:      "name1",
					Namespace: defaults.Namespace,
				},
				Spec: types.RoleSpecV3{
					Options: types.RoleOptions{
						CertificateFormat:     teleport.CertificateFormatStandard,
						ForwardAgent:          types.NewBool(true),
						MaxSessionTTL:         types.NewDuration(20 * time.Hour),
						PortForwarding:        types.NewBoolOption(true),
						ClientIdleTimeout:     types.NewDuration(0),
						DisconnectExpiredCert: types.NewBool(false),
						BPF:                   defaults.EnhancedEvents(),
					},
					Allow: types.RoleConditions{
						NodeLabels: types.Labels{
							"a":    []string{"b"},
							"key":  []string{"val"},
							"key2": []string{"val2", "val3"},
						},
						AppLabels: types.Labels{
							"a":    []string{"b"},
							"key":  []string{"val"},
							"key2": []string{"val2", "val3"},
						},
						KubernetesLabels: types.Labels{
							"a":    []string{"b"},
							"key":  []string{"val"},
							"key2": []string{"val2", "val3"},
						},
						DatabaseLabels: types.Labels{
							"a":    []string{"b"},
							"key":  []string{"val"},
							"key2": []string{"val2", "val3"},
						},
						Namespaces: []string{"default"},
					},
					Deny: types.RoleConditions{
						Namespaces: []string{defaults.Namespace},
						Logins:     []string{"c"},
					},
				},
			},
			error: nil,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			role, err := UnmarshalRole([]byte(tc.in))
			if tc.error != nil {
				require.Error(t, err)
				if tc.matchMessage != "" {
					require.Contains(t, err.Error(), tc.matchMessage)
				}
			} else {
				require.NoError(t, err)
				require.True(t, role.Equals(&tc.role))

				err := auth.ValidateRole(role)
				require.NoError(t, err)

				out, err := json.Marshal(role)
				require.NoError(t, err)

				role2, err := UnmarshalRole(out)
				require.NoError(t, err)
				require.True(t, role2.Equals(&tc.role))
			}
		})
	}
}

// TestExtractFrom makes sure roles and traits are extracted from SSH and TLS
// certificates not services.User.
func TestExtractFrom(t *testing.T) {
	origRoles := []string{"admin"}
	origTraits := wrappers.Traits(map[string][]string{
		"login": {"foo"},
	})

	// Create a SSH certificate.
	pubkey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(fixtures.UserCertificateStandard))
	require.NoError(t, err)
	cert, ok := pubkey.(*ssh.Certificate)
	require.True(t, ok)

	// Create a TLS identity.
	identity := &tlsca.Identity{
		Username: "foo",
		Groups:   origRoles,
		Traits:   origTraits,
	}

	// At this point, services.User and the certificate/identity are still in
	// sync. The roles and traits returned should be the same as the original.
	roles, traits, err := ExtractFromCertificate(&userGetter{
		roles:  origRoles,
		traits: origTraits,
	}, cert)
	require.NoError(t, err)
	require.Equal(t, roles, origRoles)
	require.Equal(t, traits, origTraits)

	roles, traits, err = ExtractFromIdentity(&userGetter{
		roles:  origRoles,
		traits: origTraits,
	}, *identity)
	require.NoError(t, err)
	require.Equal(t, roles, origRoles)
	require.Equal(t, traits, origTraits)

	// The backend now returns new roles and traits, however because the roles
	// and traits are extracted from the certificate/identity, the original
	// roles and traits will be returned.
	roles, traits, err = ExtractFromCertificate(&userGetter{
		roles: []string{"intern"},
		traits: wrappers.Traits(map[string][]string{
			"login": {"bar"},
		}),
	}, cert)
	require.NoError(t, err)
	require.Equal(t, roles, origRoles)
	require.Equal(t, traits, origTraits)

	roles, traits, err = ExtractFromIdentity(&userGetter{
		roles:  origRoles,
		traits: origTraits,
	}, *identity)
	require.NoError(t, err)
	require.Equal(t, roles, origRoles)
	require.Equal(t, traits, origTraits)
}

// TestExtractFromLegacy verifies that roles and traits are fetched
// from services.User for SSH certificates is the legacy format and TLS
// certificates that don't contain traits.
func TestExtractFromLegacy(t *testing.T) {
	origRoles := []string{"admin"}
	origTraits := wrappers.Traits(map[string][]string{
		"login": {"foo"},
	})

	// Create a SSH certificate in the legacy format.
	pubkey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(fixtures.UserCertificateLegacy))
	require.NoError(t, err)
	cert, ok := pubkey.(*ssh.Certificate)
	require.True(t, ok)

	// Create a TLS identity with only roles.
	identity := &tlsca.Identity{
		Username: "foo",
		Groups:   origRoles,
	}

	// At this point, services.User and the certificate/identity are still in
	// sync. The roles and traits returned should be the same as the original.
	roles, traits, err := ExtractFromCertificate(&userGetter{
		roles:  origRoles,
		traits: origTraits,
	}, cert)
	require.NoError(t, err)
	require.Equal(t, roles, origRoles)
	require.Equal(t, traits, origTraits)
	roles, traits, err = ExtractFromIdentity(&userGetter{
		roles:  origRoles,
		traits: origTraits,
	}, *identity)
	require.NoError(t, err)
	require.Equal(t, roles, origRoles)
	require.Equal(t, traits, origTraits)

	// The backend now returns new roles and traits, because the SSH certificate
	// is in the old standard format and the TLS identity is missing traits.
	newRoles := []string{"intern"}
	newTraits := wrappers.Traits(map[string][]string{
		"login": {"bar"},
	})
	roles, traits, err = ExtractFromCertificate(&userGetter{
		roles:  newRoles,
		traits: newTraits,
	}, cert)
	require.NoError(t, err)
	require.Equal(t, roles, newRoles)
	require.Equal(t, traits, newTraits)
	roles, traits, err = ExtractFromIdentity(&userGetter{
		roles:  newRoles,
		traits: newTraits,
	}, *identity)
	require.NoError(t, err)
	require.Equal(t, roles, newRoles)
	require.Equal(t, traits, newTraits)
}

// userGetter is used in tests to return a user with the specified roles and
// traits.
type userGetter struct {
	roles  []string
	traits map[string][]string
}

func (f *userGetter) GetUser(name string, _ bool) (types.User, error) {
	user, err := types.NewUser(name)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	user.SetRoles(f.roles)
	user.SetTraits(f.traits)
	return user, nil
}
