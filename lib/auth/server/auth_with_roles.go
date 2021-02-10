/*
Copyright 2015-2021 Gravitational, Inc.

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

package server

import (
	"context"
	"net/url"
	"time"

	"github.com/gravitational/teleport"
	"github.com/gravitational/teleport/api/client/proto"
	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/teleport/api/types/wrappers"
	"github.com/gravitational/teleport/lib/auth"
	"github.com/gravitational/teleport/lib/auth/resource"
	"github.com/gravitational/teleport/lib/auth/u2f"
	"github.com/gravitational/teleport/lib/defaults"
	"github.com/gravitational/teleport/lib/events"
	"github.com/gravitational/teleport/lib/jwt"
	"github.com/gravitational/teleport/lib/modules"
	"github.com/gravitational/teleport/lib/session"
	"github.com/gravitational/teleport/lib/utils"

	"github.com/gravitational/trace"

	"github.com/sirupsen/logrus"
)

// WithRoles is a wrapper around auth service
// methods that focuses on authorizing every request
type WithRoles struct {
	authServer *Server
	sessions   session.Service
	alog       events.IAuditLog
	// context holds authorization context
	context Context
}

// CloseContext is closed when the auth server shuts down
func (a *WithRoles) CloseContext() context.Context {
	return a.authServer.closeCtx
}

func (a *WithRoles) actionWithContext(ctx *auth.Context, namespace string, resource string, action string) error {
	return a.context.Checker.CheckAccessToRule(ctx, namespace, resource, action, false)
}

func (a *WithRoles) action(namespace string, resource string, action string) error {
	return a.context.Checker.CheckAccessToRule(&auth.Context{User: a.context.User}, namespace, resource, action, false)
}

// currentUserAction is a special checker that allows certain actions for users
// even if they are not admins, e.g. update their own passwords,
// or generate certificates, otherwise it will require admin privileges
func (a *WithRoles) currentUserAction(username string) error {
	if a.hasLocalUserRole(a.context.Checker) && username == a.context.User.GetName() {
		return nil
	}
	return a.context.Checker.CheckAccessToRule(&auth.Context{User: a.context.User},
		defaults.Namespace, types.KindUser, types.VerbCreate, true)
}

// authConnectorAction is a special checker that grants access to auth
// connectors. It first checks if you have access to the specific connector.
// If not, it checks if the requester has the meta KindAuthConnector access
// (which grants access to all connectors).
func (a *WithRoles) authConnectorAction(namespace string, resource string, verb string) error {
	if err := a.context.Checker.CheckAccessToRule(&auth.Context{User: a.context.User}, namespace, resource, verb, false); err != nil {
		if err := a.context.Checker.CheckAccessToRule(&auth.Context{User: a.context.User}, namespace, types.KindAuthConnector, verb, false); err != nil {
			return trace.Wrap(err)
		}
	}
	return nil
}

// hasBuiltinRole checks the type of the role set returned and the name.
// Returns true if role set is builtin and the name matches.
func (a *WithRoles) hasBuiltinRole(name string) bool {
	return hasBuiltinRole(a.context.Checker, name)
}

// hasBuiltinRole checks the type of the role set returned and the name.
// Returns true if role set is builtin and the name matches.
func hasBuiltinRole(checker auth.AccessChecker, name string) bool {
	if _, ok := checker.(BuiltinRoleSet); !ok {
		return false
	}
	if !checker.HasRole(name) {
		return false
	}

	return true
}

// hasRemoteBuiltinRole checks the type of the role set returned and the name.
// Returns true if role set is remote builtin and the name matches.
func (a *WithRoles) hasRemoteBuiltinRole(name string) bool {
	if _, ok := a.context.Checker.(RemoteBuiltinRoleSet); !ok {
		return false
	}
	if !a.context.Checker.HasRole(name) {
		return false
	}

	return true
}

// hasLocalUserRole checks if the type of the role set is a local user or not.
func (a *WithRoles) hasLocalUserRole(checker auth.AccessChecker) bool {
	if _, ok := checker.(LocalUserRoleSet); !ok {
		return false
	}
	return true
}

// AuthenticateWebUser authenticates web user, creates and returns a web session
// in case authentication is successful
func (a *WithRoles) AuthenticateWebUser(req AuthenticateUserRequest) (types.WebSession, error) {
	// authentication request has it's own authentication, however this limits the requests
	// types to proxies to make it harder to break
	if !a.hasBuiltinRole(string(teleport.RoleProxy)) {
		return nil, trace.AccessDenied("this request can be only executed by a proxy")
	}
	return a.authServer.AuthenticateWebUser(req)
}

// AuthenticateSSHUser authenticates SSH console user, creates and  returns a pair of signed TLS and SSH
// short lived certificates as a result
func (a *WithRoles) AuthenticateSSHUser(req AuthenticateSSHRequest) (*SSHLoginResponse, error) {
	// authentication request has it's own authentication, however this limits the requests
	// types to proxies to make it harder to break
	if !a.hasBuiltinRole(string(teleport.RoleProxy)) {
		return nil, trace.AccessDenied("this request can be only executed by a proxy")
	}
	return a.authServer.AuthenticateSSHUser(req)
}

func (a *WithRoles) GetSessions(namespace string) ([]session.Session, error) {
	if err := a.action(namespace, types.KindSSHSession, types.VerbList); err != nil {
		return nil, trace.Wrap(err)
	}

	return a.sessions.GetSessions(namespace)
}

func (a *WithRoles) GetSession(namespace string, id session.ID) (*session.Session, error) {
	if err := a.action(namespace, types.KindSSHSession, types.VerbRead); err != nil {
		return nil, trace.Wrap(err)
	}
	return a.sessions.GetSession(namespace, id)
}

func (a *WithRoles) CreateSession(s session.Session) error {
	if err := a.action(s.Namespace, types.KindSSHSession, types.VerbCreate); err != nil {
		return trace.Wrap(err)
	}
	return a.sessions.CreateSession(s)
}

func (a *WithRoles) UpdateSession(req session.UpdateRequest) error {
	if err := a.action(req.Namespace, types.KindSSHSession, types.VerbUpdate); err != nil {
		return trace.Wrap(err)
	}
	return a.sessions.UpdateSession(req)
}

// DeleteSession removes an active session from the backend.
func (a *WithRoles) DeleteSession(namespace string, id session.ID) error {
	if err := a.action(namespace, types.KindSSHSession, types.VerbDelete); err != nil {
		return trace.Wrap(err)
	}
	return a.sessions.DeleteSession(namespace, id)
}

// RotateCertAuthority starts or restarts certificate authority rotation process.
func (a *WithRoles) RotateCertAuthority(req RotateRequest) error {
	if err := req.CheckAndSetDefaults(a.authServer.clock); err != nil {
		return trace.Wrap(err)
	}
	if err := a.action(defaults.Namespace, types.KindCertAuthority, types.VerbCreate); err != nil {
		return trace.Wrap(err)
	}
	if err := a.action(defaults.Namespace, types.KindCertAuthority, types.VerbUpdate); err != nil {
		return trace.Wrap(err)
	}
	return a.authServer.RotateCertAuthority(req)
}

// RotateExternalCertAuthority rotates external certificate authority,
// this method is called by a remote trusted cluster and is used to update
// only public keys and certificates of the certificate authority.
func (a *WithRoles) RotateExternalCertAuthority(ca types.CertAuthority) error {
	if ca == nil {
		return trace.BadParameter("missing certificate authority")
	}
	ctx := &auth.Context{User: a.context.User, Resource: ca}
	if err := a.actionWithContext(ctx, defaults.Namespace, types.KindCertAuthority, types.VerbRotate); err != nil {
		return trace.Wrap(err)
	}
	return a.authServer.RotateExternalCertAuthority(ca)
}

// UpsertCertAuthority updates existing cert authority or updates the existing one.
func (a *WithRoles) UpsertCertAuthority(ca types.CertAuthority) error {
	if ca == nil {
		return trace.BadParameter("missing certificate authority")
	}
	ctx := &auth.Context{User: a.context.User, Resource: ca}
	if err := a.actionWithContext(ctx, defaults.Namespace, types.KindCertAuthority, types.VerbCreate); err != nil {
		return trace.Wrap(err)
	}
	if err := a.actionWithContext(ctx, defaults.Namespace, types.KindCertAuthority, types.VerbUpdate); err != nil {
		return trace.Wrap(err)
	}
	return a.authServer.Services.Trust.UpsertCertAuthority(ca)
}

// CompareAndSwapCertAuthority updates existing cert authority if the existing cert authority
// value matches the value stored in the backend.
func (a *WithRoles) CompareAndSwapCertAuthority(new, existing types.CertAuthority) error {
	if err := a.action(defaults.Namespace, types.KindCertAuthority, types.VerbCreate); err != nil {
		return trace.Wrap(err)
	}
	if err := a.action(defaults.Namespace, types.KindCertAuthority, types.VerbUpdate); err != nil {
		return trace.Wrap(err)
	}
	return a.authServer.Services.Trust.CompareAndSwapCertAuthority(new, existing)
}

func (a *WithRoles) GetCertAuthorities(caType types.CertAuthType, loadKeys bool, opts ...auth.MarshalOption) ([]types.CertAuthority, error) {
	if err := a.action(defaults.Namespace, types.KindCertAuthority, types.VerbList); err != nil {
		return nil, trace.Wrap(err)
	}
	if err := a.action(defaults.Namespace, types.KindCertAuthority, types.VerbReadNoSecrets); err != nil {
		return nil, trace.Wrap(err)
	}
	if loadKeys {
		if err := a.action(defaults.Namespace, types.KindCertAuthority, types.VerbRead); err != nil {
			return nil, trace.Wrap(err)
		}
	}
	return a.authServer.GetCertAuthorities(caType, loadKeys, opts...)
}

func (a *WithRoles) GetCertAuthority(id types.CertAuthID, loadKeys bool, opts ...auth.MarshalOption) (types.CertAuthority, error) {
	if err := a.action(defaults.Namespace, types.KindCertAuthority, types.VerbReadNoSecrets); err != nil {
		return nil, trace.Wrap(err)
	}
	if loadKeys {
		if err := a.action(defaults.Namespace, types.KindCertAuthority, types.VerbRead); err != nil {
			return nil, trace.Wrap(err)
		}
	}
	return a.authServer.GetCertAuthority(id, loadKeys, opts...)
}

func (a *WithRoles) GetDomainName() (string, error) {
	// anyone can read it, no harm in that
	return a.authServer.GetDomainName()
}

func (a *WithRoles) GetLocalClusterName() (string, error) {
	// anyone can read it, no harm in that
	return a.authServer.Services.GetLocalClusterName()
}

// GetClusterCACert returns the CAs for the local cluster without signing keys.
func (a *WithRoles) GetClusterCACert() (*LocalCAResponse, error) {
	// Allow all roles to get the local CA.
	return a.authServer.GetClusterCACert()
}

func (a *WithRoles) UpsertLocalClusterName(clusterName string) error {
	if err := a.action(defaults.Namespace, types.KindAuthServer, types.VerbCreate); err != nil {
		return trace.Wrap(err)
	}
	if err := a.action(defaults.Namespace, types.KindAuthServer, types.VerbUpdate); err != nil {
		return trace.Wrap(err)
	}
	return a.authServer.Services.UpsertLocalClusterName(clusterName)
}

func (a *WithRoles) DeleteCertAuthority(id types.CertAuthID) error {
	if err := a.action(defaults.Namespace, types.KindCertAuthority, types.VerbDelete); err != nil {
		return trace.Wrap(err)
	}
	return a.authServer.Services.Trust.DeleteCertAuthority(id)
}

// GenerateToken generates multi-purpose authentication token.
func (a *WithRoles) GenerateToken(ctx context.Context, req GenerateTokenRequest) (string, error) {
	if err := a.action(defaults.Namespace, types.KindToken, types.VerbCreate); err != nil {
		return "", trace.Wrap(err)
	}
	return a.authServer.GenerateToken(ctx, req)
}

func (a *WithRoles) RegisterUsingToken(req RegisterUsingTokenRequest) (*PackedKeys, error) {
	// tokens have authz mechanism  on their own, no need to check
	return a.authServer.RegisterUsingToken(req)
}

func (a *WithRoles) RegisterNewAuthServer(token string) error {
	// tokens have authz mechanism  on their own, no need to check
	return a.authServer.RegisterNewAuthServer(token)
}

// GenerateServerKeys generates new host private keys and certificates (signed
// by the host certificate authority) for a node.
func (a *WithRoles) GenerateServerKeys(req GenerateServerKeysRequest) (*PackedKeys, error) {
	clusterName, err := a.authServer.GetDomainName()
	if err != nil {
		return nil, trace.Wrap(err)
	}
	// username is hostID + cluster name, so make sure server requests new keys for itself
	if a.context.User.GetName() != HostFQDN(req.HostID, clusterName) {
		return nil, trace.AccessDenied("username mismatch %q and %q", a.context.User.GetName(), HostFQDN(req.HostID, clusterName))
	}
	existingRoles, err := teleport.NewRoles(a.context.User.GetRoles())
	if err != nil {
		return nil, trace.Wrap(err)
	}
	// prohibit privilege escalations through role changes
	if !existingRoles.Equals(req.Roles) {
		return nil, trace.AccessDenied("roles do not match: %v and %v", existingRoles, req.Roles)
	}
	return a.authServer.GenerateServerKeys(req)
}

// UpsertNodes bulk upserts nodes into the backend.
func (a *WithRoles) UpsertNodes(namespace string, servers []types.Server) error {
	if err := a.action(namespace, types.KindNode, types.VerbCreate); err != nil {
		return trace.Wrap(err)
	}
	if err := a.action(namespace, types.KindNode, types.VerbUpdate); err != nil {
		return trace.Wrap(err)
	}
	return a.authServer.Services.UpsertNodes(namespace, servers)
}

func (a *WithRoles) UpsertNode(s types.Server) (*types.KeepAlive, error) {
	if err := a.action(s.GetNamespace(), types.KindNode, types.VerbCreate); err != nil {
		return nil, trace.Wrap(err)
	}
	if err := a.action(s.GetNamespace(), types.KindNode, types.VerbUpdate); err != nil {
		return nil, trace.Wrap(err)
	}
	return a.authServer.Services.UpsertNode(s)
}

// DELETE IN: 5.1.0
//
// This logic has moved to KeepAliveServer.
func (a *WithRoles) KeepAliveNode(ctx context.Context, handle types.KeepAlive) error {
	if !a.hasBuiltinRole(string(teleport.RoleNode)) {
		return trace.AccessDenied("[10] access denied")
	}
	clusterName, err := a.GetDomainName()
	if err != nil {
		return trace.Wrap(err)
	}
	serverName, err := ExtractHostID(a.context.User.GetName(), clusterName)
	if err != nil {
		return trace.AccessDenied("[10] access denied")
	}
	if serverName != handle.Name {
		return trace.AccessDenied("[10] access denied")
	}
	if err := a.action(defaults.Namespace, types.KindNode, types.VerbUpdate); err != nil {
		return trace.Wrap(err)
	}
	return a.authServer.Services.KeepAliveNode(ctx, handle)
}

// KeepAliveServer updates expiry time of a server resource.
func (a *WithRoles) KeepAliveServer(ctx context.Context, handle types.KeepAlive) error {
	clusterName, err := a.GetDomainName()
	if err != nil {
		return trace.Wrap(err)
	}
	serverName, err := ExtractHostID(a.context.User.GetName(), clusterName)
	if err != nil {
		return trace.AccessDenied("access denied")
	}

	switch handle.GetType() {
	case teleport.KeepAliveNode:
		if serverName != handle.Name {
			return trace.AccessDenied("access denied")
		}
		if !a.hasBuiltinRole(string(teleport.RoleNode)) {
			return trace.AccessDenied("access denied")
		}
		if err := a.action(defaults.Namespace, types.KindNode, types.VerbUpdate); err != nil {
			return trace.Wrap(err)
		}
	case teleport.KeepAliveApp:
		if serverName != handle.Name {
			return trace.AccessDenied("access denied")
		}
		if !a.hasBuiltinRole(string(teleport.RoleApp)) {
			return trace.AccessDenied("access denied")
		}
		if err := a.action(defaults.Namespace, types.KindAppServer, types.VerbUpdate); err != nil {
			return trace.Wrap(err)
		}
	case teleport.KeepAliveDatabase:
		// There can be multiple database servers per host so they send their
		// host ID in a separate field because unlike SSH nodes the resource
		// name cannot be the host ID.
		if serverName != handle.HostID {
			return trace.AccessDenied("access denied")
		}
		if !a.hasBuiltinRole(string(teleport.RoleDatabase)) {
			return trace.AccessDenied("access denied")
		}
		if err := a.action(defaults.Namespace, types.KindDatabaseServer, types.VerbUpdate); err != nil {
			return trace.Wrap(err)
		}
	default:
		return trace.BadParameter("unknown keep alive type %q", handle.Type)
	}

	return a.authServer.Services.KeepAliveServer(ctx, handle)
}

// NewWatcher returns a new event watcher
func (a *WithRoles) NewWatcher(ctx context.Context, watch types.Watch) (types.Watcher, error) {
	if len(watch.Kinds) == 0 {
		return nil, trace.AccessDenied("can't setup global watch")
	}
	for _, kind := range watch.Kinds {
		// Check the permissions for data of each kind. For watching, most
		// kinds of data just need a Read permission, but some have more
		// complicated logic.
		switch kind.Kind {
		case types.KindCertAuthority:
			if kind.LoadSecrets {
				if err := a.action(defaults.Namespace, types.KindCertAuthority, types.VerbRead); err != nil {
					return nil, trace.Wrap(err)
				}
			} else {
				if err := a.action(defaults.Namespace, types.KindCertAuthority, types.VerbReadNoSecrets); err != nil {
					return nil, trace.Wrap(err)
				}
			}
		case types.KindAccessRequest:
			var filter types.AccessRequestFilter
			if err := filter.FromMap(kind.Filter); err != nil {
				return nil, trace.Wrap(err)
			}
			if filter.User == "" || a.currentUserAction(filter.User) != nil {
				if err := a.action(defaults.Namespace, types.KindAccessRequest, types.VerbRead); err != nil {
					return nil, trace.Wrap(err)
				}
			}
		case types.KindAppServer:
			if err := a.action(defaults.Namespace, types.KindAppServer, types.VerbRead); err != nil {
				return nil, trace.Wrap(err)
			}
		case types.KindWebSession:
			if err := a.action(defaults.Namespace, types.KindWebSession, types.VerbRead); err != nil {
				return nil, trace.Wrap(err)
			}
		case types.KindWebToken:
			if err := a.action(defaults.Namespace, types.KindWebToken, types.VerbRead); err != nil {
				return nil, trace.Wrap(err)
			}
		case types.KindRemoteCluster:
			if err := a.action(defaults.Namespace, types.KindRemoteCluster, types.VerbRead); err != nil {
				return nil, trace.Wrap(err)
			}
		case types.KindDatabaseServer:
			if err := a.action(defaults.Namespace, types.KindDatabaseServer, types.VerbRead); err != nil {
				return nil, trace.Wrap(err)
			}
		default:
			if err := a.action(defaults.Namespace, kind.Kind, types.VerbRead); err != nil {
				return nil, trace.Wrap(err)
			}
		}
	}
	switch {
	case a.hasBuiltinRole(string(teleport.RoleProxy)):
		watch.QueueSize = defaults.ProxyQueueSize
	case a.hasBuiltinRole(string(teleport.RoleNode)):
		watch.QueueSize = defaults.NodeQueueSize
	}
	return a.authServer.NewWatcher(ctx, watch)
}

// filterNodes filters nodes based off the role of the logged in user.
func (a *WithRoles) filterNodes(nodes []types.Server) ([]types.Server, error) {
	// For certain built-in roles, continue to allow full access and return
	// the full set of nodes to not break existing clusters during migration.
	//
	// In addition, allow proxy (and remote proxy) to access all nodes for it's
	// smart resolution address resolution. Once the smart resolution logic is
	// moved to the auth server, this logic can be removed.
	if a.hasBuiltinRole(string(teleport.RoleAdmin)) ||
		a.hasBuiltinRole(string(teleport.RoleProxy)) ||
		a.hasRemoteBuiltinRole(string(teleport.RoleRemoteProxy)) {
		return nodes, nil
	}

	roleset, err := auth.FetchRoles(a.context.User.GetRoles(), a.authServer, a.context.User.GetTraits())
	if err != nil {
		return nil, trace.Wrap(err)
	}

	// Extract all unique allowed logins across all roles.
	allowedLogins := make(map[string]bool)
	for _, role := range roleset {
		for _, login := range role.GetLogins(types.Allow) {
			allowedLogins[login] = true
		}
	}

	// Loop over all nodes and check if the caller has access.
	filteredNodes := make([]types.Server, 0, len(nodes))
	// MFA is not required to list the nodes, but will be required to connect
	// to them.
	mfaVerified := true
NextNode:
	for _, node := range nodes {
		for login := range allowedLogins {
			err := roleset.CheckAccessToServer(login, node, mfaVerified)
			if err == nil {
				filteredNodes = append(filteredNodes, node)
				continue NextNode
			}
		}
	}

	return filteredNodes, nil
}

// DeleteAllNodes deletes all nodes in a given namespace
func (a *WithRoles) DeleteAllNodes(namespace string) error {
	if err := a.action(namespace, types.KindNode, types.VerbDelete); err != nil {
		return trace.Wrap(err)
	}
	return a.authServer.Services.DeleteAllNodes(namespace)
}

// DeleteNode deletes node in the namespace
func (a *WithRoles) DeleteNode(namespace, node string) error {
	if err := a.action(namespace, types.KindNode, types.VerbDelete); err != nil {
		return trace.Wrap(err)
	}
	return a.authServer.Services.DeleteNode(namespace, node)
}

func (a *WithRoles) GetNodes(namespace string, opts ...auth.MarshalOption) ([]types.Server, error) {
	if err := a.action(namespace, types.KindNode, types.VerbList); err != nil {
		return nil, trace.Wrap(err)
	}

	// Fetch full list of nodes in the backend.
	startFetch := time.Now()
	nodes, err := a.authServer.GetNodes(namespace, opts...)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	elapsedFetch := time.Since(startFetch)

	// Filter nodes to return the ones for the connected identity.
	startFilter := time.Now()
	filteredNodes, err := a.filterNodes(nodes)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	elapsedFilter := time.Since(startFilter)

	log.WithFields(logrus.Fields{
		"user":           a.context.User.GetName(),
		"elapsed_fetch":  elapsedFetch,
		"elapsed_filter": elapsedFilter,
	}).Debugf("GetServers(%v->%v) in %v.",
		len(nodes), len(filteredNodes), elapsedFetch+elapsedFilter)

	return filteredNodes, nil
}

func (a *WithRoles) UpsertAuthServer(s types.Server) error {
	if err := a.action(defaults.Namespace, types.KindAuthServer, types.VerbCreate); err != nil {
		return trace.Wrap(err)
	}
	if err := a.action(defaults.Namespace, types.KindAuthServer, types.VerbUpdate); err != nil {
		return trace.Wrap(err)
	}
	return a.authServer.Services.UpsertAuthServer(s)
}

func (a *WithRoles) GetAuthServers() ([]types.Server, error) {
	if err := a.action(defaults.Namespace, types.KindAuthServer, types.VerbList); err != nil {
		return nil, trace.Wrap(err)
	}
	if err := a.action(defaults.Namespace, types.KindAuthServer, types.VerbRead); err != nil {
		return nil, trace.Wrap(err)
	}
	return a.authServer.Services.GetAuthServers()
}

// DeleteAllAuthServers deletes all auth servers
func (a *WithRoles) DeleteAllAuthServers() error {
	if err := a.action(defaults.Namespace, types.KindAuthServer, types.VerbDelete); err != nil {
		return trace.Wrap(err)
	}
	return a.authServer.Services.DeleteAllAuthServers()
}

// DeleteAuthServer deletes auth server by name
func (a *WithRoles) DeleteAuthServer(name string) error {
	if err := a.action(defaults.Namespace, types.KindAuthServer, types.VerbDelete); err != nil {
		return trace.Wrap(err)
	}
	return a.authServer.Services.DeleteAuthServer(name)
}

func (a *WithRoles) UpsertProxy(s types.Server) error {
	if err := a.action(defaults.Namespace, types.KindProxy, types.VerbCreate); err != nil {
		return trace.Wrap(err)
	}
	if err := a.action(defaults.Namespace, types.KindProxy, types.VerbUpdate); err != nil {
		return trace.Wrap(err)
	}
	return a.authServer.Services.UpsertProxy(s)
}

func (a *WithRoles) GetProxies() ([]types.Server, error) {
	if err := a.action(defaults.Namespace, types.KindProxy, types.VerbList); err != nil {
		return nil, trace.Wrap(err)
	}
	if err := a.action(defaults.Namespace, types.KindProxy, types.VerbRead); err != nil {
		return nil, trace.Wrap(err)
	}
	return a.authServer.GetProxies()
}

// DeleteAllProxies deletes all proxies
func (a *WithRoles) DeleteAllProxies() error {
	if err := a.action(defaults.Namespace, types.KindProxy, types.VerbDelete); err != nil {
		return trace.Wrap(err)
	}
	return a.authServer.Services.DeleteAllProxies()
}

// DeleteProxy deletes proxy by name
func (a *WithRoles) DeleteProxy(name string) error {
	if err := a.action(defaults.Namespace, types.KindProxy, types.VerbDelete); err != nil {
		return trace.Wrap(err)
	}
	return a.authServer.Services.DeleteProxy(name)
}

func (a *WithRoles) UpsertReverseTunnel(r types.ReverseTunnel) error {
	if err := a.action(defaults.Namespace, types.KindReverseTunnel, types.VerbCreate); err != nil {
		return trace.Wrap(err)
	}
	if err := a.action(defaults.Namespace, types.KindReverseTunnel, types.VerbUpdate); err != nil {
		return trace.Wrap(err)
	}
	return a.authServer.Services.UpsertReverseTunnel(r)
}

func (a *WithRoles) GetReverseTunnel(name string, opts ...auth.MarshalOption) (types.ReverseTunnel, error) {
	if err := a.action(defaults.Namespace, types.KindReverseTunnel, types.VerbRead); err != nil {
		return nil, trace.Wrap(err)
	}
	return a.authServer.Services.GetReverseTunnel(name, opts...)
}

func (a *WithRoles) GetReverseTunnels(opts ...auth.MarshalOption) ([]types.ReverseTunnel, error) {
	if err := a.action(defaults.Namespace, types.KindReverseTunnel, types.VerbList); err != nil {
		return nil, trace.Wrap(err)
	}
	if err := a.action(defaults.Namespace, types.KindReverseTunnel, types.VerbRead); err != nil {
		return nil, trace.Wrap(err)
	}
	return a.authServer.GetReverseTunnels(opts...)
}

func (a *WithRoles) DeleteReverseTunnel(domainName string) error {
	if err := a.action(defaults.Namespace, types.KindReverseTunnel, types.VerbDelete); err != nil {
		return trace.Wrap(err)
	}
	return a.authServer.Services.DeleteReverseTunnel(domainName)
}

func (a *WithRoles) DeleteToken(token string) error {
	if err := a.action(defaults.Namespace, types.KindToken, types.VerbDelete); err != nil {
		return trace.Wrap(err)
	}
	return a.authServer.DeleteToken(token)
}

func (a *WithRoles) GetTokens(opts ...auth.MarshalOption) ([]types.ProvisionToken, error) {
	if err := a.action(defaults.Namespace, types.KindToken, types.VerbList); err != nil {
		return nil, trace.Wrap(err)
	}
	if err := a.action(defaults.Namespace, types.KindToken, types.VerbRead); err != nil {
		return nil, trace.Wrap(err)
	}
	return a.authServer.GetTokens(opts...)
}

func (a *WithRoles) GetToken(token string) (types.ProvisionToken, error) {
	if err := a.action(defaults.Namespace, types.KindToken, types.VerbRead); err != nil {
		return nil, trace.Wrap(err)
	}
	return a.authServer.GetToken(token)
}

func (a *WithRoles) UpsertToken(token types.ProvisionToken) error {
	if err := a.action(defaults.Namespace, types.KindToken, types.VerbCreate); err != nil {
		return trace.Wrap(err)
	}
	if err := a.action(defaults.Namespace, types.KindToken, types.VerbUpdate); err != nil {
		return trace.Wrap(err)
	}
	return a.authServer.Services.UpsertToken(token)
}

func (a *WithRoles) UpsertPassword(user string, password []byte) error {
	if err := a.currentUserAction(user); err != nil {
		return trace.Wrap(err)
	}
	return a.authServer.Services.UpsertPassword(user, password)
}

// ChangePassword updates users password based on the old password.
func (a *WithRoles) ChangePassword(req auth.ChangePasswordReq) error {
	if err := a.currentUserAction(req.User); err != nil {
		return trace.Wrap(err)
	}
	return a.authServer.ChangePassword(req)
}

func (a *WithRoles) CheckPassword(user string, password []byte, otpToken string) error {
	if err := a.currentUserAction(user); err != nil {
		return trace.Wrap(err)
	}
	return a.authServer.CheckPassword(user, password, otpToken)
}

func (a *WithRoles) PreAuthenticatedSignIn(user string) (types.WebSession, error) {
	if err := a.currentUserAction(user); err != nil {
		return nil, trace.Wrap(err)
	}
	return a.authServer.PreAuthenticatedSignIn(user, a.context.Identity.GetIdentity())
}

func (a *WithRoles) GetMFAAuthenticateChallenge(user string, password []byte) (*MFAAuthenticateChallenge, error) {
	// we are already checking password here, no need to extra permission check
	// anyone who has user's password can generate sign request
	return a.authServer.GetMFAAuthenticateChallenge(user, password)
}

// CreateWebSession creates a new web session for the specified user
func (a *WithRoles) CreateWebSession(user string) (types.WebSession, error) {
	if err := a.currentUserAction(user); err != nil {
		return nil, trace.Wrap(err)
	}
	return a.authServer.CreateWebSession(user)
}

// ExtendWebSession creates a new web session for a user based on a valid previous session.
// Additional roles are appended to initial roles if there is an approved access request.
// The new session expiration time will not exceed the expiration time of the old session.
func (a *WithRoles) ExtendWebSession(user, prevSessionID, accessRequestID string) (types.WebSession, error) {
	if err := a.currentUserAction(user); err != nil {
		return nil, trace.Wrap(err)
	}
	return a.authServer.ExtendWebSession(user, prevSessionID, accessRequestID, a.context.Identity.GetIdentity())
}

// GetWebSessionInfo returns the web session for the given user specified with sid.
// The session is stripped of any authentication details.
// Implements auth.WebUIService
func (a *WithRoles) GetWebSessionInfo(ctx context.Context, user, sessionID string) (types.WebSession, error) {
	if err := a.currentUserAction(user); err != nil {
		return nil, trace.Wrap(err)
	}
	return a.authServer.GetWebSessionInfo(ctx, user, sessionID)
}

// GetWebSession returns the web session specified with req.
// Implements auth.ReadAccessPoint.
func (a *WithRoles) GetWebSession(ctx context.Context, req types.GetWebSessionRequest) (types.WebSession, error) {
	return a.WebSessions().Get(ctx, req)
}

// WebSessions returns the web session manager.
// Implements types.WebSessionsGetter.
func (a *WithRoles) WebSessions() types.WebSessionInterface {
	return &webSessionsWithRoles{c: a, ws: a.authServer.Services.WebSessions()}
}

// Get returns the web session specified with req.
func (r *webSessionsWithRoles) Get(ctx context.Context, req types.GetWebSessionRequest) (types.WebSession, error) {
	if err := r.c.currentUserAction(req.User); err != nil {
		if err := r.c.action(defaults.Namespace, types.KindWebSession, types.VerbRead); err != nil {
			return nil, trace.Wrap(err)
		}
	}
	return r.ws.Get(ctx, req)
}

// List returns the list of all web sessions.
func (r *webSessionsWithRoles) List(ctx context.Context) ([]types.WebSession, error) {
	if err := r.c.action(defaults.Namespace, types.KindWebSession, types.VerbList); err != nil {
		return nil, trace.Wrap(err)
	}
	if err := r.c.action(defaults.Namespace, types.KindWebSession, types.VerbRead); err != nil {
		return nil, trace.Wrap(err)
	}
	return r.ws.List(ctx)
}

// Delete removes the web session specified with req.
func (r *webSessionsWithRoles) Delete(ctx context.Context, req types.DeleteWebSessionRequest) error {
	if err := r.c.currentUserAction(req.User); err != nil {
		if err := r.c.action(defaults.Namespace, types.KindWebSession, types.VerbDelete); err != nil {
			return trace.Wrap(err)
		}
	}
	return r.ws.Delete(ctx, req)
}

// DeleteAll removes all web sessions.
func (r *webSessionsWithRoles) DeleteAll(ctx context.Context) error {
	if err := r.c.action(defaults.Namespace, types.KindWebSession, types.VerbList); err != nil {
		return trace.Wrap(err)
	}
	if err := r.c.action(defaults.Namespace, types.KindWebSession, types.VerbDelete); err != nil {
		return trace.Wrap(err)
	}
	return r.ws.DeleteAll(ctx)
}

// GetWebToken returns the web token specified with req.
// Implements auth.ReadAccessPoint.
func (a *WithRoles) GetWebToken(ctx context.Context, req types.GetWebTokenRequest) (types.WebToken, error) {
	return a.WebTokens().Get(ctx, req)
}

type webSessionsWithRoles struct {
	c  accessChecker
	ws types.WebSessionInterface
}

// WebTokens returns the web token manager.
// Implements types.WebTokensGetter.
func (a *WithRoles) WebTokens() types.WebTokenInterface {
	return &webTokensWithRoles{c: a, t: a.authServer.Services.WebTokens()}
}

// Get returns the web token specified with req.
func (r *webTokensWithRoles) Get(ctx context.Context, req types.GetWebTokenRequest) (types.WebToken, error) {
	if err := r.c.currentUserAction(req.User); err != nil {
		if err := r.c.action(defaults.Namespace, types.KindWebToken, types.VerbRead); err != nil {
			return nil, trace.Wrap(err)
		}
	}
	return r.t.Get(ctx, req)
}

// List returns the list of all web tokens.
func (r *webTokensWithRoles) List(ctx context.Context) ([]types.WebToken, error) {
	if err := r.c.action(defaults.Namespace, types.KindWebToken, types.VerbList); err != nil {
		return nil, trace.Wrap(err)
	}
	return r.t.List(ctx)
}

// Delete removes the web token specified with req.
func (r *webTokensWithRoles) Delete(ctx context.Context, req types.DeleteWebTokenRequest) error {
	if err := r.c.currentUserAction(req.User); err != nil {
		if err := r.c.action(defaults.Namespace, types.KindWebToken, types.VerbDelete); err != nil {
			return trace.Wrap(err)
		}
	}
	return r.t.Delete(ctx, req)
}

// DeleteAll removes all web tokens.
func (r *webTokensWithRoles) DeleteAll(ctx context.Context) error {
	if err := r.c.action(defaults.Namespace, types.KindWebToken, types.VerbList); err != nil {
		return trace.Wrap(err)
	}
	if err := r.c.action(defaults.Namespace, types.KindWebToken, types.VerbDelete); err != nil {
		return trace.Wrap(err)
	}
	return r.t.DeleteAll(ctx)
}

type webTokensWithRoles struct {
	c accessChecker
	t types.WebTokenInterface
}

type accessChecker interface {
	action(namespace, resource, action string) error
	currentUserAction(user string) error
}

func (a *WithRoles) GetAccessRequests(ctx context.Context, filter types.AccessRequestFilter) ([]types.AccessRequest, error) {
	// An exception is made to allow users to get their own access requests.
	if filter.User == "" || a.currentUserAction(filter.User) != nil {
		if err := a.action(defaults.Namespace, types.KindAccessRequest, types.VerbList); err != nil {
			return nil, trace.Wrap(err)
		}
		if err := a.action(defaults.Namespace, types.KindAccessRequest, types.VerbRead); err != nil {
			return nil, trace.Wrap(err)
		}
	}
	return a.authServer.Services.GetAccessRequests(ctx, filter)
}

func (a *WithRoles) CreateAccessRequest(ctx context.Context, req types.AccessRequest) error {
	// An exception is made to allow users to create access *pending* requests for themselves.
	if !req.GetState().IsPending() || a.currentUserAction(req.GetUser()) != nil {
		if err := a.action(defaults.Namespace, types.KindAccessRequest, types.VerbCreate); err != nil {
			return trace.Wrap(err)
		}
	}
	// Ensure that an access request cannot outlive the identity that creates it.
	if req.GetAccessExpiry().Before(a.authServer.GetClock().Now()) || req.GetAccessExpiry().After(a.context.Identity.GetIdentity().Expires) {
		req.SetAccessExpiry(a.context.Identity.GetIdentity().Expires)
	}
	return a.authServer.CreateAccessRequest(ctx, req)
}

func (a *WithRoles) SetAccessRequestState(ctx context.Context, params types.AccessRequestUpdate) error {
	if err := a.action(defaults.Namespace, types.KindAccessRequest, types.VerbUpdate); err != nil {
		return trace.Wrap(err)
	}
	return a.authServer.SetAccessRequestState(ctx, params)
}

func (a *WithRoles) GetAccessCapabilities(ctx context.Context, req types.AccessCapabilitiesRequest) (*types.AccessCapabilities, error) {
	// default to checking the capabilities of the caller
	if req.User == "" {
		req.User = a.context.User.GetName()
	}

	// all users can check their own capabilities
	if a.currentUserAction(req.User) != nil {
		if err := a.action(defaults.Namespace, types.KindUser, types.VerbRead); err != nil {
			return nil, trace.Wrap(err)
		}
		if err := a.action(defaults.Namespace, types.KindRole, types.VerbList); err != nil {
			return nil, trace.Wrap(err)
		}
		if err := a.action(defaults.Namespace, types.KindRole, types.VerbRead); err != nil {
			return nil, trace.Wrap(err)
		}
	}

	return a.authServer.GetAccessCapabilities(ctx, req)
}

// GetPluginData loads all plugin data matching the supplied filter.
func (a *WithRoles) GetPluginData(ctx context.Context, filter types.PluginDataFilter) ([]types.PluginData, error) {
	switch filter.Kind {
	case types.KindAccessRequest:
		if err := a.action(defaults.Namespace, types.KindAccessRequest, types.VerbList); err != nil {
			return nil, trace.Wrap(err)
		}
		if err := a.action(defaults.Namespace, types.KindAccessRequest, types.VerbRead); err != nil {
			return nil, trace.Wrap(err)
		}
		return a.authServer.Services.GetPluginData(ctx, filter)
	default:
		return nil, trace.BadParameter("unsupported resource kind %q", filter.Kind)
	}
}

// UpdatePluginData updates a per-resource PluginData entry.
func (a *WithRoles) UpdatePluginData(ctx context.Context, params types.PluginDataUpdateParams) error {
	switch params.Kind {
	case types.KindAccessRequest:
		if err := a.action(defaults.Namespace, types.KindAccessRequest, types.VerbUpdate); err != nil {
			return trace.Wrap(err)
		}
		return a.authServer.Services.UpdatePluginData(ctx, params)
	default:
		return trace.BadParameter("unsupported resource kind %q", params.Kind)
	}
}

// Ping gets basic info about the auth server.
func (a *WithRoles) Ping(ctx context.Context) (proto.PingResponse, error) {
	// The Ping method does not require special permissions since it only returns
	// basic status information.  This is an intentional design choice.  Alternative
	// methods should be used for relaying any sensitive information.
	cn, err := a.authServer.GetClusterName()
	if err != nil {
		return proto.PingResponse{}, trace.Wrap(err)
	}
	return proto.PingResponse{
		ClusterName:   cn.GetClusterName(),
		ServerVersion: teleport.Version,
	}, nil
}

func (a *WithRoles) DeleteAccessRequest(ctx context.Context, name string) error {
	if err := a.action(defaults.Namespace, types.KindAccessRequest, types.VerbUpdate); err != nil {
		return trace.Wrap(err)
	}
	return a.authServer.Services.DeleteAccessRequest(ctx, name)
}

func (a *WithRoles) GetUsers(withSecrets bool) ([]types.User, error) {
	if withSecrets {
		// TODO(fspmarshall): replace admin requirement with VerbReadWithSecrets once we've
		// migrated to that model.
		if !a.hasBuiltinRole(string(teleport.RoleAdmin)) {
			err := trace.AccessDenied("user %q requested access to all users with secrets", a.context.User.GetName())
			log.Warning(err)
			if err := a.authServer.emitter.EmitAuditEvent(a.authServer.closeCtx, &events.UserLogin{
				Metadata: events.Metadata{
					Type: events.UserLoginEvent,
					Code: events.UserLocalLoginFailureCode,
				},
				Method: events.LoginMethodClientCert,
				Status: events.Status{
					Success:     false,
					Error:       trace.Unwrap(err).Error(),
					UserMessage: err.Error(),
				},
			}); err != nil {
				log.WithError(err).Warn("Failed to emit local login failure event.")
			}
			return nil, trace.AccessDenied("this request can be only executed by an admin")
		}
	} else {
		if err := a.action(defaults.Namespace, types.KindUser, types.VerbList); err != nil {
			return nil, trace.Wrap(err)
		}
		if err := a.action(defaults.Namespace, types.KindUser, types.VerbRead); err != nil {
			return nil, trace.Wrap(err)
		}
	}
	return a.authServer.GetUsers(withSecrets)
}

func (a *WithRoles) GetUser(name string, withSecrets bool) (types.User, error) {
	if withSecrets {
		// TODO(fspmarshall): replace admin requirement with VerbReadWithSecrets once we've
		// migrated to that model.
		if !a.hasBuiltinRole(string(teleport.RoleAdmin)) {
			err := trace.AccessDenied("user %q requested access to user %q with secrets", a.context.User.GetName(), name)
			log.Warning(err)
			if err := a.authServer.emitter.EmitAuditEvent(a.authServer.closeCtx, &events.UserLogin{
				Metadata: events.Metadata{
					Type: events.UserLoginEvent,
					Code: events.UserLocalLoginFailureCode,
				},
				Method: events.LoginMethodClientCert,
				Status: events.Status{
					Success:     false,
					Error:       trace.Unwrap(err).Error(),
					UserMessage: err.Error(),
				},
			}); err != nil {
				log.WithError(err).Warn("Failed to emit local login failure event.")
			}
			return nil, trace.AccessDenied("this request can be only executed by an admin")
		}
	} else {
		// if secrets are not being accessed, let users always read
		// their own info.
		if err := a.currentUserAction(name); err != nil {
			// not current user, perform normal permission check.
			if err := a.action(defaults.Namespace, types.KindUser, types.VerbRead); err != nil {
				return nil, trace.Wrap(err)
			}
		}
	}
	return a.authServer.Services.Identity.GetUser(name, withSecrets)
}

// DeleteUser deletes an existng user in a backend by username.
func (a *WithRoles) DeleteUser(ctx context.Context, user string) error {
	if err := a.action(defaults.Namespace, types.KindUser, types.VerbDelete); err != nil {
		return trace.Wrap(err)
	}

	return a.authServer.DeleteUser(ctx, user)
}

func (a *WithRoles) GenerateKeyPair(pass string) ([]byte, []byte, error) {
	if err := a.action(defaults.Namespace, types.KindKeyPair, types.VerbCreate); err != nil {
		return nil, nil, trace.Wrap(err)
	}
	return a.authServer.GenerateKeyPair(pass)
}

func (a *WithRoles) GenerateHostCert(
	key []byte, hostID, nodeName string, principals []string, clusterName string, roles teleport.Roles, ttl time.Duration) ([]byte, error) {

	if err := a.action(defaults.Namespace, types.KindHostCert, types.VerbCreate); err != nil {
		return nil, trace.Wrap(err)
	}
	return a.authServer.GenerateHostCert(key, hostID, nodeName, principals, clusterName, roles, ttl)
}

// GenerateUserCerts generates users certificates
func (a *WithRoles) GenerateUserCerts(ctx context.Context, req proto.UserCertsRequest) (*proto.Certs, error) {
	return a.generateUserCerts(ctx, req)
}

func (a *WithRoles) generateUserCerts(ctx context.Context, req proto.UserCertsRequest, opts ...certRequestOption) (*proto.Certs, error) {
	var err error
	var roles []string
	var traits wrappers.Traits

	switch {
	case a.hasBuiltinRole(string(teleport.RoleAdmin)):
		// If it's an admin generating the certificate, the roles and traits for
		// the user have to be fetched from the backend. This should be safe since
		// this is typically done against a local user.
		user, err := a.GetUser(req.Username, false)
		if err != nil {
			return nil, trace.Wrap(err)
		}
		roles = user.GetRoles()
		traits = user.GetTraits()
	case req.Username == a.context.User.GetName():
		// user is requesting TTL for themselves,
		// limit the TTL to the duration of the session, to prevent
		// users renewing their certificates forever
		expires := a.context.Identity.GetIdentity().Expires
		if expires.IsZero() {
			log.Warningf("Encountered identity with no expiry: %v and denied request. Must be internal logic error.", a.context.Identity)
			return nil, trace.AccessDenied("access denied")
		}
		if req.Expires.After(expires) {
			req.Expires = expires
		}
		if req.Expires.Before(a.authServer.GetClock().Now()) {
			return nil, trace.AccessDenied("access denied: client credentials have expired, please relogin.")
		}
		// If the user is generating a certificate, the roles and traits come from
		// the logged in identity.
		roles, traits, err = resource.ExtractFromIdentity(a.authServer, a.context.Identity.GetIdentity())
		if err != nil {
			return nil, trace.Wrap(err)
		}
	default:
		err := trace.AccessDenied("user %q has requested to generate certs for %q.", a.context.User.GetName(), req.Username)
		log.Warning(err)
		if err := a.authServer.emitter.EmitAuditEvent(a.CloseContext(), &events.UserLogin{
			Metadata: events.Metadata{
				Type: events.UserLoginEvent,
				Code: events.UserLocalLoginFailureCode,
			},
			Method: events.LoginMethodClientCert,
			Status: events.Status{
				Success:     false,
				Error:       trace.Unwrap(err).Error(),
				UserMessage: err.Error(),
			},
		}); err != nil {
			log.WithError(err).Warn("Failed to emit local login failure event.")
		}
		// this error is vague on purpose, it should not happen unless someone is trying something out of loop
		return nil, trace.AccessDenied("this request can be only executed by an admin")
	}

	if len(req.AccessRequests) > 0 {
		// add any applicable access request values.
		for _, reqID := range req.AccessRequests {
			accessReq, err := auth.GetAccessRequest(ctx, a.authServer.Services, reqID)
			if err != nil {
				if trace.IsNotFound(err) {
					return nil, trace.AccessDenied("invalid access request %q", reqID)
				}
				return nil, trace.Wrap(err)
			}
			if accessReq.GetUser() != req.Username {
				return nil, trace.AccessDenied("invalid access request %q", reqID)
			}
			if !accessReq.GetState().IsApproved() {
				if accessReq.GetState().IsDenied() {
					return nil, trace.AccessDenied("access-request %q has been denied", reqID)
				}
				return nil, trace.AccessDenied("access-request %q is awaiting approval", reqID)
			}
			if err := auth.ValidateAccessRequestForUser(a.authServer, accessReq); err != nil {
				return nil, trace.Wrap(err)
			}
			aexp := accessReq.GetAccessExpiry()
			if aexp.Before(a.authServer.GetClock().Now()) {
				return nil, trace.AccessDenied("access-request %q is expired", reqID)
			}
			if aexp.Before(req.Expires) {
				// cannot generate a cert that would outlive the access request
				req.Expires = aexp
			}
			roles = append(roles, accessReq.GetRoles()...)
		}
		// nothing prevents an access-request from including roles already possessed by the
		// user, so we must make sure to trim duplicate roles.
		roles = utils.Deduplicate(roles)
	}

	// Extract the user and role set for whom the certificate will be generated.
	user, err := a.GetUser(req.Username, false)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	checker, err := auth.FetchRoles(roles, a.authServer, traits)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	// Generate certificate, note that the roles TTL will be ignored because
	// the request is coming from "tctl auth sign" itself.
	certReq := certRequest{
		user:              user,
		ttl:               req.Expires.Sub(a.authServer.GetClock().Now()),
		compatibility:     req.Format,
		publicKey:         req.PublicKey,
		overrideRoleTTL:   a.hasBuiltinRole(string(teleport.RoleAdmin)),
		routeToCluster:    req.RouteToCluster,
		kubernetesCluster: req.KubernetesCluster,
		dbService:         req.RouteToDatabase.ServiceName,
		dbProtocol:        req.RouteToDatabase.Protocol,
		dbUser:            req.RouteToDatabase.Username,
		dbName:            req.RouteToDatabase.Database,
		checker:           checker,
		traits:            traits,
		activeRequests: auth.RequestIDs{
			AccessRequests: req.AccessRequests,
		},
	}
	switch req.Usage {
	case proto.UserCertsRequest_Database:
		certReq.usage = []string{teleport.UsageDatabaseOnly}
	case proto.UserCertsRequest_Kubernetes:
		certReq.usage = []string{teleport.UsageKubeOnly}
	case proto.UserCertsRequest_SSH:
		// SSH certs are ssh-only by definition, certReq.usage only applies to
		// TLS certs.
	case proto.UserCertsRequest_All:
		// Unrestricted usage.
	default:
		return nil, trace.BadParameter("unsupported cert usage %q", req.Usage)
	}
	for _, o := range opts {
		o(&certReq)
	}
	certs, err := a.authServer.generateUserCert(certReq)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	return &proto.Certs{
		SSH: certs.ssh,
		TLS: certs.tls,
	}, nil
}

func (a *WithRoles) GetSignupU2FRegisterRequest(token string) (*u2f.RegisterChallenge, error) {
	// signup token are their own authz resource
	return a.authServer.CreateSignupU2FRegisterRequest(token)
}

func (a *WithRoles) CreateResetPasswordToken(ctx context.Context, req CreateResetPasswordTokenRequest) (types.ResetPasswordToken, error) {
	if err := a.action(defaults.Namespace, types.KindUser, types.VerbUpdate); err != nil {
		return nil, trace.Wrap(err)
	}
	return a.authServer.CreateResetPasswordToken(ctx, req)
}

func (a *WithRoles) GetResetPasswordToken(ctx context.Context, tokenID string) (types.ResetPasswordToken, error) {
	// tokens are their own authz mechanism, no need to double check
	return a.authServer.Services.GetResetPasswordToken(ctx, tokenID)
}

func (a *WithRoles) RotateResetPasswordTokenSecrets(ctx context.Context, tokenID string) (types.ResetPasswordTokenSecrets, error) {
	// tokens are their own authz mechanism, no need to double check
	return a.authServer.RotateResetPasswordTokenSecrets(ctx, tokenID)
}

func (a *WithRoles) ChangePasswordWithToken(ctx context.Context, req ChangePasswordWithTokenRequest) (types.WebSession, error) {
	// Token is it's own authentication, no need to double check.
	return a.authServer.ChangePasswordWithToken(ctx, req)
}

// CreateUser inserts a new user entry in a backend.
func (a *WithRoles) CreateUser(ctx context.Context, user types.User) error {
	if err := a.action(defaults.Namespace, types.KindUser, types.VerbCreate); err != nil {
		return trace.Wrap(err)
	}
	return a.authServer.CreateUser(ctx, user)
}

// UpdateUser updates an existing user in a backend.
// Captures the auth user who modified the user record.
func (a *WithRoles) UpdateUser(ctx context.Context, user types.User) error {
	if err := a.action(defaults.Namespace, types.KindUser, types.VerbUpdate); err != nil {
		return trace.Wrap(err)
	}

	return a.authServer.UpdateUser(ctx, user)
}

func (a *WithRoles) UpsertUser(u types.User) error {
	if err := a.action(defaults.Namespace, types.KindUser, types.VerbCreate); err != nil {
		return trace.Wrap(err)
	}
	if err := a.action(defaults.Namespace, types.KindUser, types.VerbUpdate); err != nil {
		return trace.Wrap(err)
	}

	createdBy := u.GetCreatedBy()
	if createdBy.IsEmpty() {
		u.SetCreatedBy(types.CreatedBy{
			User: types.UserRef{Name: a.context.User.GetName()},
		})
	}
	return a.authServer.UpsertUser(u)
}

// UpsertOIDCConnector creates or updates an OIDC connector.
func (a *WithRoles) UpsertOIDCConnector(ctx context.Context, connector types.OIDCConnector) error {
	if err := a.authConnectorAction(defaults.Namespace, types.KindOIDC, types.VerbCreate); err != nil {
		return trace.Wrap(err)
	}
	if err := a.authConnectorAction(defaults.Namespace, types.KindOIDC, types.VerbUpdate); err != nil {
		return trace.Wrap(err)
	}
	if modules.GetModules().Features().OIDC == false {
		return trace.AccessDenied("OIDC is only available in enterprise subscriptions")
	}

	return a.authServer.UpsertOIDCConnector(ctx, connector)
}

func (a *WithRoles) GetOIDCConnector(id string, withSecrets bool) (types.OIDCConnector, error) {
	if err := a.authConnectorAction(defaults.Namespace, types.KindOIDC, types.VerbReadNoSecrets); err != nil {
		return nil, trace.Wrap(err)
	}
	if withSecrets {
		if err := a.authConnectorAction(defaults.Namespace, types.KindOIDC, types.VerbRead); err != nil {
			return nil, trace.Wrap(err)
		}
	}
	return a.authServer.Services.Identity.GetOIDCConnector(id, withSecrets)
}

func (a *WithRoles) GetOIDCConnectors(withSecrets bool) ([]types.OIDCConnector, error) {
	if err := a.authConnectorAction(defaults.Namespace, types.KindOIDC, types.VerbList); err != nil {
		return nil, trace.Wrap(err)
	}
	if err := a.authConnectorAction(defaults.Namespace, types.KindOIDC, types.VerbReadNoSecrets); err != nil {
		return nil, trace.Wrap(err)
	}
	if withSecrets {
		if err := a.authConnectorAction(defaults.Namespace, types.KindOIDC, types.VerbRead); err != nil {
			return nil, trace.Wrap(err)
		}
	}
	return a.authServer.Services.Identity.GetOIDCConnectors(withSecrets)
}

func (a *WithRoles) CreateOIDCAuthRequest(req auth.OIDCAuthRequest) (*auth.OIDCAuthRequest, error) {
	if err := a.action(defaults.Namespace, types.KindOIDCRequest, types.VerbCreate); err != nil {
		return nil, trace.Wrap(err)
	}
	return a.authServer.CreateOIDCAuthRequest(req)
}

func (a *WithRoles) ValidateOIDCAuthCallback(q url.Values) (*OIDCAuthResponse, error) {
	// auth callback is it's own authz, no need to check extra permissions
	return a.authServer.ValidateOIDCAuthCallback(q)
}

func (a *WithRoles) DeleteOIDCConnector(ctx context.Context, connectorID string) error {
	if err := a.authConnectorAction(defaults.Namespace, types.KindOIDC, types.VerbDelete); err != nil {
		return trace.Wrap(err)
	}
	return a.authServer.DeleteOIDCConnector(ctx, connectorID)
}

func (a *WithRoles) CreateSAMLConnector(ctx context.Context, connector types.SAMLConnector) error {
	if err := a.authConnectorAction(defaults.Namespace, types.KindSAML, types.VerbCreate); err != nil {
		return trace.Wrap(err)
	}
	if modules.GetModules().Features().SAML == false {
		return trace.AccessDenied("SAML is only available in enterprise subscriptions")
	}
	return a.authServer.UpsertSAMLConnector(ctx, connector)
}

// UpsertSAMLConnector creates or updates a SAML connector.
func (a *WithRoles) UpsertSAMLConnector(ctx context.Context, connector types.SAMLConnector) error {
	if err := a.authConnectorAction(defaults.Namespace, types.KindSAML, types.VerbCreate); err != nil {
		return trace.Wrap(err)
	}
	if err := a.authConnectorAction(defaults.Namespace, types.KindSAML, types.VerbUpdate); err != nil {
		return trace.Wrap(err)
	}
	if modules.GetModules().Features().SAML == false {
		return trace.AccessDenied("SAML is only available in enterprise subscriptions")
	}
	return a.authServer.UpsertSAMLConnector(ctx, connector)
}

func (a *WithRoles) GetSAMLConnector(id string, withSecrets bool) (types.SAMLConnector, error) {
	if err := a.authConnectorAction(defaults.Namespace, types.KindSAML, types.VerbReadNoSecrets); err != nil {
		return nil, trace.Wrap(err)
	}
	if withSecrets {
		if err := a.authConnectorAction(defaults.Namespace, types.KindSAML, types.VerbRead); err != nil {
			return nil, trace.Wrap(err)
		}
	}
	return a.authServer.Services.Identity.GetSAMLConnector(id, withSecrets)
}

func (a *WithRoles) GetSAMLConnectors(withSecrets bool) ([]types.SAMLConnector, error) {
	if err := a.authConnectorAction(defaults.Namespace, types.KindSAML, types.VerbList); err != nil {
		return nil, trace.Wrap(err)
	}
	if err := a.authConnectorAction(defaults.Namespace, types.KindSAML, types.VerbReadNoSecrets); err != nil {
		return nil, trace.Wrap(err)
	}
	if withSecrets {
		if err := a.authConnectorAction(defaults.Namespace, types.KindSAML, types.VerbRead); err != nil {
			return nil, trace.Wrap(err)
		}
	}
	return a.authServer.Services.Identity.GetSAMLConnectors(withSecrets)
}

func (a *WithRoles) CreateSAMLAuthRequest(req auth.SAMLAuthRequest) (*auth.SAMLAuthRequest, error) {
	if err := a.action(defaults.Namespace, types.KindSAMLRequest, types.VerbCreate); err != nil {
		return nil, trace.Wrap(err)
	}
	return a.authServer.CreateSAMLAuthRequest(req)
}

func (a *WithRoles) ValidateSAMLResponse(re string) (*SAMLAuthResponse, error) {
	// auth callback is it's own authz, no need to check extra permissions
	return a.authServer.ValidateSAMLResponse(re)
}

// DeleteSAMLConnector deletes a SAML connector by name.
func (a *WithRoles) DeleteSAMLConnector(ctx context.Context, connectorID string) error {
	if err := a.authConnectorAction(defaults.Namespace, types.KindSAML, types.VerbDelete); err != nil {
		return trace.Wrap(err)
	}
	return a.authServer.DeleteSAMLConnector(ctx, connectorID)
}

func (a *WithRoles) CreateGithubConnector(connector types.GithubConnector) error {
	if err := a.authConnectorAction(defaults.Namespace, types.KindGithub, types.VerbCreate); err != nil {
		return trace.Wrap(err)
	}
	if err := a.checkGithubConnector(connector); err != nil {
		return trace.Wrap(err)
	}
	return a.authServer.Services.CreateGithubConnector(connector)
}

func (a *WithRoles) checkGithubConnector(connector types.GithubConnector) error {
	mapping := connector.GetTeamsToLogins()
	for _, team := range mapping {
		if len(team.KubeUsers) != 0 || len(team.KubeGroups) != 0 {
			return trace.BadParameter("since 6.0 teleport uses teams_to_logins to reference a role, use it instead of local kubernetes_users and kubernetes_groups ")
		}
		for _, localRole := range team.Logins {
			_, err := a.GetRole(localRole)
			if err != nil {
				if trace.IsNotFound(err) {
					return trace.BadParameter("since 6.0 teleport uses teams_to_logins to reference a role, role %q referenced in mapping for organization %q is not found", localRole, team.Organization)
				}
				return trace.Wrap(err)
			}
		}
	}
	return nil
}

// UpsertGithubConnector creates or updates a Github connector.
func (a *WithRoles) UpsertGithubConnector(ctx context.Context, connector types.GithubConnector) error {
	if err := a.authConnectorAction(defaults.Namespace, types.KindGithub, types.VerbCreate); err != nil {
		return trace.Wrap(err)
	}
	if err := a.authConnectorAction(defaults.Namespace, types.KindGithub, types.VerbUpdate); err != nil {
		return trace.Wrap(err)
	}
	if err := a.checkGithubConnector(connector); err != nil {
		return trace.Wrap(err)
	}
	return a.authServer.upsertGithubConnector(ctx, connector)
}

func (a *WithRoles) GetGithubConnector(id string, withSecrets bool) (types.GithubConnector, error) {
	if err := a.authConnectorAction(defaults.Namespace, types.KindGithub, types.VerbReadNoSecrets); err != nil {
		return nil, trace.Wrap(err)
	}
	if withSecrets {
		if err := a.authConnectorAction(defaults.Namespace, types.KindGithub, types.VerbRead); err != nil {
			return nil, trace.Wrap(err)
		}
	}
	return a.authServer.Services.Identity.GetGithubConnector(id, withSecrets)
}

func (a *WithRoles) GetGithubConnectors(withSecrets bool) ([]types.GithubConnector, error) {
	if err := a.authConnectorAction(defaults.Namespace, types.KindGithub, types.VerbList); err != nil {
		return nil, trace.Wrap(err)
	}
	if err := a.authConnectorAction(defaults.Namespace, types.KindGithub, types.VerbReadNoSecrets); err != nil {
		return nil, trace.Wrap(err)
	}
	if withSecrets {
		if err := a.authConnectorAction(defaults.Namespace, types.KindGithub, types.VerbRead); err != nil {
			return nil, trace.Wrap(err)
		}
	}
	return a.authServer.Services.Identity.GetGithubConnectors(withSecrets)
}

// DeleteGithubConnector deletes a Github connector by name.
func (a *WithRoles) DeleteGithubConnector(ctx context.Context, connectorID string) error {
	if err := a.authConnectorAction(defaults.Namespace, types.KindGithub, types.VerbDelete); err != nil {
		return trace.Wrap(err)
	}
	return a.authServer.deleteGithubConnector(ctx, connectorID)
}

func (a *WithRoles) CreateGithubAuthRequest(req auth.GithubAuthRequest) (*auth.GithubAuthRequest, error) {
	if err := a.action(defaults.Namespace, types.KindGithubRequest, types.VerbCreate); err != nil {
		return nil, trace.Wrap(err)
	}
	return a.authServer.CreateGithubAuthRequest(req)
}

func (a *WithRoles) ValidateGithubAuthCallback(q url.Values) (*GithubAuthResponse, error) {
	return a.authServer.ValidateGithubAuthCallback(q)
}

// EmitAuditEvent emits a single audit event
func (a *WithRoles) EmitAuditEvent(ctx context.Context, event events.AuditEvent) error {
	if err := a.action(defaults.Namespace, types.KindEvent, types.VerbCreate); err != nil {
		return trace.Wrap(err)
	}
	role, ok := a.context.Identity.(BuiltinRole)
	if !ok || !role.IsServer() {
		return trace.AccessDenied("this request can be only executed by proxy, node or auth")
	}
	err := validateServerMetadata(event, role.GetServerID())
	if err != nil {
		// TODO: this should be a proper audit event
		// notifying about access violation
		log.Warningf("Rejecting audit event %v(%q) from %q: %v. The client is attempting to "+
			"submit events for an identity other than the one on its x509 certificate.",
			event.GetType(), event.GetID(), role.GetServerID(), err)
		// this message is sparse on purpose to avoid conveying extra data to an attacker
		return trace.AccessDenied("failed to validate event metadata")
	}
	return a.authServer.emitter.EmitAuditEvent(ctx, event)
}

// CreateAuditStream creates audit event stream
func (a *WithRoles) CreateAuditStream(ctx context.Context, sid session.ID) (events.Stream, error) {
	if err := a.action(defaults.Namespace, types.KindEvent, types.VerbCreate); err != nil {
		return nil, trace.Wrap(err)
	}
	if err := a.action(defaults.Namespace, types.KindEvent, types.VerbUpdate); err != nil {
		return nil, trace.Wrap(err)
	}
	role, ok := a.context.Identity.(BuiltinRole)
	if !ok || !role.IsServer() {
		return nil, trace.AccessDenied("this request can be only executed by proxy, node or auth")
	}
	stream, err := a.authServer.CreateAuditStream(ctx, sid)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return &streamWithRoles{
		stream:   stream,
		a:        a,
		serverID: role.GetServerID(),
	}, nil
}

// ResumeAuditStream resumes the stream that has been created
func (a *WithRoles) ResumeAuditStream(ctx context.Context, sid session.ID, uploadID string) (events.Stream, error) {
	if err := a.action(defaults.Namespace, types.KindEvent, types.VerbCreate); err != nil {
		return nil, trace.Wrap(err)
	}
	if err := a.action(defaults.Namespace, types.KindEvent, types.VerbUpdate); err != nil {
		return nil, trace.Wrap(err)
	}
	role, ok := a.context.Identity.(BuiltinRole)
	if !ok || !role.IsServer() {
		return nil, trace.AccessDenied("this request can be only executed by proxy, node or auth")
	}
	stream, err := a.authServer.ResumeAuditStream(ctx, sid, uploadID)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return &streamWithRoles{
		stream:   stream,
		a:        a,
		serverID: role.GetServerID(),
	}, nil
}

// streamWithRoles verifies every event
type streamWithRoles struct {
	a        *WithRoles
	serverID string
	stream   events.Stream
}

// Status returns channel receiving updates about stream status
// last event index that was uploaded and upload ID
func (s *streamWithRoles) Status() <-chan events.StreamStatus {
	return s.stream.Status()
}

// Done returns channel closed when streamer is closed
// should be used to detect sending errors
func (s *streamWithRoles) Done() <-chan struct{} {
	return s.stream.Done()
}

// Complete closes the stream and marks it finalized
func (s *streamWithRoles) Complete(ctx context.Context) error {
	return s.stream.Complete(ctx)
}

// Close flushes non-uploaded flight stream data without marking
// the stream completed and closes the stream instance
func (s *streamWithRoles) Close(ctx context.Context) error {
	return s.stream.Close(ctx)
}

func (s *streamWithRoles) EmitAuditEvent(ctx context.Context, event events.AuditEvent) error {
	err := validateServerMetadata(event, s.serverID)
	if err != nil {
		// TODO: this should be a proper audit event
		// notifying about access violation
		log.Warningf("Rejecting audit event %v from %v: %v. A node is attempting to "+
			"submit events for an identity other than the one on its x509 certificate.",
			event.GetID(), s.serverID, err)
		// this message is sparse on purpose to avoid conveying extra data to an attacker
		return trace.AccessDenied("failed to validate event metadata")
	}
	return s.stream.EmitAuditEvent(ctx, event)
}

func (a *WithRoles) EmitAuditEventLegacy(event events.Event, fields events.EventFields) error {
	if err := a.action(defaults.Namespace, types.KindEvent, types.VerbCreate); err != nil {
		return trace.Wrap(err)
	}
	if err := a.action(defaults.Namespace, types.KindEvent, types.VerbUpdate); err != nil {
		return trace.Wrap(err)
	}
	return a.alog.EmitAuditEventLegacy(event, fields)
}

func (a *WithRoles) PostSessionSlice(slice events.SessionSlice) error {
	if err := a.action(slice.Namespace, types.KindEvent, types.VerbCreate); err != nil {
		return trace.Wrap(err)
	}
	if err := a.action(slice.Namespace, types.KindEvent, types.VerbUpdate); err != nil {
		return trace.Wrap(err)
	}
	return a.alog.PostSessionSlice(slice)
}

func (a *WithRoles) UploadSessionRecording(r events.SessionRecording) error {
	if err := r.CheckAndSetDefaults(); err != nil {
		return trace.Wrap(err)
	}
	if err := a.action(r.Namespace, types.KindEvent, types.VerbCreate); err != nil {
		return trace.Wrap(err)
	}
	if err := a.action(r.Namespace, types.KindEvent, types.VerbUpdate); err != nil {
		return trace.Wrap(err)
	}
	return a.alog.UploadSessionRecording(r)
}

func (a *WithRoles) GetSessionChunk(namespace string, sid session.ID, offsetBytes, maxBytes int) ([]byte, error) {
	if err := a.action(namespace, types.KindSession, types.VerbRead); err != nil {
		return nil, trace.Wrap(err)
	}

	return a.alog.GetSessionChunk(namespace, sid, offsetBytes, maxBytes)
}

func (a *WithRoles) GetSessionEvents(namespace string, sid session.ID, afterN int, includePrintEvents bool) ([]events.EventFields, error) {
	if err := a.action(namespace, types.KindSession, types.VerbRead); err != nil {
		return nil, trace.Wrap(err)
	}

	return a.alog.GetSessionEvents(namespace, sid, afterN, includePrintEvents)
}

func (a *WithRoles) SearchEvents(from, to time.Time, query string, limit int) ([]events.EventFields, error) {
	if err := a.action(defaults.Namespace, types.KindEvent, types.VerbList); err != nil {
		return nil, trace.Wrap(err)
	}

	return a.alog.SearchEvents(from, to, query, limit)
}

func (a *WithRoles) SearchSessionEvents(from, to time.Time, limit int) ([]events.EventFields, error) {
	if err := a.action(defaults.Namespace, types.KindSession, types.VerbList); err != nil {
		return nil, trace.Wrap(err)
	}

	return a.alog.SearchSessionEvents(from, to, limit)
}

// GetNamespaces returns a list of namespaces
func (a *WithRoles) GetNamespaces() ([]types.Namespace, error) {
	if err := a.action(defaults.Namespace, types.KindNamespace, types.VerbList); err != nil {
		return nil, trace.Wrap(err)
	}
	if err := a.action(defaults.Namespace, types.KindNamespace, types.VerbRead); err != nil {
		return nil, trace.Wrap(err)
	}
	return a.authServer.GetNamespaces()
}

// GetNamespace returns namespace by name
func (a *WithRoles) GetNamespace(name string) (*types.Namespace, error) {
	if err := a.action(defaults.Namespace, types.KindNamespace, types.VerbRead); err != nil {
		return nil, trace.Wrap(err)
	}
	return a.authServer.GetNamespace(name)
}

// UpsertNamespace upserts namespace
func (a *WithRoles) UpsertNamespace(ns types.Namespace) error {
	if err := a.action(defaults.Namespace, types.KindNamespace, types.VerbCreate); err != nil {
		return trace.Wrap(err)
	}
	if err := a.action(defaults.Namespace, types.KindNamespace, types.VerbUpdate); err != nil {
		return trace.Wrap(err)
	}
	return a.authServer.Services.UpsertNamespace(ns)
}

// DeleteNamespace deletes namespace by name
func (a *WithRoles) DeleteNamespace(name string) error {
	if err := a.action(defaults.Namespace, types.KindNamespace, types.VerbDelete); err != nil {
		return trace.Wrap(err)
	}
	return a.authServer.DeleteNamespace(name)
}

// GetRoles returns a list of roles
func (a *WithRoles) GetRoles() ([]types.Role, error) {
	if err := a.action(defaults.Namespace, types.KindRole, types.VerbList); err != nil {
		return nil, trace.Wrap(err)
	}
	if err := a.action(defaults.Namespace, types.KindRole, types.VerbRead); err != nil {
		return nil, trace.Wrap(err)
	}
	return a.authServer.GetRoles()
}

// UpsertRole creates or updates role.
func (a *WithRoles) UpsertRole(ctx context.Context, role types.Role) error {
	if err := a.action(defaults.Namespace, types.KindRole, types.VerbCreate); err != nil {
		return trace.Wrap(err)
	}
	if err := a.action(defaults.Namespace, types.KindRole, types.VerbUpdate); err != nil {
		return trace.Wrap(err)
	}

	// Some options are only available with enterprise subscription
	features := modules.GetModules().Features()
	options := role.GetOptions()

	switch {
	case features.AccessControls == false && options.MaxSessions > 0:
		return trace.AccessDenied(
			"role option max_sessions is only available in enterprise subscriptions")
	case features.AdvancedAccessWorkflows == false &&
		(options.RequestAccess == types.RequestStrategyReason || options.RequestAccess == types.RequestStrategyAlways):
		return trace.AccessDenied(
			"role option request_access: %v is only available in enterprise subscriptions", options.RequestAccess)
	}

	return a.authServer.upsertRole(ctx, role)
}

// GetRole returns role by name
func (a *WithRoles) GetRole(name string) (types.Role, error) {
	// Current-user exception: we always allow users to read roles
	// that they hold.  This requirement is checked first to avoid
	// misleading denial messages in the logs.
	if !utils.SliceContainsStr(a.context.User.GetRoles(), name) {
		if err := a.action(defaults.Namespace, types.KindRole, types.VerbRead); err != nil {
			return nil, trace.Wrap(err)
		}
	}
	return a.authServer.GetRole(name)
}

// DeleteRole deletes role by name
func (a *WithRoles) DeleteRole(ctx context.Context, name string) error {
	if err := a.action(defaults.Namespace, types.KindRole, types.VerbDelete); err != nil {
		return trace.Wrap(err)
	}
	// DELETE IN (7.0)
	// It's OK to delete this code alongside migrateOSS code in auth.
	// It prevents 6.0 from migrating resources multiple times
	// and the role is used for `tctl users add` code too.
	if modules.GetModules().BuildType() == modules.BuildOSS && name == teleport.OSSUserRoleName {
		return trace.AccessDenied("can not delete system role %q", name)
	}
	return a.authServer.DeleteRole(ctx, name)
}

// GetClusterConfig gets cluster level configuration.
func (a *WithRoles) GetClusterConfig(opts ...auth.MarshalOption) (types.ClusterConfig, error) {
	if err := a.action(defaults.Namespace, types.KindClusterConfig, types.VerbRead); err != nil {
		return nil, trace.Wrap(err)
	}
	return a.authServer.GetClusterConfig(opts...)
}

// DeleteClusterConfig deletes cluster config
func (a *WithRoles) DeleteClusterConfig() error {
	if err := a.action(defaults.Namespace, types.KindClusterConfig, types.VerbDelete); err != nil {
		return trace.Wrap(err)
	}
	return a.authServer.Services.DeleteClusterConfig()
}

// DeleteClusterName deletes cluster name
func (a *WithRoles) DeleteClusterName() error {
	if err := a.action(defaults.Namespace, types.KindClusterName, types.VerbDelete); err != nil {
		return trace.Wrap(err)
	}
	return a.authServer.Services.DeleteClusterName()
}

// DeleteStaticTokens deletes static tokens
func (a *WithRoles) DeleteStaticTokens() error {
	if err := a.action(defaults.Namespace, types.KindStaticTokens, types.VerbDelete); err != nil {
		return trace.Wrap(err)
	}
	return a.authServer.Services.DeleteStaticTokens()
}

// SetClusterConfig sets cluster level configuration.
func (a *WithRoles) SetClusterConfig(c types.ClusterConfig) error {
	if err := a.action(defaults.Namespace, types.KindClusterConfig, types.VerbCreate); err != nil {
		return trace.Wrap(err)
	}
	if err := a.action(defaults.Namespace, types.KindClusterConfig, types.VerbUpdate); err != nil {
		return trace.Wrap(err)
	}
	return a.authServer.Services.SetClusterConfig(c)
}

// GetClusterName gets the name of the cluster.
func (a *WithRoles) GetClusterName(opts ...auth.MarshalOption) (types.ClusterName, error) {
	if err := a.action(defaults.Namespace, types.KindClusterName, types.VerbRead); err != nil {
		return nil, trace.Wrap(err)
	}
	return a.authServer.GetClusterName()
}

// SetClusterName sets the name of the cluster. SetClusterName can only be called once.
func (a *WithRoles) SetClusterName(c types.ClusterName) error {
	if err := a.action(defaults.Namespace, types.KindClusterName, types.VerbCreate); err != nil {
		return trace.Wrap(err)
	}
	if err := a.action(defaults.Namespace, types.KindClusterName, types.VerbUpdate); err != nil {
		return trace.Wrap(err)
	}
	return a.authServer.Services.SetClusterName(c)
}

// UpsertClusterName sets the name of the cluster.
func (a *WithRoles) UpsertClusterName(c types.ClusterName) error {
	if err := a.action(defaults.Namespace, types.KindClusterName, types.VerbCreate); err != nil {
		return trace.Wrap(err)
	}
	if err := a.action(defaults.Namespace, types.KindClusterName, types.VerbUpdate); err != nil {
		return trace.Wrap(err)
	}
	return a.authServer.Services.UpsertClusterName(c)
}

// GetStaticTokens gets the list of static tokens used to provision nodes.
func (a *WithRoles) GetStaticTokens() (types.StaticTokens, error) {
	if err := a.action(defaults.Namespace, types.KindStaticTokens, types.VerbRead); err != nil {
		return nil, trace.Wrap(err)
	}
	return a.authServer.GetStaticTokens()
}

// SetStaticTokens sets the list of static tokens used to provision nodes.
func (a *WithRoles) SetStaticTokens(s types.StaticTokens) error {
	if err := a.action(defaults.Namespace, types.KindStaticTokens, types.VerbCreate); err != nil {
		return trace.Wrap(err)
	}
	if err := a.action(defaults.Namespace, types.KindStaticTokens, types.VerbUpdate); err != nil {
		return trace.Wrap(err)
	}
	return a.authServer.Services.SetStaticTokens(s)
}

func (a *WithRoles) GetAuthPreference() (types.AuthPreference, error) {
	if err := a.action(defaults.Namespace, types.KindClusterAuthPreference, types.VerbRead); err != nil {
		return nil, trace.Wrap(err)
	}

	return a.authServer.Services.GetAuthPreference()
}

func (a *WithRoles) SetAuthPreference(cap types.AuthPreference) error {
	if err := a.action(defaults.Namespace, types.KindClusterAuthPreference, types.VerbCreate); err != nil {
		return trace.Wrap(err)
	}
	if err := a.action(defaults.Namespace, types.KindClusterAuthPreference, types.VerbUpdate); err != nil {
		return trace.Wrap(err)
	}

	return a.authServer.Services.SetAuthPreference(cap)
}

func (a *WithRoles) GetTrustedClusters() ([]types.TrustedCluster, error) {
	if err := a.action(defaults.Namespace, types.KindTrustedCluster, types.VerbList); err != nil {
		return nil, trace.Wrap(err)
	}
	if err := a.action(defaults.Namespace, types.KindTrustedCluster, types.VerbRead); err != nil {
		return nil, trace.Wrap(err)
	}

	return a.authServer.Services.GetTrustedClusters()
}

func (a *WithRoles) GetTrustedCluster(name string) (types.TrustedCluster, error) {
	if err := a.action(defaults.Namespace, types.KindTrustedCluster, types.VerbRead); err != nil {
		return nil, trace.Wrap(err)
	}

	return a.authServer.Services.GetTrustedCluster(name)
}

// UpsertTrustedCluster creates or updates a trusted cluster.
func (a *WithRoles) UpsertTrustedCluster(ctx context.Context, tc types.TrustedCluster) (types.TrustedCluster, error) {
	if err := a.action(defaults.Namespace, types.KindTrustedCluster, types.VerbCreate); err != nil {
		return nil, trace.Wrap(err)
	}
	if err := a.action(defaults.Namespace, types.KindTrustedCluster, types.VerbUpdate); err != nil {
		return nil, trace.Wrap(err)
	}

	return a.authServer.UpsertTrustedCluster(ctx, tc)
}

func (a *WithRoles) ValidateTrustedCluster(validateRequest *ValidateTrustedClusterRequest) (*ValidateTrustedClusterResponse, error) {
	// the token provides it's own authorization and authentication
	return a.authServer.validateTrustedCluster(validateRequest)
}

// DeleteTrustedCluster deletes a trusted cluster by name.
func (a *WithRoles) DeleteTrustedCluster(ctx context.Context, name string) error {
	if err := a.action(defaults.Namespace, types.KindTrustedCluster, types.VerbDelete); err != nil {
		return trace.Wrap(err)
	}

	return a.authServer.DeleteTrustedCluster(ctx, name)
}

func (a *WithRoles) UpsertTunnelConnection(conn types.TunnelConnection) error {
	if err := a.action(defaults.Namespace, types.KindTunnelConnection, types.VerbCreate); err != nil {
		return trace.Wrap(err)
	}
	if err := a.action(defaults.Namespace, types.KindTunnelConnection, types.VerbUpdate); err != nil {
		return trace.Wrap(err)
	}
	return a.authServer.Services.UpsertTunnelConnection(conn)
}

func (a *WithRoles) GetTunnelConnections(clusterName string, opts ...auth.MarshalOption) ([]types.TunnelConnection, error) {
	if err := a.action(defaults.Namespace, types.KindTunnelConnection, types.VerbList); err != nil {
		return nil, trace.Wrap(err)
	}
	return a.authServer.GetTunnelConnections(clusterName, opts...)
}

func (a *WithRoles) GetAllTunnelConnections(opts ...auth.MarshalOption) ([]types.TunnelConnection, error) {
	if err := a.action(defaults.Namespace, types.KindTunnelConnection, types.VerbList); err != nil {
		return nil, trace.Wrap(err)
	}
	return a.authServer.GetAllTunnelConnections(opts...)
}

func (a *WithRoles) DeleteTunnelConnection(clusterName string, connName string) error {
	if err := a.action(defaults.Namespace, types.KindTunnelConnection, types.VerbDelete); err != nil {
		return trace.Wrap(err)
	}
	return a.authServer.Services.DeleteTunnelConnection(clusterName, connName)
}

func (a *WithRoles) DeleteTunnelConnections(clusterName string) error {
	if err := a.action(defaults.Namespace, types.KindTunnelConnection, types.VerbList); err != nil {
		return trace.Wrap(err)
	}
	if err := a.action(defaults.Namespace, types.KindTunnelConnection, types.VerbDelete); err != nil {
		return trace.Wrap(err)
	}
	return a.authServer.Services.DeleteTunnelConnections(clusterName)
}

func (a *WithRoles) DeleteAllTunnelConnections() error {
	if err := a.action(defaults.Namespace, types.KindTunnelConnection, types.VerbList); err != nil {
		return trace.Wrap(err)
	}
	if err := a.action(defaults.Namespace, types.KindTunnelConnection, types.VerbDelete); err != nil {
		return trace.Wrap(err)
	}
	return a.authServer.Services.DeleteAllTunnelConnections()
}

func (a *WithRoles) CreateRemoteCluster(conn types.RemoteCluster) error {
	if err := a.action(defaults.Namespace, types.KindRemoteCluster, types.VerbCreate); err != nil {
		return trace.Wrap(err)
	}
	return a.authServer.Services.CreateRemoteCluster(conn)
}

func (a *WithRoles) UpdateRemoteCluster(ctx context.Context, rc types.RemoteCluster) error {
	if err := a.action(defaults.Namespace, types.KindRemoteCluster, types.VerbUpdate); err != nil {
		return trace.Wrap(err)
	}
	return a.authServer.Services.UpdateRemoteCluster(ctx, rc)
}

func (a *WithRoles) GetRemoteCluster(clusterName string) (types.RemoteCluster, error) {
	if err := a.action(defaults.Namespace, types.KindRemoteCluster, types.VerbRead); err != nil {
		return nil, trace.Wrap(err)
	}
	cluster, err := a.authServer.GetRemoteCluster(clusterName)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	if err := a.context.Checker.CheckAccessToRemoteCluster(cluster); err != nil {
		return nil, trace.Wrap(err)
	}
	return cluster, nil
}

func (a *WithRoles) GetRemoteClusters(opts ...auth.MarshalOption) ([]types.RemoteCluster, error) {
	if err := a.action(defaults.Namespace, types.KindRemoteCluster, types.VerbList); err != nil {
		return nil, trace.Wrap(err)
	}
	remoteClusters, err := a.authServer.GetRemoteClusters(opts...)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return a.filterRemoteClustersForUser(remoteClusters)
}

// filterRemoteClustersForUser filters remote clusters based on what the current user is authorized to access
func (a *WithRoles) filterRemoteClustersForUser(remoteClusters []types.RemoteCluster) ([]types.RemoteCluster, error) {
	filteredClusters := make([]types.RemoteCluster, 0, len(remoteClusters))
	for _, rc := range remoteClusters {
		if err := a.context.Checker.CheckAccessToRemoteCluster(rc); err != nil {
			if trace.IsAccessDenied(err) {
				continue
			}
			return nil, trace.Wrap(err)
		}
		filteredClusters = append(filteredClusters, rc)
	}
	return filteredClusters, nil
}

func (a *WithRoles) DeleteRemoteCluster(clusterName string) error {
	if err := a.action(defaults.Namespace, types.KindRemoteCluster, types.VerbDelete); err != nil {
		return trace.Wrap(err)
	}
	return a.authServer.DeleteRemoteCluster(clusterName)
}

func (a *WithRoles) DeleteAllRemoteClusters() error {
	if err := a.action(defaults.Namespace, types.KindRemoteCluster, types.VerbList); err != nil {
		return trace.Wrap(err)
	}
	if err := a.action(defaults.Namespace, types.KindRemoteCluster, types.VerbDelete); err != nil {
		return trace.Wrap(err)
	}
	return a.authServer.Services.DeleteAllRemoteClusters()
}

// AcquireSemaphore acquires lease with requested resources from semaphore.
func (a *WithRoles) AcquireSemaphore(ctx context.Context, params types.AcquireSemaphoreRequest) (*types.SemaphoreLease, error) {
	if err := a.action(defaults.Namespace, types.KindSemaphore, types.VerbCreate); err != nil {
		return nil, trace.Wrap(err)
	}
	if err := a.action(defaults.Namespace, types.KindSemaphore, types.VerbUpdate); err != nil {
		return nil, trace.Wrap(err)
	}
	return a.authServer.Services.AcquireSemaphore(ctx, params)
}

// KeepAliveSemaphoreLease updates semaphore lease.
func (a *WithRoles) KeepAliveSemaphoreLease(ctx context.Context, lease types.SemaphoreLease) error {
	if err := a.action(defaults.Namespace, types.KindSemaphore, types.VerbUpdate); err != nil {
		return trace.Wrap(err)
	}
	return a.authServer.Services.KeepAliveSemaphoreLease(ctx, lease)
}

// CancelSemaphoreLease cancels semaphore lease early.
func (a *WithRoles) CancelSemaphoreLease(ctx context.Context, lease types.SemaphoreLease) error {
	if err := a.action(defaults.Namespace, types.KindSemaphore, types.VerbUpdate); err != nil {
		return trace.Wrap(err)
	}
	return a.authServer.Services.CancelSemaphoreLease(ctx, lease)
}

// GetSemaphores returns a list of all semaphores matching the supplied filter.
func (a *WithRoles) GetSemaphores(ctx context.Context, filter types.SemaphoreFilter) ([]types.Semaphore, error) {
	if err := a.action(defaults.Namespace, types.KindSemaphore, types.VerbReadNoSecrets); err != nil {
		return nil, trace.Wrap(err)
	}
	if err := a.action(defaults.Namespace, types.KindSemaphore, types.VerbList); err != nil {
		return nil, trace.Wrap(err)
	}
	return a.authServer.Services.GetSemaphores(ctx, filter)
}

// DeleteSemaphore deletes a semaphore matching the supplied filter.
func (a *WithRoles) DeleteSemaphore(ctx context.Context, filter types.SemaphoreFilter) error {
	if err := a.action(defaults.Namespace, types.KindSemaphore, types.VerbDelete); err != nil {
		return trace.Wrap(err)
	}
	return a.authServer.Services.DeleteSemaphore(ctx, filter)
}

// ProcessKubeCSR processes CSR request against Kubernetes CA, returns
// signed certificate if successful.
func (a *WithRoles) ProcessKubeCSR(req KubeCSR) (*KubeCSRResponse, error) {
	// limits the requests types to proxies to make it harder to break
	if !a.hasBuiltinRole(string(teleport.RoleProxy)) {
		return nil, trace.AccessDenied("this request can be only executed by a proxy")
	}
	return a.authServer.ProcessKubeCSR(req)
}

// GetDatabaseServers returns all registered database servers.
func (a *WithRoles) GetDatabaseServers(ctx context.Context, namespace string, opts ...auth.MarshalOption) ([]types.DatabaseServer, error) {
	if err := a.action(namespace, types.KindDatabaseServer, types.VerbList); err != nil {
		return nil, trace.Wrap(err)
	}
	if err := a.action(namespace, types.KindDatabaseServer, types.VerbRead); err != nil {
		return nil, trace.Wrap(err)
	}
	servers, err := a.authServer.GetDatabaseServers(ctx, namespace, opts...)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	// Filter out databases the caller doesn't have access to from each server.
	var filtered []types.DatabaseServer
	// MFA is not required to list the databases, but will be required to
	// connect to them.
	mfaVerified := true
	for _, server := range servers {
		err := a.context.Checker.CheckAccessToDatabase(server, mfaVerified, &auth.DatabaseLabelsMatcher{Labels: server.GetAllLabels()})
		if err != nil && !trace.IsAccessDenied(err) {
			return nil, trace.Wrap(err)
		} else if err == nil {
			filtered = append(filtered, server)
		}
	}
	return filtered, nil
}

// UpsertDatabaseServer creates or updates a new database proxy server.
func (a *WithRoles) UpsertDatabaseServer(ctx context.Context, server types.DatabaseServer) (*types.KeepAlive, error) {
	if err := a.action(server.GetNamespace(), types.KindDatabaseServer, types.VerbCreate); err != nil {
		return nil, trace.Wrap(err)
	}
	if err := a.action(server.GetNamespace(), types.KindDatabaseServer, types.VerbUpdate); err != nil {
		return nil, trace.Wrap(err)
	}
	return a.authServer.Services.UpsertDatabaseServer(ctx, server)
}

// DeleteDatabaseServer removes the specified database proxy server.
func (a *WithRoles) DeleteDatabaseServer(ctx context.Context, namespace, hostID, name string) error {
	if err := a.action(namespace, types.KindDatabaseServer, types.VerbDelete); err != nil {
		return trace.Wrap(err)
	}
	return a.authServer.Services.DeleteDatabaseServer(ctx, namespace, hostID, name)
}

// DeleteAllDatabaseServers removes all registered database proxy servers.
func (a *WithRoles) DeleteAllDatabaseServers(ctx context.Context, namespace string) error {
	if err := a.action(namespace, types.KindDatabaseServer, types.VerbList); err != nil {
		return trace.Wrap(err)
	}
	if err := a.action(namespace, types.KindDatabaseServer, types.VerbDelete); err != nil {
		return trace.Wrap(err)
	}
	return a.authServer.Services.DeleteAllDatabaseServers(ctx, namespace)
}

// SignDatabaseCSR generates a client certificate used by proxy when talking
// to a remote database service.
func (a *WithRoles) SignDatabaseCSR(ctx context.Context, req *proto.DatabaseCSRRequest) (*proto.DatabaseCSRResponse, error) {
	// Only proxy is allowed to request this certificate when proxying
	// database client connection to a remote database service.
	if !a.hasBuiltinRole(string(teleport.RoleProxy)) {
		return nil, trace.AccessDenied("this request can only be executed by a proxy service")
	}
	return a.authServer.SignDatabaseCSR(ctx, req)
}

// GenerateDatabaseCert generates a certificate used by a database service
// to authenticate with the database instance
func (a *WithRoles) GenerateDatabaseCert(ctx context.Context, req *proto.DatabaseCertRequest) (*proto.DatabaseCertResponse, error) {
	// This certificate can be requested only by a database service when
	// initiating connection to a database instance, or by an admin when
	// generating certificates for a database instance.
	if !a.hasBuiltinRole(string(teleport.RoleDatabase)) && !a.hasBuiltinRole(string(teleport.RoleAdmin)) {
		return nil, trace.AccessDenied("this request can only be executed by a database service or an admin")
	}
	return a.authServer.GenerateDatabaseCert(ctx, req)
}

// GetAppServers gets all application servers.
func (a *WithRoles) GetAppServers(ctx context.Context, namespace string, opts ...auth.MarshalOption) ([]types.Server, error) {
	if err := a.action(namespace, types.KindAppServer, types.VerbList); err != nil {
		return nil, trace.Wrap(err)
	}
	if err := a.action(namespace, types.KindAppServer, types.VerbRead); err != nil {
		return nil, trace.Wrap(err)
	}

	servers, err := a.authServer.GetAppServers(ctx, namespace, opts...)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	// Loop over all servers, filter out applications on each server and only
	// return the applications the caller has access to.
	//
	// MFA is not required to list the apps, but will be required to connect to
	// them.
	mfaVerified := true
	for _, server := range servers {
		filteredApps := make([]*types.App, 0, len(server.GetApps()))
		for _, app := range server.GetApps() {
			err := a.context.Checker.CheckAccessToApp(server.GetNamespace(), app, mfaVerified)
			if err != nil {
				if trace.IsAccessDenied(err) {
					continue
				}
				return nil, trace.Wrap(err)
			}
			filteredApps = append(filteredApps, app)
		}
		server.SetApps(filteredApps)
	}

	return servers, nil
}

// UpsertAppServer adds an application server.
func (a *WithRoles) UpsertAppServer(ctx context.Context, server types.Server) (*types.KeepAlive, error) {
	if err := a.action(server.GetNamespace(), types.KindAppServer, types.VerbCreate); err != nil {
		return nil, trace.Wrap(err)
	}
	if err := a.action(server.GetNamespace(), types.KindAppServer, types.VerbUpdate); err != nil {
		return nil, trace.Wrap(err)
	}

	return a.authServer.Services.UpsertAppServer(ctx, server)
}

// DeleteAppServer removes an application server.
func (a *WithRoles) DeleteAppServer(ctx context.Context, namespace string, name string) error {
	if err := a.action(namespace, types.KindAppServer, types.VerbDelete); err != nil {
		return trace.Wrap(err)
	}

	if err := a.authServer.Services.DeleteAppServer(ctx, namespace, name); err != nil {
		return trace.Wrap(err)
	}
	return nil
}

// DeleteAllAppServers removes all application servers.
func (a *WithRoles) DeleteAllAppServers(ctx context.Context, namespace string) error {
	if err := a.action(namespace, types.KindAppServer, types.VerbList); err != nil {
		return trace.Wrap(err)
	}
	if err := a.action(namespace, types.KindAppServer, types.VerbDelete); err != nil {
		return trace.Wrap(err)
	}

	if err := a.authServer.Services.DeleteAllAppServers(ctx, namespace); err != nil {
		return trace.Wrap(err)
	}
	return nil
}

// GetAppSession gets an application web session.
func (a *WithRoles) GetAppSession(ctx context.Context, req types.GetAppSessionRequest) (types.WebSession, error) {
	if err := a.action(defaults.Namespace, types.KindWebSession, types.VerbRead); err != nil {
		return nil, trace.Wrap(err)
	}

	session, err := a.authServer.GetAppSession(ctx, req)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return session, nil
}

// GetAppSessions gets all application web sessions.
func (a *WithRoles) GetAppSessions(ctx context.Context) ([]types.WebSession, error) {
	if err := a.action(defaults.Namespace, types.KindWebSession, types.VerbList); err != nil {
		return nil, trace.Wrap(err)
	}
	if err := a.action(defaults.Namespace, types.KindWebSession, types.VerbRead); err != nil {
		return nil, trace.Wrap(err)
	}

	sessions, err := a.authServer.Services.GetAppSessions(ctx)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return sessions, nil
}

// CreateAppSession creates an application web session. Application web
// sessions represent a browser session the client holds.
func (a *WithRoles) CreateAppSession(ctx context.Context, req types.CreateAppSessionRequest) (types.WebSession, error) {
	if err := a.currentUserAction(req.Username); err != nil {
		return nil, trace.Wrap(err)
	}

	session, err := a.authServer.CreateAppSession(ctx, req, a.context.User, a.context.Checker)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return session, nil
}

// DeleteAppSession removes an application web session.
func (a *WithRoles) DeleteAppSession(ctx context.Context, req types.DeleteAppSessionRequest) error {
	if err := a.action(defaults.Namespace, types.KindWebSession, types.VerbDelete); err != nil {
		return trace.Wrap(err)
	}

	if err := a.authServer.Services.DeleteAppSession(ctx, req); err != nil {
		return trace.Wrap(err)
	}
	return nil
}

// DeleteAllAppSessions removes all application web sessions.
func (a *WithRoles) DeleteAllAppSessions(ctx context.Context) error {
	if err := a.action(defaults.Namespace, types.KindWebSession, types.VerbList); err != nil {
		return trace.Wrap(err)
	}
	if err := a.action(defaults.Namespace, types.KindWebSession, types.VerbDelete); err != nil {
		return trace.Wrap(err)
	}

	if err := a.authServer.Services.DeleteAllAppSessions(ctx); err != nil {
		return trace.Wrap(err)
	}
	return nil
}

// GenerateAppToken creates a JWT token with application access.
func (a *WithRoles) GenerateAppToken(ctx context.Context, req jwt.GenerateAppTokenRequest) (string, error) {
	if err := a.action(defaults.Namespace, types.KindJWT, types.VerbCreate); err != nil {
		return "", trace.Wrap(err)
	}

	session, err := a.authServer.generateAppToken(req.Username, req.Roles, req.URI, req.Expires)
	if err != nil {
		return "", trace.Wrap(err)
	}
	return session, nil
}

func (a *WithRoles) Close() error {
	return a.authServer.Close()
}

func (a *WithRoles) WaitForDelivery(context.Context) error {
	return nil
}

// UpsertKubeService creates or updates a Server representing a teleport
// kubernetes service.
func (a *WithRoles) UpsertKubeService(ctx context.Context, s types.Server) error {
	if err := a.action(defaults.Namespace, types.KindKubeService, types.VerbCreate); err != nil {
		return trace.Wrap(err)
	}
	if err := a.action(defaults.Namespace, types.KindKubeService, types.VerbUpdate); err != nil {
		return trace.Wrap(err)
	}

	for _, kube := range s.GetKubernetesClusters() {
		if err := a.context.Checker.CheckAccessToKubernetes(s.GetNamespace(), kube, a.context.Identity.GetIdentity().MFAVerified); err != nil {
			return trace.Wrap(err)
		}
	}
	return a.authServer.Services.UpsertKubeService(ctx, s)
}

// GetKubeServices returns all Servers representing teleport kubernetes
// types.
func (a *WithRoles) GetKubeServices(ctx context.Context) ([]types.Server, error) {
	if err := a.action(defaults.Namespace, types.KindKubeService, types.VerbList); err != nil {
		return nil, trace.Wrap(err)
	}
	if err := a.action(defaults.Namespace, types.KindKubeService, types.VerbRead); err != nil {
		return nil, trace.Wrap(err)
	}
	servers, err := a.authServer.Services.GetKubeServices(ctx)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	// Loop over all servers, filter out kube clusters on each server and only
	// return the kube cluster the caller has access to.
	//
	// MFA is not required to list the clusters, but will be required to
	// connect to them.
	mfaVerified := true
	for _, server := range servers {
		filtered := make([]*types.KubernetesCluster, 0, len(server.GetKubernetesClusters()))
		for _, kube := range server.GetKubernetesClusters() {
			if err := a.context.Checker.CheckAccessToKubernetes(server.GetNamespace(), kube, mfaVerified); err != nil {
				if trace.IsAccessDenied(err) {
					continue
				}
				return nil, trace.Wrap(err)
			}
			filtered = append(filtered, kube)
		}
		server.SetKubernetesClusters(filtered)
	}
	return servers, nil
}

// DeleteKubeService deletes a named kubernetes service.
func (a *WithRoles) DeleteKubeService(ctx context.Context, name string) error {
	if err := a.action(defaults.Namespace, types.KindKubeService, types.VerbDelete); err != nil {
		return trace.Wrap(err)
	}
	return a.authServer.Services.DeleteKubeService(ctx, name)
}

// DeleteAllKubeService deletes all registered kubernetes types.
func (a *WithRoles) DeleteAllKubeServices(ctx context.Context) error {
	if err := a.action(defaults.Namespace, types.KindKubeService, types.VerbDelete); err != nil {
		return trace.Wrap(err)
	}
	return a.authServer.Services.DeleteAllKubeServices(ctx)
}

// NewAdminAuthServer returns auth server authorized as admin,
// used for auth server cached access
func NewAdminAuthServer(authServer *Server, sessions session.Service, alog events.IAuditLog) (*WithRoles, error) {
	ctx, err := NewAdminContext()
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return &WithRoles{
		authServer: authServer,
		context:    *ctx,
		alog:       alog,
		sessions:   sessions,
	}, nil
}

// validateServerMetadata checks that event server ID of the event
// if present, matches the passed server ID and namespace has proper syntax
func validateServerMetadata(event events.AuditEvent, serverID string) error {
	getter, ok := event.(events.ServerMetadataGetter)
	if !ok {
		return nil
	}
	if getter.GetServerID() != serverID {
		return trace.BadParameter("server %q can't emit event with server ID %q", serverID, getter.GetServerID())
	}
	if ns := getter.GetServerNamespace(); ns != "" && !types.IsValidNamespace(ns) {
		return trace.BadParameter("invalid namespace %q", ns)
	}
	return nil
}
