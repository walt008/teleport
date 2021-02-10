package ui

import (
	"testing"

	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/teleport/lib/auth"
	"github.com/gravitational/teleport/lib/defaults"
	"gopkg.in/check.v1"
)

type UserContextSuite struct{}

var _ = check.Suite(&UserContextSuite{})

func TestUserContext(t *testing.T) { check.TestingT(t) }

func (s *UserContextSuite) TestNewUserContext(c *check.C) {
	user := &types.UserV2{
		Metadata: types.Metadata{
			Name: "root",
		},
	}

	// set some rules
	role1 := &types.RoleV3{}
	role1.SetNamespaces(types.Allow, []string{defaults.Namespace})
	role1.SetRules(types.Allow, []types.Rule{
		{
			Resources: []string{types.KindAuthConnector},
			Verbs:     auth.RW(),
		},
	})

	// not setting the rule, or explicitly denying, both denies access
	role1.SetRules(types.Deny, []types.Rule{
		{
			Resources: []string{types.KindEvent},
			Verbs:     auth.RW(),
		},
	})

	role2 := &types.RoleV3{}
	role2.SetNamespaces(types.Allow, []string{defaults.Namespace})
	role2.SetRules(types.Allow, []types.Rule{
		{
			Resources: []string{types.KindTrustedCluster},
			Verbs:     auth.RW(),
		},
	})

	// set some logins
	role1.SetLogins(types.Allow, []string{"a", "b"})
	role1.SetLogins(types.Deny, []string{"c"})
	role2.SetLogins(types.Allow, []string{"d"})

	roleSet := []types.Role{role1, role2}
	userContext, err := NewUserContext(user, roleSet)
	c.Assert(err, check.IsNil)

	allowed := access{true, true, true, true, true}
	denied := access{false, false, false, false, false}

	// test user name and acl
	c.Assert(userContext.Name, check.Equals, "root")
	c.Assert(userContext.ACL.AuthConnectors, check.DeepEquals, allowed)
	c.Assert(userContext.ACL.TrustedClusters, check.DeepEquals, allowed)
	c.Assert(userContext.ACL.AppServers, check.DeepEquals, denied)
	c.Assert(userContext.ACL.Events, check.DeepEquals, denied)
	c.Assert(userContext.ACL.Sessions, check.DeepEquals, denied)
	c.Assert(userContext.ACL.Roles, check.DeepEquals, denied)
	c.Assert(userContext.ACL.Users, check.DeepEquals, denied)
	c.Assert(userContext.ACL.Tokens, check.DeepEquals, denied)
	c.Assert(userContext.ACL.Nodes, check.DeepEquals, denied)
	c.Assert(userContext.ACL.AccessRequests, check.DeepEquals, denied)
	c.Assert(userContext.ACL.SSHLogins, check.DeepEquals, []string{"a", "b", "d"})
	c.Assert(userContext.AccessStrategy, check.DeepEquals, accessStrategy{
		Type:   types.RequestStrategyOptional,
		Prompt: "",
	})

	// test local auth type
	c.Assert(userContext.AuthType, check.Equals, authLocal)

	// test sso auth type
	user.Spec.GithubIdentities = []types.ExternalIdentity{{ConnectorID: "foo", Username: "bar"}}
	userContext, err = NewUserContext(user, roleSet)
	c.Assert(err, check.IsNil)
	c.Assert(userContext.AuthType, check.Equals, authSSO)
}
