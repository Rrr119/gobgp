package table

import (
	"net/netip"
	"testing"
	"time"

	"github.com/osrg/gobgp/v4/pkg/config/oc"
	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func compositeTestPath(t *testing.T, asns []uint32, communities ...string) *Path {
	t.Helper()
	nlri, err := bgp.NewIPAddrPrefix(netip.MustParsePrefix("192.0.2.0/24"))
	require.NoError(t, err)
	attrs := []bgp.PathAttributeInterface{
		bgp.NewPathAttributeOrigin(0),
		bgp.NewPathAttributeAsPath([]bgp.AsPathParamInterface{
			bgp.NewAs4PathParam(bgp.BGP_ASPATH_ATTR_TYPE_SEQ, asns),
		}),
	}
	if len(communities) != 0 {
		values := make([]uint32, 0, len(communities))
		for _, c := range communities {
			values = append(values, stringToCommunityValue(c))
		}
		attrs = append(attrs, bgp.NewPathAttributeCommunities(values))
	}
	return NewPath(bgp.RF_IPv4_UC, nil, bgp.PathNLRI{NLRI: nlri}, false, attrs, time.Now(), false)
}

func compositeTestSets() oc.DefinedSets {
	return oc.DefinedSets{
		BgpDefinedSets: oc.BgpDefinedSets{
			AsPathSets: []oc.AsPathSet{
				{AsPathSetName: "from-65001", AsPathList: []string{"^65001_"}},
			},
			CommunitySets: []oc.CommunitySet{
				{CommunitySetName: "gold", CommunityList: []string{"65001:100"}},
			},
		},
	}
}

func compositeTestStatement(name string, cond oc.BgpConditions, priority int32, disposition oc.RouteDisposition) oc.Statement {
	actions := oc.Actions{RouteDisposition: disposition}
	return oc.Statement{
		Name:       name,
		Priority:   priority,
		Conditions: oc.Conditions{BgpConditions: cond},
		Actions:    actions,
	}
}

func applyCompositeTestPolicy(t *testing.T, defs []oc.PolicyDefinition, order []string) *RoutingPolicy {
	t.Helper()
	r := NewRoutingPolicy(logger)
	require.NoError(t, r.Reset(&oc.RoutingPolicy{
		DefinedSets:       compositeTestSets(),
		PolicyDefinitions: defs,
	}, nil))
	refs := make([]*oc.PolicyDefinition, 0, len(order))
	for _, name := range order {
		refs = append(refs, &oc.PolicyDefinition{Name: name})
	}
	require.NoError(t, r.SetPolicyAssignment(GLOBAL_RIB_NAME, POLICY_DIRECTION_IMPORT, refs, ROUTE_TYPE_REJECT))
	return r
}

func TestSourceASAndCommunityCompositeCondition(t *testing.T) {
	cond := oc.BgpConditions{
		MatchAsPathCommunitySet: oc.MatchAsPathCommunitySet{
			AsPathSet:    "from-65001",
			CommunitySet: "gold",
			SourceASList: []uint32{65002},
		},
	}
	defs := []oc.PolicyDefinition{{
		Name: "composite",
		Statements: []oc.Statement{
			compositeTestStatement("accept", cond, 0, oc.ROUTE_DISPOSITION_ACCEPT_ROUTE),
		},
	}}

	r := applyCompositeTestPolicy(t, defs, []string{"composite"})
	accept := func(path *Path) bool {
		return r.ApplyPolicy(GLOBAL_RIB_NAME, POLICY_DIRECTION_IMPORT, path, nil) != nil
	}

	assert.True(t, accept(compositeTestPath(t, []uint32{65001, 65002}, "65001:100")))
	assert.False(t, accept(compositeTestPath(t, []uint32{65001, 65002})), "community must also match")
	assert.False(t, accept(compositeTestPath(t, []uint32{65001, 65003}, "65001:100")), "source AS must match")
	assert.False(t, accept(compositeTestPath(t, []uint32{65009, 65002}, "65001:100")), "AS path must match")
}

func TestSourceASConditionInvert(t *testing.T) {
	cond := oc.BgpConditions{
		MatchSourceASSet: oc.MatchSourceASSet{
			SourceASList:    []uint32{65001},
			MatchSetOptions: oc.MATCH_SET_OPTIONS_TYPE_INVERT,
		},
	}
	defs := []oc.PolicyDefinition{{
		Name: "not-from-65001",
		Statements: []oc.Statement{
			compositeTestStatement("accept", cond, 0, oc.ROUTE_DISPOSITION_ACCEPT_ROUTE),
		},
	}}
	r := applyCompositeTestPolicy(t, defs, []string{"not-from-65001"})

	assert.False(t, r.ApplyPolicy(GLOBAL_RIB_NAME, POLICY_DIRECTION_IMPORT,
		compositeTestPath(t, []uint32{65001, 65001}), nil) != nil)
	assert.True(t, r.ApplyPolicy(GLOBAL_RIB_NAME, POLICY_DIRECTION_IMPORT,
		compositeTestPath(t, []uint32{65001, 65002}), nil) != nil)
}

func TestTenPolicyCombinationsMatchManualSelection(t *testing.T) {
	composite := func(name string, priority int32, disposition oc.RouteDisposition) oc.PolicyDefinition {
		return oc.PolicyDefinition{
			Name: name,
			Statements: []oc.Statement{
				compositeTestStatement(name+"-stmt", oc.BgpConditions{
					MatchAsPathCommunitySet: oc.MatchAsPathCommunitySet{
						AsPathSet:    "from-65001",
						CommunitySet: "gold",
						SourceASList: []uint32{65002},
					},
				}, priority, disposition),
			},
		}
	}
	plain := func(name string, priority int32, disposition oc.RouteDisposition) oc.PolicyDefinition {
		return oc.PolicyDefinition{
			Name:     name,
			Priority: priority,
			Statements: []oc.Statement{
				compositeTestStatement(name+"-stmt", oc.BgpConditions{}, 0, disposition),
			},
		}
	}

	matching := compositeTestPath(t, []uint32{65001, 65002}, "65001:100")
	noCommunity := compositeTestPath(t, []uint32{65001, 65002})
	wrongSource := compositeTestPath(t, []uint32{65001, 65003}, "65001:100")
	wrongASPath := compositeTestPath(t, []uint32{65009, 65002}, "65001:100")

	tests := []struct {
		name      string
		defs      []oc.PolicyDefinition
		order     []string
		path      *Path
		accepted  bool
		wantOrder []string
		wantStmts []string
	}{
		{
			name:      "01 composite all components match",
			defs:      []oc.PolicyDefinition{composite("permit", 0, oc.ROUTE_DISPOSITION_ACCEPT_ROUTE)},
			order:     []string{"permit"},
			path:      matching,
			accepted:  true,
			wantOrder: []string{"permit"},
		},
		{
			name:      "02 community missing rejects",
			defs:      []oc.PolicyDefinition{composite("permit", 0, oc.ROUTE_DISPOSITION_ACCEPT_ROUTE)},
			order:     []string{"permit"},
			path:      noCommunity,
			accepted:  false,
			wantOrder: []string{"permit"},
		},
		{
			name:      "03 source AS mismatch rejects",
			defs:      []oc.PolicyDefinition{composite("permit", 0, oc.ROUTE_DISPOSITION_ACCEPT_ROUTE)},
			order:     []string{"permit"},
			path:      wrongSource,
			accepted:  false,
			wantOrder: []string{"permit"},
		},
		{
			name:      "04 AS_PATH mismatch rejects",
			defs:      []oc.PolicyDefinition{composite("permit", 0, oc.ROUTE_DISPOSITION_ACCEPT_ROUTE)},
			order:     []string{"permit"},
			path:      wrongASPath,
			accepted:  false,
			wantOrder: []string{"permit"},
		},
		{
			name: "05 high-priority permit wins",
			defs: []oc.PolicyDefinition{
				plain("permit", 20, oc.ROUTE_DISPOSITION_ACCEPT_ROUTE),
				plain("deny", 10, oc.ROUTE_DISPOSITION_REJECT_ROUTE),
			},
			order:     []string{"deny", "permit"},
			path:      matching,
			accepted:  true,
			wantOrder: []string{"permit", "deny"},
		},
		{
			name: "06 high-priority reject wins",
			defs: []oc.PolicyDefinition{
				plain("permit", 10, oc.ROUTE_DISPOSITION_ACCEPT_ROUTE),
				plain("deny", 20, oc.ROUTE_DISPOSITION_REJECT_ROUTE),
			},
			order:     []string{"permit", "deny"},
			path:      matching,
			accepted:  false,
			wantOrder: []string{"deny", "permit"},
		},
		{
			name: "07 equal priority keeps reference order (permit first)",
			defs: []oc.PolicyDefinition{
				plain("permit", 0, oc.ROUTE_DISPOSITION_ACCEPT_ROUTE),
				plain("deny", 0, oc.ROUTE_DISPOSITION_REJECT_ROUTE),
			},
			order:     []string{"permit", "deny"},
			path:      matching,
			accepted:  true,
			wantOrder: []string{"permit", "deny"},
		},
		{
			name: "08 equal priority keeps reference order (deny first)",
			defs: []oc.PolicyDefinition{
				plain("permit", 0, oc.ROUTE_DISPOSITION_ACCEPT_ROUTE),
				plain("deny", 0, oc.ROUTE_DISPOSITION_REJECT_ROUTE),
			},
			order:     []string{"deny", "permit"},
			path:      matching,
			accepted:  false,
			wantOrder: []string{"deny", "permit"},
		},
		{
			name: "09 statement priority overrides declaration",
			defs: []oc.PolicyDefinition{{
				Name: "mixed",
				Statements: []oc.Statement{
					compositeTestStatement("deny", oc.BgpConditions{}, 10, oc.ROUTE_DISPOSITION_REJECT_ROUTE),
					compositeTestStatement("permit", oc.BgpConditions{}, 20, oc.ROUTE_DISPOSITION_ACCEPT_ROUTE),
				},
			}},
			order:     []string{"mixed"},
			path:      matching,
			accepted:  true,
			wantOrder: []string{"mixed"},
			wantStmts: []string{"permit", "deny"},
		},
		{
			name: "10 equal statement priority keeps declaration order",
			defs: []oc.PolicyDefinition{{
				Name: "mixed",
				Statements: []oc.Statement{
					compositeTestStatement("deny", oc.BgpConditions{}, 0, oc.ROUTE_DISPOSITION_REJECT_ROUTE),
					compositeTestStatement("permit", oc.BgpConditions{}, 0, oc.ROUTE_DISPOSITION_ACCEPT_ROUTE),
				},
			}},
			order:     []string{"mixed"},
			path:      matching,
			accepted:  false,
			wantOrder: []string{"mixed"},
			wantStmts: []string{"deny", "permit"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := applyCompositeTestPolicy(t, tt.defs, tt.order)

			order := r.EvaluationOrder(GLOBAL_RIB_NAME, POLICY_DIRECTION_IMPORT)
			gotOrder := make([]string, 0, len(order))
			for _, entry := range order {
				gotOrder = append(gotOrder, entry.Policy)
			}
			assert.Equal(t, tt.wantOrder, gotOrder)
			if len(tt.wantStmts) != 0 {
				assert.Equal(t, tt.wantStmts, r.policyMap[tt.wantOrder[0]].EvaluationOrder())
			}

			got := r.ApplyPolicy(GLOBAL_RIB_NAME, POLICY_DIRECTION_IMPORT, tt.path, nil)
			assert.Equal(t, tt.accepted, got != nil, "manual table says accepted=%v", tt.accepted)

			trace := r.ApplyPolicyWithTrace(GLOBAL_RIB_NAME, POLICY_DIRECTION_IMPORT, tt.path, nil)
			assert.Equal(t, tt.accepted, trace.Accepted)
		})
	}
}

func TestStatementPriorityEvaluationOrder(t *testing.T) {
	defs := []oc.PolicyDefinition{{
		Name: "ordered",
		Statements: []oc.Statement{
			compositeTestStatement("low-deny", oc.BgpConditions{}, 1, oc.ROUTE_DISPOSITION_REJECT_ROUTE),
			compositeTestStatement("high-permit", oc.BgpConditions{}, 100, oc.ROUTE_DISPOSITION_ACCEPT_ROUTE),
			compositeTestStatement("tie-deny", oc.BgpConditions{}, 100, oc.ROUTE_DISPOSITION_REJECT_ROUTE),
		},
	}}
	r := applyCompositeTestPolicy(t, defs, []string{"ordered"})
	assert.Equal(t, []string{"high-permit", "tie-deny", "low-deny"}, r.policyMap["ordered"].EvaluationOrder())
}

func TestConfigPolicyPriorityOverridesReferenceOrder(t *testing.T) {
	defs := []oc.PolicyDefinition{
		{
			Name:     "deny",
			Priority: 10,
			Statements: []oc.Statement{
				compositeTestStatement("deny-stmt", oc.BgpConditions{}, 0, oc.ROUTE_DISPOSITION_REJECT_ROUTE),
			},
		},
		{
			Name:     "permit",
			Priority: 20,
			Statements: []oc.Statement{
				compositeTestStatement("permit-stmt", oc.BgpConditions{}, 0, oc.ROUTE_DISPOSITION_ACCEPT_ROUTE),
			},
		},
	}
	r := NewRoutingPolicy(logger)
	require.NoError(t, r.Reset(&oc.RoutingPolicy{PolicyDefinitions: defs}, nil))
	require.NoError(t, r.SetPeerPolicy("peer", oc.ApplyPolicy{
		Config: oc.ApplyPolicyConfig{
			ImportPolicyList: []string{"deny", "permit"},
		},
	}))

	order := r.EvaluationOrder("peer", POLICY_DIRECTION_IMPORT)
	require.Len(t, order, 2)
	assert.Equal(t, "permit", order[0].Policy)
	assert.Equal(t, "deny", order[1].Policy)
	assert.NotNil(t, r.ApplyPolicy("peer", POLICY_DIRECTION_IMPORT,
		compositeTestPath(t, []uint32{65001, 65002}, "65001:100"), nil))
}

func TestCompositePolicyDrivesBestPathSelection(t *testing.T) {
	goldSet, err := NewCommunitySet(oc.CommunitySet{
		CommunitySetName: "gold",
		CommunityList:    []string{"65001:100"},
	})
	require.NoError(t, err)
	policy := &Policy{
		Name: "prefer-gold",
		Statements: []*Statement{{
			Name: "set-local-pref",
			Conditions: []Condition{&AsPathCommunityCondition{
				community: &CommunityCondition{
					set:    goldSet,
					option: MATCH_OPTION_ANY,
				},
				sourceAS: &SourceASCondition{list: []uint32{65002}, option: MATCH_OPTION_ANY},
			}},
			ModActions: []Action{&LocalPrefAction{value: 200}},
		}},
	}

	gold := compositeTestPath(t, []uint32{65001, 65002}, "65001:100")
	silver := compositeTestPath(t, []uint32{65001, 65003}, "65001:200")

	_, preferred := policy.Apply(logger, gold, nil)
	_, other := policy.Apply(logger, silver, nil)
	best := compareByLocalPref(preferred, other)
	assert.Same(t, preferred, best, "the source-AS/community match must win best-path selection")
}
