package server

import (
	"testing"

	"github.com/osrg/gobgp/v4/api"
	"github.com/osrg/gobgp/v4/internal/pkg/table"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCompositePolicyApiRoundTrip(t *testing.T) {
	in := &api.Statement{
		Name:     "composite",
		Priority: 7,
		Conditions: &api.Conditions{
			SourceAsSet: &api.MatchSourceASSet{
				SourceAsList:    []uint32{65001, 65002},
				MatchSetOptions: api.MatchSet_TYPE_ANY,
			},
			AsPathCommunitySet: &api.MatchAsPathCommunitySet{
				AsPathSet:                "as-set",
				CommunitySet:             "community-set",
				SourceAsList:             []uint32{65002},
				MatchSetOptions:          api.MatchSet_TYPE_ANY,
				AsPathMatchSetOptions:    api.MatchSet_TYPE_ANY,
				CommunityMatchSetOptions: api.MatchSet_TYPE_ALL,
				SourceAsMatchSetOptions:  api.MatchSet_TYPE_ANY,
			},
		},
		Actions: &api.Actions{RouteAction: api.RouteAction_ROUTE_ACTION_ACCEPT},
	}

	st, err := newStatementFromApiStruct(in)
	require.NoError(t, err)
	assert.Equal(t, int32(7), st.Priority)
	require.Len(t, st.Conditions, 2)

	out := table.ToStatementApi(st.ToConfig())
	assert.Equal(t, int32(7), out.Priority)
	require.NotNil(t, out.Conditions)
	assert.Equal(t, []uint32{65001, 65002}, out.Conditions.SourceAsSet.SourceAsList)
	require.NotNil(t, out.Conditions.AsPathCommunitySet)
	assert.Equal(t, "as-set", out.Conditions.AsPathCommunitySet.AsPathSet)
	assert.Equal(t, "community-set", out.Conditions.AsPathCommunitySet.CommunitySet)
	assert.Equal(t, []uint32{65002}, out.Conditions.AsPathCommunitySet.SourceAsList)
	assert.Equal(t, api.MatchSet_TYPE_ALL, out.Conditions.AsPathCommunitySet.CommunityMatchSetOptions)

	p, err := newPolicyFromApiStruct(&api.Policy{Name: "policy", Priority: 11})
	require.NoError(t, err)
	assert.Equal(t, int32(11), p.Priority)
}
