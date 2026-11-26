package config

import (
	"strings"
	"testing"

	"github.com/osrg/gobgp/v4/pkg/config/oc"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCompositePolicyConfigDecode(t *testing.T) {
	const cfg = `
defined-sets:
  bgp-defined-sets:
    as-path-sets:
      - as-path-set-name: from-65001
        as-path-list: ["^65001_"]
    community-sets:
      - community-set-name: gold
        community-list: ["65001:100"]
policy-definitions:
  - name: peer-filter
    priority: 30
    statements:
      - name: source-community
        priority: 250
        conditions:
          bgp-conditions:
            match-source-as-set:
              source-as-list: [65002]
              match-set-options: any
            match-as-path-community-set:
              as-path-set: from-65001
              community-set: gold
              source-as-list: [65002]
              match-set-options: any
        actions:
          route-disposition: reject-route
`
	c, err := oc.ReadConfig(strings.NewReader(cfg), "yaml")
	require.NoError(t, err)
	require.Len(t, c.PolicyDefinitions, 1)
	p := c.PolicyDefinitions[0]
	assert.Equal(t, int32(30), p.Priority)
	require.Len(t, p.Statements, 1)
	assert.Equal(t, int32(250), p.Statements[0].Priority)
	assert.Equal(t, []uint32{65002}, p.Statements[0].Conditions.BgpConditions.MatchSourceASSet.SourceASList)
	composite := p.Statements[0].Conditions.BgpConditions.MatchAsPathCommunitySet
	assert.Equal(t, "from-65001", composite.AsPathSet)
	assert.Equal(t, "gold", composite.CommunitySet)
	assert.Equal(t, []uint32{65002}, composite.SourceASList)
}
