/*
Copyright 2019 Gravitational, Inc.

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

package services

import (
	"testing"

	"github.com/gravitational/teleport/lib/fixtures"
	"github.com/gravitational/teleport/lib/utils"

	"github.com/stretchr/testify/require"
)

// TestThresholdReviewFilter verifies basic filter syntax.
func TestThresholdReviewFilter(t *testing.T) {

	// test cases consist of a context, and various filter expressions
	// which should or should not match the supplied context.
	tts := []struct {
		ctx       thresholdFilterContext
		willMatch []string
		wontMatch []string
		wontParse []string
	}{
		{ // test expected matching behavior against a basic example context
			ctx: thresholdFilterContext{
				Reviewer: reviewAuthorContext{
					Roles: []string{"dev"},
					Traits: map[string][]string{
						"teams": []string{"staging-admin"},
					},
				},
				Review: reviewParamsContext{
					Reason: "ok",
					Annotations: map[string][]string{
						"constraints": []string{"no-admin"},
					},
				},
				Request: reviewRequestContext{
					Roles:  []string{"dev"},
					Reason: "plz",
					SystemAnnotations: map[string][]string{
						"teams": []string{"staging-dev"},
					},
				},
			},
			willMatch: []string{
				`contains(reviewer.roles,"dev")`,
				`contains(reviewer.traits["teams"],"staging-admin") && contains(request.system_annotations["teams"],"staging-dev")`,
				`!contains(review.annotations["constraints"],"no-admin") || !contains(request.roles,"admin")`,
				`equals(request.reason,"plz") && equals(review.reason,"ok")`,
				`contains(reviewer.roles,"admin") || contains(reviewer.roles,"dev")`,
				`!(contains(reviewer.roles,"foo") || contains(reviewer.roles,"bar"))`,
			},
			wontMatch: []string{
				`contains(reviewer.roles, "admin")`,
				`equals(request.reason,review.reason)`,
				`!contains(reviewer.traits["teams"],"staging-admin")`,
				`contains(reviewer.roles,"admin") && contains(reviewer.roles,"dev")`,
			},
		},
		{ // test expected matching behavior against zero values
			willMatch: []string{
				`equals(request.reason,review.reason)`,
				`!contains(reviewer.traits["teams"],"staging-admin")`,
				`!contains(review.annotations["constraints"],"no-admin") || !contains(request.roles,"admin")`,
				`!(contains(reviewer.roles,"foo") || contains(reviewer.roles,"bar"))`,
			},
			wontMatch: []string{
				`contains(reviewer.roles, "admin")`,
				`contains(reviewer.roles,"admin") && contains(reviewer.roles,"dev")`,
				`contains(reviewer.roles,"dev")`,
				`contains(reviewer.traits["teams"],"staging-admin") && contains(request.system_annotations["teams"],"staging-dev")`,
				`equals(request.reason,"plz") && equals(review.reason,"ok")`,
				`contains(reviewer.roles,"admin") || contains(reviewer.roles,"dev")`,
			},
			// confirm that an empty context can be used to catch syntax errors
			wontParse: []string{
				`equals(fully.fake.path,"should-fail")`,
				`fakefunc(reviewer.roles,"some-role")`,
				`equals("too","many","params")`,
				`contains("missing-param")`,
				`contains(reviewer.partially.fake.path,"also fails")`,
				`!`,
				`&& missing-left`,
			},
		},
	}

	for _, tt := range tts {
		parser, err := NewJSONBoolParser(tt.ctx)
		require.NoError(t, err)
		for _, expr := range tt.willMatch {
			result, err := parser.EvalBoolPredicate(expr)
			require.NoError(t, err)
			require.True(t, result)
		}

		for _, expr := range tt.wontMatch {
			result, err := parser.EvalBoolPredicate(expr)
			require.NoError(t, err)
			require.False(t, result)
		}

		for _, expr := range tt.wontParse {
			_, err := parser.EvalBoolPredicate(expr)
			require.Error(t, err)
		}
	}
}

// TestAccessRequestMarshaling verifies that marshaling/unmarshaling access requests
// works as expected (failures likely indicate a problem with json schema).
func TestAccessRequestMarshaling(t *testing.T) {
	req1, err := NewAccessRequest("some-user", "role-1", "role-2")
	require.NoError(t, err)

	marshaled, err := GetAccessRequestMarshaler().MarshalAccessRequest(req1)
	require.NoError(t, err)

	req2, err := GetAccessRequestMarshaler().UnmarshalAccessRequest(marshaled)
	require.NoError(t, err)

	require.True(t, req1.Equals(req2))
}

// TestPluginDataExpectations verifies the correct behavior of the `Expect` mapping.
// Update operations which include an `Expect` mapping should not succeed unless
// all expectations match (e.g. `{"foo":"bar","spam":""}` matches the state where
// key `foo` has value `bar` and key `spam` does not exist).
func TestPluginDataExpectations(t *testing.T) {
	const rname = "my-resource"
	const pname = "my-plugin"
	data, err := NewPluginData(rname, KindAccessRequest)
	require.NoError(t, err)

	// Set two keys, expecting them to be unset.
	err = data.Update(PluginDataUpdateParams{
		Kind:     KindAccessRequest,
		Resource: rname,
		Plugin:   pname,
		Set: map[string]string{
			"hello": "world",
			"spam":  "eggs",
		},
		Expect: map[string]string{
			"hello": "",
			"spam":  "",
		},
	})
	require.NoError(t, err)

	// Expect a value which does not exist.
	err = data.Update(PluginDataUpdateParams{
		Kind:     KindAccessRequest,
		Resource: rname,
		Plugin:   pname,
		Set: map[string]string{
			"should": "fail",
		},
		Expect: map[string]string{
			"missing": "key",
		},
	})
	fixtures.AssertCompareFailed(t, err)

	// Expect a value to not exist when it does exist.
	err = data.Update(PluginDataUpdateParams{
		Kind:     KindAccessRequest,
		Resource: rname,
		Plugin:   pname,
		Set: map[string]string{
			"should": "fail",
		},
		Expect: map[string]string{
			"hello": "world",
			"spam":  "",
		},
	})
	fixtures.AssertCompareFailed(t, err)

	// Expect the correct state, updating one key and removing another.
	err = data.Update(PluginDataUpdateParams{
		Kind:     KindAccessRequest,
		Resource: rname,
		Plugin:   pname,
		Set: map[string]string{
			"hello": "there",
			"spam":  "",
		},
		Expect: map[string]string{
			"hello": "world",
			"spam":  "eggs",
		},
	})
	require.NoError(t, err)

	// Expect the new updated state.
	err = data.Update(PluginDataUpdateParams{
		Kind:     KindAccessRequest,
		Resource: rname,
		Plugin:   pname,
		Set: map[string]string{
			"should": "succeed",
		},
		Expect: map[string]string{
			"hello": "there",
			"spam":  "",
		},
	})
	require.NoError(t, err)
}

// TestPluginDataFilterMatching verifies the expected matching behavior for PluginDataFilter
func TestPluginDataFilterMatching(t *testing.T) {
	const rname = "my-resource"
	const pname = "my-plugin"
	data, err := NewPluginData(rname, KindAccessRequest)
	require.NoError(t, err)

	var f PluginDataFilter

	// Filter for a different resource
	f.Resource = "other-resource"
	require.False(t, f.Match(data))

	// Filter for the same resource
	f.Resource = rname
	require.True(t, f.Match(data))

	// Filter for a plugin which does not have data yet
	f.Plugin = pname
	require.False(t, f.Match(data))

	// Add some data
	err = data.Update(PluginDataUpdateParams{
		Kind:     KindAccessRequest,
		Resource: rname,
		Plugin:   pname,
		Set: map[string]string{
			"spam": "eggs",
		},
	})
	// Filter again now that data exists
	require.NoError(t, err)
	require.True(t, f.Match(data))
}

// TestRequestFilterMatching verifies expected matching behavior for AccessRequestFilter.
func TestRequestFilterMatching(t *testing.T) {
	reqA, err := NewAccessRequest("alice", "role-a")
	require.NoError(t, err)

	reqB, err := NewAccessRequest("bob", "role-b")
	require.NoError(t, err)

	testCases := []struct {
		user   string
		id     string
		matchA bool
		matchB bool
	}{
		{"", "", true, true},
		{"alice", "", true, false},
		{"", reqA.GetName(), true, false},
		{"bob", reqA.GetName(), false, false},
		{"carol", "", false, false},
	}
	for _, tc := range testCases {
		m := AccessRequestFilter{
			User: tc.user,
			ID:   tc.id,
		}
		if m.Match(reqA) != tc.matchA {
			t.Errorf("bad filter behavior (a) %+v", tc)
		}
		if m.Match(reqB) != tc.matchB {
			t.Errorf("bad filter behavior (b) %+v", tc)
		}
	}
}

// TestRequestFilterConversion verifies that filters convert to and from
// maps correctly.
func TestRequestFilterConversion(t *testing.T) {
	testCases := []struct {
		f AccessRequestFilter
		m map[string]string
	}{
		{
			AccessRequestFilter{User: "alice", ID: "foo", State: RequestState_PENDING},
			map[string]string{"user": "alice", "id": "foo", "state": "PENDING"},
		},
		{
			AccessRequestFilter{User: "bob"},
			map[string]string{"user": "bob"},
		},
		{
			AccessRequestFilter{},
			map[string]string{},
		},
	}
	for _, tc := range testCases {

		if m := tc.f.IntoMap(); !utils.StringMapsEqual(m, tc.m) {
			t.Errorf("bad map encoding: expected %+v, got %+v", tc.m, m)
		}
		var f AccessRequestFilter
		if err := f.FromMap(tc.m); err != nil {
			t.Errorf("failed to parse %+v: %s", tc.m, err)
		}
		if !f.Equals(tc.f) {
			t.Errorf("bad map decoding: expected %+v, got %+v", tc.f, f)
		}
	}
	badMaps := []map[string]string{
		{"food": "carrots"},
		{"state": "homesick"},
	}
	for _, m := range badMaps {
		var f AccessRequestFilter
		require.Error(t, f.FromMap(m))
	}
}
