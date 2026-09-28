// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License"). You may
// not use this file except in compliance with the License. A copy of the
// License is located at
//
//     http://aws.amazon.com/apache2.0/
//
// or in the "license" file accompanying this file. This file is distributed
// on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
// express or implied. See the License for the specific language governing
// permissions and limitations under the License.

package permission

import (
	"context"
	"sort"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	svcsdk "github.com/aws/aws-sdk-go-v2/service/lakeformation"
	svcsdktypes "github.com/aws/aws-sdk-go-v2/service/lakeformation/types"
)

func strPtrSlice(vals ...string) []*string {
	out := make([]*string, 0, len(vals))
	for _, v := range vals {
		out = append(out, aws.String(v))
	}
	return out
}

func assertSameSet(t *testing.T, got []*string, want []string) {
	t.Helper()
	gotStrs := make([]string, 0, len(got))
	for _, p := range got {
		gotStrs = append(gotStrs, *p)
	}
	sort.Strings(gotStrs)
	wantSorted := append([]string(nil), want...)
	sort.Strings(wantSorted)
	if len(gotStrs) != len(wantSorted) {
		t.Fatalf("got %v, want %v", gotStrs, wantSorted)
	}
	for i := range gotStrs {
		if gotStrs[i] != wantSorted[i] {
			t.Fatalf("got %v, want %v", gotStrs, wantSorted)
		}
	}
}

func TestDiff_PureAdd(t *testing.T) {
	added, removed := Diff(strPtrSlice("DESCRIBE", "ALTER"), strPtrSlice("DESCRIBE"))
	assertSameSet(t, added, []string{"ALTER"})
	assertSameSet(t, removed, nil)
}

func TestDiff_PureRemove(t *testing.T) {
	added, removed := Diff(strPtrSlice("DESCRIBE"), strPtrSlice("DESCRIBE", "ALTER"))
	assertSameSet(t, added, nil)
	assertSameSet(t, removed, []string{"ALTER"})
}

func TestDiff_MixedAddAndRemove(t *testing.T) {
	added, removed := Diff(strPtrSlice("DESCRIBE", "DROP"), strPtrSlice("DESCRIBE", "ALTER"))
	assertSameSet(t, added, []string{"DROP"})
	assertSameSet(t, removed, []string{"ALTER"})
}

func TestDiff_NoOp(t *testing.T) {
	added, removed := Diff(strPtrSlice("DESCRIBE", "ALTER"), strPtrSlice("ALTER", "DESCRIBE"))
	assertSameSet(t, added, nil)
	assertSameSet(t, removed, nil)
}

func TestDiff_BothEmpty(t *testing.T) {
	added, removed := Diff(nil, nil)
	assertSameSet(t, added, nil)
	assertSameSet(t, removed, nil)
}

func TestDiff_FullSwap(t *testing.T) {
	added, removed := Diff(strPtrSlice("SELECT", "DESCRIBE"), strPtrSlice("ALTER", "DROP"))
	assertSameSet(t, added, []string{"SELECT", "DESCRIBE"})
	assertSameSet(t, removed, []string{"ALTER", "DROP"})
}

func TestMatchPrincipal_Matches(t *testing.T) {
	principalARN := "arn:aws:iam::123456789012:role/test"
	perms := []svcsdktypes.PrincipalResourcePermissions{
		{
			Principal:   &svcsdktypes.DataLakePrincipal{DataLakePrincipalIdentifier: aws.String(principalARN)},
			Permissions: []svcsdktypes.Permission{svcsdktypes.PermissionDescribe},
		},
	}
	matched, ok := MatchPrincipal(perms, principalARN)
	if !ok {
		t.Fatal("expected a match")
	}
	if len(matched.Permissions) != 1 || matched.Permissions[0] != svcsdktypes.PermissionDescribe {
		t.Fatalf("unexpected matched permissions: %v", matched.Permissions)
	}
}

func TestMatchPrincipal_SkipsResourceShareRows(t *testing.T) {
	principalARN := "arn:aws:iam::123456789012:role/test"
	perms := []svcsdktypes.PrincipalResourcePermissions{
		{
			Principal:         &svcsdktypes.DataLakePrincipal{DataLakePrincipalIdentifier: aws.String(principalARN)},
			Permissions:       []svcsdktypes.Permission{svcsdktypes.PermissionAll},
			AdditionalDetails: &svcsdktypes.DetailsMap{ResourceShare: []string{"arn:aws:ram:us-east-1:123456789012:resource-share/abc"}},
		},
	}
	_, ok := MatchPrincipal(perms, principalARN)
	if ok {
		t.Fatal("expected no match: row is RAM-share-derived, not an explicit grant")
	}
}

func TestMatchPrincipal_NoMatch(t *testing.T) {
	perms := []svcsdktypes.PrincipalResourcePermissions{
		{
			Principal:   &svcsdktypes.DataLakePrincipal{DataLakePrincipalIdentifier: aws.String("arn:aws:iam::123456789012:role/someone-else")},
			Permissions: []svcsdktypes.Permission{svcsdktypes.PermissionAll},
		},
	}
	_, ok := MatchPrincipal(perms, "arn:aws:iam::123456789012:role/test")
	if ok {
		t.Fatal("expected no match for a different principal")
	}
}

func TestMatchPrincipal_EmptyPrincipalARN(t *testing.T) {
	// Regression test for the hybrid-access-mode bug: an implicit "effective"
	// row for an unset principal must never be treated as a match.
	perms := []svcsdktypes.PrincipalResourcePermissions{
		{
			Principal:   &svcsdktypes.DataLakePrincipal{DataLakePrincipalIdentifier: aws.String("IAM_ALLOWED_PRINCIPALS")},
			Permissions: []svcsdktypes.Permission{svcsdktypes.PermissionAll},
		},
	}
	_, ok := MatchPrincipal(perms, "")
	if ok {
		t.Fatal("expected no match when principalARN is empty")
	}
}

func TestPermissionsCovered_CreatorImplicitAllGrant(t *testing.T) {
	if !PermissionsCovered(strPtrSlice("SELECT", "DESCRIBE"), strPtrSlice("ALL")) {
		t.Fatal("expected ALL to cover any desired permission list")
	}
}

func TestPermissionsCovered_IAMAllowedPrincipalsDefaultAllGrant(t *testing.T) {
	if !PermissionsCovered(strPtrSlice("DESCRIBE"), strPtrSlice("ALL")) {
		t.Fatal("expected ALL to cover DESCRIBE")
	}
}

func TestPermissionsCovered_NotASuperset(t *testing.T) {
	if PermissionsCovered(strPtrSlice("SELECT"), strPtrSlice("DESCRIBE", "ALTER")) {
		t.Fatal("expected no coverage: latest lacks SELECT and has no ALL")
	}
}

type fakeClient struct {
	grantCalls  []*svcsdk.GrantPermissionsInput
	revokeCalls []*svcsdk.RevokePermissionsInput
}

func (f *fakeClient) GrantPermissions(_ context.Context, in *svcsdk.GrantPermissionsInput, _ ...func(*svcsdk.Options)) (*svcsdk.GrantPermissionsOutput, error) {
	f.grantCalls = append(f.grantCalls, in)
	return &svcsdk.GrantPermissionsOutput{}, nil
}

func (f *fakeClient) RevokePermissions(_ context.Context, in *svcsdk.RevokePermissionsInput, _ ...func(*svcsdk.Options)) (*svcsdk.RevokePermissionsOutput, error) {
	f.revokeCalls = append(f.revokeCalls, in)
	return &svcsdk.RevokePermissionsOutput{}, nil
}

type fakeMetrics struct{}

func (fakeMetrics) RecordAPICall(string, string, error) {}

func testTarget(name string) GrantTarget {
	return GrantTarget{
		CatalogID: aws.String("123456789012"),
		Principal: svcsdktypes.DataLakePrincipal{DataLakePrincipalIdentifier: aws.String("arn:aws:iam::123456789012:role/test")},
		Resource:  svcsdktypes.Resource{Database: &svcsdktypes.DatabaseResource{Name: aws.String(name)}},
	}
}

func TestUpdatePermissions_PureAdd(t *testing.T) {
	c := &fakeClient{}
	target := testTarget("db")
	err := UpdatePermissions(context.Background(), c, fakeMetrics{},
		target,
		strPtrSlice("DESCRIBE", "ALTER"), strPtrSlice("DESCRIBE"),
		nil, nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(c.revokeCalls) != 0 {
		t.Fatalf("expected no revoke calls, got %d", len(c.revokeCalls))
	}
	if len(c.grantCalls) != 1 {
		t.Fatalf("expected 1 grant call, got %d", len(c.grantCalls))
	}
	if len(c.grantCalls[0].Permissions) != 1 || string(c.grantCalls[0].Permissions[0]) != "ALTER" {
		t.Fatalf("unexpected grant permissions: %v", c.grantCalls[0].Permissions)
	}
}

func TestUpdatePermissions_PureRemove(t *testing.T) {
	c := &fakeClient{}
	target := testTarget("db")
	err := UpdatePermissions(context.Background(), c, fakeMetrics{},
		target,
		strPtrSlice("DESCRIBE"), strPtrSlice("DESCRIBE", "ALTER"),
		nil, nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(c.grantCalls) != 0 {
		t.Fatalf("expected no grant calls, got %d", len(c.grantCalls))
	}
	if len(c.revokeCalls) != 1 {
		t.Fatalf("expected 1 revoke call, got %d", len(c.revokeCalls))
	}
	if len(c.revokeCalls[0].Permissions) != 1 || string(c.revokeCalls[0].Permissions[0]) != "ALTER" {
		t.Fatalf("unexpected revoke permissions: %v", c.revokeCalls[0].Permissions)
	}
}

func TestUpdatePermissions_Mixed(t *testing.T) {
	c := &fakeClient{}
	target := testTarget("db")
	err := UpdatePermissions(context.Background(), c, fakeMetrics{},
		target,
		strPtrSlice("DESCRIBE", "DROP"), strPtrSlice("DESCRIBE", "ALTER"),
		nil, nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(c.grantCalls) != 1 || len(c.grantCalls[0].Permissions) != 1 || string(c.grantCalls[0].Permissions[0]) != "DROP" {
		t.Fatalf("unexpected grant calls: %+v", c.grantCalls)
	}
	if len(c.revokeCalls) != 1 || len(c.revokeCalls[0].Permissions) != 1 || string(c.revokeCalls[0].Permissions[0]) != "ALTER" {
		t.Fatalf("unexpected revoke calls: %+v", c.revokeCalls)
	}
}

func TestUpdatePermissions_NoOp(t *testing.T) {
	c := &fakeClient{}
	target := testTarget("db")
	err := UpdatePermissions(context.Background(), c, fakeMetrics{},
		target,
		strPtrSlice("DESCRIBE"), strPtrSlice("DESCRIBE"),
		nil, nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(c.grantCalls) != 0 || len(c.revokeCalls) != 0 {
		t.Fatalf("expected no API calls, got grant=%d revoke=%d", len(c.grantCalls), len(c.revokeCalls))
	}
}
