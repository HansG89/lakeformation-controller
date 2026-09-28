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

// Package permission holds Lake Formation grant/revoke logic shared across
// every *Permission resource. Uses only AWS SDK types, no per-CRD Spec type.
package permission

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	svcsdk "github.com/aws/aws-sdk-go-v2/service/lakeformation"
	svcsdktypes "github.com/aws/aws-sdk-go-v2/service/lakeformation/types"
)

// client is the subset of *lakeformation.Client used by this package.
type client interface {
	GrantPermissions(context.Context, *svcsdk.GrantPermissionsInput, ...func(*svcsdk.Options)) (*svcsdk.GrantPermissionsOutput, error)
	RevokePermissions(context.Context, *svcsdk.RevokePermissionsInput, ...func(*svcsdk.Options)) (*svcsdk.RevokePermissionsOutput, error)
}

// metricsRecorder is the subset of *ackmetrics.Metrics used by this package.
type metricsRecorder interface {
	RecordAPICall(opType string, opID string, err error)
}

// GrantTarget identifies the (principal, resource) tuple that a grant
// applies to. It's the same shape regardless of which *Permission CRD kind
// is asking, since svcsdktypes.Resource is already the union covering
// Database, Table, DataLocation, LFTag, etc.
type GrantTarget struct {
	CatalogID *string
	Principal svcsdktypes.DataLakePrincipal
	Resource  svcsdktypes.Resource
	Condition *svcsdktypes.Condition
}

// Diff compares two []*string permission lists as sets (order insensitive)
// and returns the entries present in desired but not latest (added) and
// present in latest but not desired (removed).
func Diff(desired, latest []*string) (added, removed []*string) {
	desiredSet := make(map[string]struct{}, len(desired))
	for _, p := range desired {
		if p != nil {
			desiredSet[*p] = struct{}{}
		}
	}
	latestSet := make(map[string]struct{}, len(latest))
	for _, p := range latest {
		if p != nil {
			latestSet[*p] = struct{}{}
		}
	}
	for _, p := range desired {
		if p == nil {
			continue
		}
		if _, ok := latestSet[*p]; !ok {
			added = append(added, p)
		}
	}
	for _, p := range latest {
		if p == nil {
			continue
		}
		if _, ok := desiredSet[*p]; !ok {
			removed = append(removed, p)
		}
	}
	return added, removed
}

// UpdatePermissions reconciles granted permissions. Lake Formation has no
// update API, only Grant/Revoke scoped to a (Principal, Resource) tuple;
// repeated grants merge, revoke leaves the rest untouched, and Permissions
// vs PermissionsWithGrantOption toggle independently (verified live).
//
// Each list is diffed against target and only the delta is touched,
// avoiding a no-access window on purely additive changes. Assumes target's
// identity (Principal/Resource) can't change between desired and latest -
// enforced by marking those fields immutable at the CRD level.
func UpdatePermissions(
	ctx context.Context,
	c client,
	mr metricsRecorder,
	target GrantTarget,
	desiredPermissions, latestPermissions []*string,
	desiredGrantable, latestGrantable []*string,
) error {
	addedPermissions, removedPermissions := Diff(desiredPermissions, latestPermissions)
	addedGrantable, removedGrantable := Diff(desiredGrantable, latestGrantable)

	if err := revoke(ctx, c, mr, target, removedPermissions, removedGrantable); err != nil {
		return err
	}
	return grant(ctx, c, mr, target, addedPermissions, addedGrantable)
}

// grant calls GrantPermissions for target, scoped to just the given
// permission subsets. No-op if both subsets are empty.
func grant(
	ctx context.Context,
	c client,
	mr metricsRecorder,
	target GrantTarget,
	permissions, permissionsWithGrantOption []*string,
) error {
	if len(permissions) == 0 && len(permissionsWithGrantOption) == 0 {
		return nil
	}
	_, err := c.GrantPermissions(ctx, &svcsdk.GrantPermissionsInput{
		CatalogId:                  target.CatalogID,
		Condition:                  target.Condition,
		Permissions:                toSDKPermissions(permissions),
		PermissionsWithGrantOption: toSDKPermissions(permissionsWithGrantOption),
		Principal:                  &target.Principal,
		Resource:                   &target.Resource,
	})
	mr.RecordAPICall("UPDATE", "GrantPermissions", err)
	return err
}

// revoke calls RevokePermissions for target, scoped to just the given
// permission subsets. No-op if both subsets are empty.
func revoke(
	ctx context.Context,
	c client,
	mr metricsRecorder,
	target GrantTarget,
	permissions, permissionsWithGrantOption []*string,
) error {
	if len(permissions) == 0 && len(permissionsWithGrantOption) == 0 {
		return nil
	}
	_, err := c.RevokePermissions(ctx, &svcsdk.RevokePermissionsInput{
		CatalogId:                  target.CatalogID,
		Condition:                  target.Condition,
		Permissions:                toSDKPermissions(permissions),
		PermissionsWithGrantOption: toSDKPermissions(permissionsWithGrantOption),
		Principal:                  &target.Principal,
		Resource:                   &target.Resource,
	})
	mr.RecordAPICall("UPDATE", "RevokePermissions", err)
	return err
}

// toSDKPermissions converts a []*string permission list to the SDK's
// []svcsdktypes.Permission enum slice.
func toSDKPermissions(permissions []*string) []svcsdktypes.Permission {
	out := make([]svcsdktypes.Permission, 0, len(permissions))
	for _, p := range permissions {
		if p != nil {
			out = append(out, svcsdktypes.Permission(*p))
		}
	}
	return out
}

// SDKPermissionsToStrings converts the SDK's []svcsdktypes.Permission enum
// slice to a []*string permission list, the shape every *Permission CRD's
// Spec uses.
func SDKPermissionsToStrings(permissions []svcsdktypes.Permission) []*string {
	out := make([]*string, 0, len(permissions))
	for _, p := range permissions {
		out = append(out, aws.String(string(p)))
	}
	return out
}

// PermissionsCovered reports whether latest already grants everything in
// desired, treating PermissionAll in latest as covering every desired
// permission. Call once for Permissions and once for
// PermissionsWithGrantOption - ALL on one does not imply ALL on the other.
func PermissionsCovered(desired, latest []*string) bool {
	for _, l := range latest {
		if l != nil && *l == string(svcsdktypes.PermissionAll) {
			return true
		}
	}
	for _, d := range desired {
		if d == nil {
			continue
		}
		covered := false
		for _, l := range latest {
			if l != nil && *l == *d {
				covered = true
				break
			}
		}
		if !covered {
			return false
		}
	}
	return true
}

// MatchPrincipal scans a ListPermissions response for the explicit grant row
// for principalARN, skipping RAM-share-derived entries.
//
// Callers must query ListPermissions by Resource only, never Principal:
// passing both switches the API into "effective permissions" mode, which on
// accounts with hybrid access mode enabled makes IAM_ALLOWED_PRINCIPALS'
// default ALL grant look like every principal already has every permission
// (verified live).
func MatchPrincipal(
	perms []svcsdktypes.PrincipalResourcePermissions,
	principalARN string,
) (svcsdktypes.PrincipalResourcePermissions, bool) {
	if principalARN == "" {
		return svcsdktypes.PrincipalResourcePermissions{}, false
	}
	for _, elem := range perms {
		if elem.AdditionalDetails != nil && len(elem.AdditionalDetails.ResourceShare) > 0 {
			// Share-derived, not an explicit grant.
			continue
		}
		if elem.Principal == nil || elem.Principal.DataLakePrincipalIdentifier == nil {
			continue
		}
		if *elem.Principal.DataLakePrincipalIdentifier != principalARN {
			continue
		}
		return elem, true
	}
	return svcsdktypes.PrincipalResourcePermissions{}, false
}
