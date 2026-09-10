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

package database_permission

import (
	"context"

	ackcompare "github.com/aws-controllers-k8s/runtime/pkg/compare"
	svcsdktypes "github.com/aws/aws-sdk-go-v2/service/lakeformation/types"

	svcapitypes "github.com/aws-controllers-k8s/lakeformation-controller/apis/v1alpha1"
	"github.com/aws-controllers-k8s/lakeformation-controller/pkg/permission"
)

// customUpdateDatabasePermission delegates to pkg/permission's Grant/Revoke
// orchestration.
func (rm *resourceManager) customUpdateDatabasePermission(
	ctx context.Context,
	desired *resource,
	latest *resource,
	delta *ackcompare.Delta,
) (*resource, error) {
	ko := desired.ko.DeepCopy()
	rm.setStatusDefaults(ko)

	identityChanged := delta.DifferentAt("Spec.Principal.DataLakePrincipalIdentifier") ||
		delta.DifferentAt("Spec.Resource.Database.CatalogID") ||
		delta.DifferentAt("Spec.Resource.Database.Name")

	err := permission.UpdatePermissions(
		ctx, rm.sdkapi, rm.metrics, identityChanged,
		grantTargetFor(latest.ko), grantTargetFor(desired.ko),
		desired.ko.Spec.Permissions, latest.ko.Spec.Permissions,
		desired.ko.Spec.PermissionsWithGrantOption, latest.ko.Spec.PermissionsWithGrantOption,
	)
	if err != nil {
		return nil, err
	}

	return &resource{ko}, nil
}

// matchAndApplyPermissions finds the ListPermissions row for principalARN
// and overwrites ko's Principal/Resource/Condition/Permissions/
// PermissionsWithGrantOption from it. matched reports whether a row was
// found; bypassUnmanaged reports whether the caller should treat this as
// NotFound instead.
//
// Must overwrite Principal/Resource/Condition too, not just the permission
// lists: the generated code before this hook point copies those fields from
// the FIRST row of an unordered, Resource-only-filtered response (which can
// include other principals on the same resource) - left uncorrected,
// ackcompare sees a false identity change and Update takes the
// revoke+regrant path against the wrong principal (reproduced live).
//
// bypassUnmanaged is true only on a CR's first-ever reconcile (no
// ACKResourceMetadata yet), with no Condition on either side, when the
// matched row already covers everything desired - e.g. the resource
// creator's implicit ALL grant, or IAM_ALLOWED_PRINCIPALS' default ALL
// grant under hybrid access mode. Without this, such a CR's first reconcile
// hits ACK.Terminal "already exists, not managed by ACK" before any AWS
// call (reproduced live), since the runtime treats any sdkFind match as a
// pre-existing foreign resource unless the CR already has a finalizer.
// Bypassing lets the normal Create path run instead, issuing a real,
// additive GrantPermissions call. Any non-covering match, a Condition on
// either side, or a later reconcile keeps today's Terminal behavior.
//
// Wrapping this in an rm method (instead of calling pkg/permission from the
// hook template directly) sidesteps a goimports limitation: build-controller.sh's
// post-generation goimports pass runs from the wrong module's CWD and can't
// add a new local-package import to generated sdk.go. This file is
// hand-written and already imports pkg/permission, so no new import is
// needed in generated code.
func (rm *resourceManager) matchAndApplyPermissions(
	ko *svcapitypes.DatabasePermission,
	principal *svcapitypes.DataLakePrincipal,
	resourceSpec *svcapitypes.Resource,
	perms []svcsdktypes.PrincipalResourcePermissions,
	principalARN string,
	firstReconcile bool,
	desiredCondition *svcapitypes.Condition,
	desiredPermissions, desiredGrantable []*string,
) (matched bool, bypassUnmanaged bool) {
	elem, ok := permission.MatchPrincipal(perms, principalARN)
	if !ok {
		return false, false
	}
	if firstReconcile && desiredCondition == nil && elem.Condition == nil &&
		permission.PermissionsCovered(desiredPermissions, permission.SDKPermissionsToStrings(elem.Permissions)) &&
		permission.PermissionsCovered(desiredGrantable, permission.SDKPermissionsToStrings(elem.PermissionsWithGrantOption)) {
		return true, true
	}
	ko.Spec.Principal = principal.DeepCopy()
	ko.Spec.Resource = resourceSpec.DeepCopy()
	if elem.Condition != nil {
		ko.Spec.Condition = &svcapitypes.Condition{Expression: elem.Condition.Expression}
	} else {
		ko.Spec.Condition = nil
	}
	ko.Spec.Permissions = permission.SDKPermissionsToStrings(elem.Permissions)
	ko.Spec.PermissionsWithGrantOption = permission.SDKPermissionsToStrings(elem.PermissionsWithGrantOption)
	return true, false
}

// setSelfHealAdvisory sets the shared self-heal Advisory condition on ko.
// Wrapper method for the same goimports reason as matchAndApplyPermissions.
func (rm *resourceManager) setSelfHealAdvisory(ko *svcapitypes.DatabasePermission) {
	permission.SetSelfHealAdvisory(&resource{ko}, "DatabasePermission")
}

// grantTargetFor builds a permission.GrantTarget from a DatabasePermission's Spec.
func grantTargetFor(ko *svcapitypes.DatabasePermission) permission.GrantTarget {
	target := permission.GrantTarget{
		CatalogID: ko.Spec.CatalogID,
	}
	if ko.Spec.Condition != nil {
		target.Condition = &svcsdktypes.Condition{
			Expression: ko.Spec.Condition.Expression,
		}
	}
	if ko.Spec.Principal != nil {
		target.Principal = svcsdktypes.DataLakePrincipal{
			DataLakePrincipalIdentifier: ko.Spec.Principal.DataLakePrincipalIdentifier,
		}
	}
	if ko.Spec.Resource != nil && ko.Spec.Resource.Database != nil {
		target.Resource = svcsdktypes.Resource{
			Database: &svcsdktypes.DatabaseResource{
				CatalogId: ko.Spec.Resource.Database.CatalogID,
				Name:      ko.Spec.Resource.Database.Name,
			},
		}
	}
	return target
}
