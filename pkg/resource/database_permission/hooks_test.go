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
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	svcsdktypes "github.com/aws/aws-sdk-go-v2/service/lakeformation/types"

	svcapitypes "github.com/aws-controllers-k8s/lakeformation-controller/apis/v1alpha1"
)

func strSlice(vals ...string) []*string {
	out := make([]*string, 0, len(vals))
	for _, v := range vals {
		out = append(out, aws.String(v))
	}
	return out
}

func TestMatchAndApplyPermissions_FirstReconcile_CreatorImplicitAllGrant_Bypasses(t *testing.T) {
	rm := &resourceManager{}
	principalARN := "arn:aws:iam::123456789012:role/creator"
	perms := []svcsdktypes.PrincipalResourcePermissions{
		{
			Principal:                  &svcsdktypes.DataLakePrincipal{DataLakePrincipalIdentifier: aws.String(principalARN)},
			Permissions:                []svcsdktypes.Permission{svcsdktypes.PermissionAll},
			PermissionsWithGrantOption: []svcsdktypes.Permission{svcsdktypes.PermissionAll},
		},
	}
	ko := &svcapitypes.DatabasePermission{}
	matched, bypass := rm.matchAndApplyPermissions(
		ko,
		&svcapitypes.DataLakePrincipal{DataLakePrincipalIdentifier: aws.String(principalARN)},
		&svcapitypes.Resource{Database: &svcapitypes.DatabaseResource{Name: aws.String("db")}},
		perms, principalARN,
		true, nil,
		strSlice("DESCRIBE"), nil,
	)
	if !matched || !bypass {
		t.Fatalf("expected matched=true bypass=true, got matched=%v bypass=%v", matched, bypass)
	}
}

func TestMatchAndApplyPermissions_FirstReconcile_IAMAllowedPrincipalsDefaultAllGrant_Bypasses(t *testing.T) {
	rm := &resourceManager{}
	principalARN := "IAM_ALLOWED_PRINCIPALS"
	perms := []svcsdktypes.PrincipalResourcePermissions{
		{
			Principal:   &svcsdktypes.DataLakePrincipal{DataLakePrincipalIdentifier: aws.String(principalARN)},
			Permissions: []svcsdktypes.Permission{svcsdktypes.PermissionAll},
		},
	}
	ko := &svcapitypes.DatabasePermission{}
	matched, bypass := rm.matchAndApplyPermissions(
		ko,
		&svcapitypes.DataLakePrincipal{DataLakePrincipalIdentifier: aws.String(principalARN)},
		&svcapitypes.Resource{Database: &svcapitypes.DatabaseResource{Name: aws.String("db")}},
		perms, principalARN,
		true, nil,
		strSlice("DESCRIBE"), nil,
	)
	if !matched || !bypass {
		t.Fatalf("expected matched=true bypass=true, got matched=%v bypass=%v", matched, bypass)
	}
}

func TestMatchAndApplyPermissions_FirstReconcile_NotASuperset_NoBypass(t *testing.T) {
	rm := &resourceManager{}
	principalARN := "arn:aws:iam::123456789012:role/test"
	perms := []svcsdktypes.PrincipalResourcePermissions{
		{
			Principal:   &svcsdktypes.DataLakePrincipal{DataLakePrincipalIdentifier: aws.String(principalARN)},
			Permissions: []svcsdktypes.Permission{svcsdktypes.PermissionDescribe},
		},
	}
	ko := &svcapitypes.DatabasePermission{}
	matched, bypass := rm.matchAndApplyPermissions(
		ko,
		&svcapitypes.DataLakePrincipal{DataLakePrincipalIdentifier: aws.String(principalARN)},
		&svcapitypes.Resource{Database: &svcapitypes.DatabaseResource{Name: aws.String("db")}},
		perms, principalARN,
		true, nil,
		strSlice("SELECT"), nil,
	)
	if !matched || bypass {
		t.Fatalf("expected matched=true bypass=false, got matched=%v bypass=%v", matched, bypass)
	}
}

func TestMatchAndApplyPermissions_NotFirstReconcile_NoBypassEvenIfSuperset(t *testing.T) {
	rm := &resourceManager{}
	principalARN := "arn:aws:iam::123456789012:role/test"
	perms := []svcsdktypes.PrincipalResourcePermissions{
		{
			Principal:   &svcsdktypes.DataLakePrincipal{DataLakePrincipalIdentifier: aws.String(principalARN)},
			Permissions: []svcsdktypes.Permission{svcsdktypes.PermissionAll},
		},
	}
	ko := &svcapitypes.DatabasePermission{}
	matched, bypass := rm.matchAndApplyPermissions(
		ko,
		&svcapitypes.DataLakePrincipal{DataLakePrincipalIdentifier: aws.String(principalARN)},
		&svcapitypes.Resource{Database: &svcapitypes.DatabaseResource{Name: aws.String("db")}},
		perms, principalARN,
		false, nil,
		strSlice("SELECT"), nil,
	)
	if !matched || bypass {
		t.Fatalf("expected matched=true bypass=false, got matched=%v bypass=%v", matched, bypass)
	}
}

func TestMatchAndApplyPermissions_FirstReconcile_ConditionPresent_NoBypass(t *testing.T) {
	rm := &resourceManager{}
	principalARN := "arn:aws:iam::123456789012:role/test"
	perms := []svcsdktypes.PrincipalResourcePermissions{
		{
			Principal:   &svcsdktypes.DataLakePrincipal{DataLakePrincipalIdentifier: aws.String(principalARN)},
			Permissions: []svcsdktypes.Permission{svcsdktypes.PermissionAll},
		},
	}
	ko := &svcapitypes.DatabasePermission{}
	matched, bypass := rm.matchAndApplyPermissions(
		ko,
		&svcapitypes.DataLakePrincipal{DataLakePrincipalIdentifier: aws.String(principalARN)},
		&svcapitypes.Resource{Database: &svcapitypes.DatabaseResource{Name: aws.String("db")}},
		perms, principalARN,
		true, &svcapitypes.Condition{Expression: aws.String("tag=value")},
		strSlice("SELECT"), nil,
	)
	if !matched || bypass {
		t.Fatalf("expected matched=true bypass=false, got matched=%v bypass=%v", matched, bypass)
	}
}
