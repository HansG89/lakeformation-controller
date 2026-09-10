// Resource-only filter above can return rows for other principals/shares;
// match the right one here instead of trusting the first row.
principalARN := ""
if r.ko.Spec.Principal != nil && r.ko.Spec.Principal.DataLakePrincipalIdentifier != nil {
	principalARN = *r.ko.Spec.Principal.DataLakePrincipalIdentifier
}
// First reconcile matching a row that already covers everything desired is
// a benign pre-existing implicit grant, not a foreign unmanaged resource;
// report NotFound so the normal Create path runs instead of Terminal.
firstReconcile := r.ko.Status.ACKResourceMetadata == nil
matchedRow, bypassUnmanaged := rm.matchAndApplyPermissions(
	ko, r.ko.Spec.Principal, r.ko.Spec.Resource, resp.PrincipalResourcePermissions,
	principalARN, firstReconcile, r.ko.Spec.Condition,
	r.ko.Spec.Permissions, r.ko.Spec.PermissionsWithGrantOption,
)
if !matchedRow || bypassUnmanaged {
	return nil, ackerr.NotFound
}
