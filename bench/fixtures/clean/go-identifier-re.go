// False positive guard: a long Go test name contains a `re_<camelCase>`
// substring (re_ + 32+ alphanumerics) that must NOT match the resend-api rule.
package command

import "testing"

func TestInit_stateStore_reconfigureLeadingToMigrationOfLocalState(t *testing.T) {
	_ = t
}
