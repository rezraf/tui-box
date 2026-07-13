//go:build !darwin

package update

func validatePathACL(string) error {
	return nil
}

func stripPathACL(string) error {
	return nil
}
