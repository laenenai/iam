package pgregistry

// MapErrForTest exposes the package-private error mapper so an external
// test can assert, against a real Postgres error carrying real row values
// in its detail, that the mapping never forwards them. The property is
// only demonstrable with an error Postgres actually produced, which is why
// this cannot be an internal unit test over a synthetic value.
func MapErrForTest(err error) error { return mapErr(err) }
