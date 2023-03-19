package saml

import uuid "github.com/nu7hatch/gouuid"

// UUID generate a new V4 UUID
func newID() string {
	u, err := uuid.NewV4()
	if err != nil {
		panic(err)
	}
	return "_" + u.String()
}
