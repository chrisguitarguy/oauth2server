package oauth2server

import (
	"net/url"
	"time"
)

// the entity for a user in the oauth2 server's domain. This only has an identity
// which can be used to associate access tokens with a user.
type User interface {
	// returns the user's identifier in the IdP itself
	ID() string
}

type UserEmail struct {
	// The users email address
	Email string

	// whether or not the email has been verified. This probably means some out of
	// band verification like a link clicked in an email, etc.
	Verified bool
}

// User entities that implement this will support the OpenID `email` scope, this
// _may_ return empty strings in doing so the `email` claim will not included in
// the `id_token`. See https://openid.net/specs/openid-connect-basic-1_0.html#Scopes
type UserWithEmail interface {
	UserEmail() UserEmail
}

// an struct containing all the `profile` scope values from OpenID. If any of these
// are empty they'll be excluded from issued `id_tokens`
// See https://openid.net/specs/openid-connect-basic-1_0.html
type UserProfile struct {
	// the users full name
	Name string

	// given or first names of the end user
	GivenName string

	// the users surname or last name
	FamilyName string

	// the user's middle name
	MiddleName string

	// "casual" name of the end user
	Nickname string

	// the user's prefered username
	PreferredUsername string

	// link to the users web profile
	Profile *url.URL

	// link to the end users website
	Website *url.URL

	// Link to the users avatar or picture
	Picture *url.URL

	// the end users birth date, thiw will be returned in the ID token as YYYY-MM-DD
	// set the year to zeros if the user does not wish to share their birth year.
	Birthdate time.Time

	// the end users time zone
	Zoneinfo time.Location

	// the end users preferred locale, probaboy in {lang}_{CountryCode} format
	Locale string

	// the last time the end user was updated
	UpdatedAt time.Time
}

type UserWithProfile interface {
	UserProfile() UserProfile
}
