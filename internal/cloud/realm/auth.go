package realm

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/10gen/realm-cli/internal/cli/user"
	"github.com/10gen/realm-cli/internal/utils/api"
)

const (
	authenticatePathPattern = adminAPI + "/auth/providers/%s/login"
	authProfilePath         = adminAPI + "/auth/profile"
	authSessionPath         = adminAPI + "/auth/session"
)

// set of supported auth types
const (
	AuthTypeCloud = "mongodb-cloud"
	AuthTypeLocal = "local-userpass"
)

// Session is the Realm session
type Session struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

type authRequestCloud struct {
	PublicAPIKey  string `json:"username"`
	PrivateAPIKey string `json:"apiKey"`
}

type authRequestLocal struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func (c *client) Authenticate(authType string, creds user.Credentials) (Session, error) {
	var payload interface{}
	switch authType {
	case AuthTypeCloud:
		payload = authRequestCloud{creds.PublicAPIKey, creds.PrivateAPIKey}
	case AuthTypeLocal:
		payload = authRequestLocal{creds.Username, creds.Password}
	}

	res, resErr := c.doJSON(
		http.MethodPost,
		fmt.Sprintf(authenticatePathPattern, authType),
		payload,
		api.RequestOptions{NoAuth: true, PreventRefresh: true},
	)
	if resErr != nil {
		return Session{}, resErr
	}
	if res.StatusCode != http.StatusOK {
		return Session{}, api.ErrUnexpectedStatusCode{"authenticate", res.StatusCode}
	}
	defer res.Body.Close()

	var session Session
	if err := json.NewDecoder(res.Body).Decode(&session); err != nil {
		return Session{}, err
	}
	return session, nil
}

// AuthProfile is the user's profile
type AuthProfile struct {
	Roles []Role `json:"roles"`
}

// Role is a user role
type Role struct {
	GroupID string `json:"group_id"`
}

func (c *client) AuthProfile() (AuthProfile, error) {
	res, resErr := c.do(http.MethodGet, authProfilePath, api.RequestOptions{})
	if resErr != nil {
		return AuthProfile{}, resErr
	}
	if res.StatusCode != http.StatusOK {
		return AuthProfile{}, api.ErrUnexpectedStatusCode{"get auth profile", res.StatusCode}
	}
	defer res.Body.Close()

	var profile AuthProfile
	if err := json.NewDecoder(res.Body).Decode(&profile); err != nil {
		return AuthProfile{}, err
	}
	return profile, nil
}

func (c *client) getAuthToken(options api.RequestOptions) (string, error) {
	fmt.Println("getAuthToken: 000 -- entered")
	requiresAccessToken := !options.NoAuth
	requiresRefreshToken := options.RefreshAuth

	if requiresAccessToken || requiresRefreshToken {
		if c.profile == nil {
			fmt.Println("0")
			return "", ErrInvalidSession{}
		}

		session := c.profile.Session()
		if requiresRefreshToken {
			// fmt.Println(session.RefreshToken)
			if session.RefreshToken == "" {
				fmt.Println("getAuthToken: 001")
				return "", ErrInvalidSession{}
			}
			fmt.Println("getAuthToken: 002 - there exists a refresh token")
			return session.RefreshToken, nil
		}

		if requiresAccessToken {
			if session.AccessToken == "" {
				fmt.Println("getAuthToken: 003")
				return "", ErrInvalidSession{}
			}
			fmt.Println("getAuthToken: 004")
			return session.AccessToken, nil
		}
	}

	fmt.Println("getAuthToken 005: END")
	return "", nil
}

func (c *client) refreshAuth() error {
	fmt.Println("refreshAuth: 000 - entered")
	res, resErr := c.do(
		http.MethodPost,
		authSessionPath,
		api.RequestOptions{RefreshAuth: true},
	)
	fmt.Println("refreshAuth: 001 - do finally is gotten past")
	if resErr != nil {
		fmt.Println("refreshAuth: 002 - a resErr")
		return resErr
	}
	if res.StatusCode != http.StatusCreated {
		fmt.Println("refreshAuth: 003 - status issue")
		return ErrInvalidSession{}
	}
	defer res.Body.Close()

	var s Session
	if err := json.NewDecoder(res.Body).Decode(&s); err != nil {
		fmt.Println("refreshAuth: 004 - issue decoding body")
		return err
	}

	session := c.profile.Session()
	session.AccessToken = s.AccessToken
	c.profile.SetSession(session)
	fmt.Println("refreshAuth: 005 - end, return profile")
	return c.profile.Save()
}

// AllGroupIDs returns all group ids associated with the user's profile
func (profile AuthProfile) AllGroupIDs() []string {
	groupIDSet := map[string]struct{}{"": struct{}{}}

	var groupIDs []string
	for _, role := range profile.Roles {
		if _, ok := groupIDSet[role.GroupID]; ok {
			continue
		}
		groupIDs = append(groupIDs, role.GroupID)
		groupIDSet[role.GroupID] = struct{}{}
	}
	return groupIDs
}
