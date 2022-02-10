package realm

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/10gen/realm-cli/internal/cli/user"
	"github.com/10gen/realm-cli/internal/utils/api"
	"github.com/kr/pretty"
)

const (
	adminAPI   = "/api/admin/v3.0"
	privateAPI = "/api/private/v1.0"

	requestOriginHeader = "X-BAAS-Request-Origin"
	cliHeaderValue      = "mongodb-baas-cli"
)

// Client is a Realm client
type Client interface {
	AuthProfile() (AuthProfile, error)
	Authenticate(authType string, credentials user.Credentials) (Session, error)

	Export(groupID, appID string, req ExportRequest) (string, *zip.Reader, error)
	ExportDependencies(groupID, appID string) (string, io.ReadCloser, error)
	ExportDependenciesArchive(groupID, appID string) (string, io.ReadCloser, error)
	Import(groupID, appID string, appData interface{}) error
	ImportDependencies(groupID, appID, uploadPath string) error
	Diff(groupID, appID string, appData interface{}) ([]string, error)
	DiffDependencies(groupID, appID, uploadPath string) (DependenciesDiff, error)
	DependenciesStatus(groupID, appID string) (DependenciesStatus, error)

	CreateApp(groupID, name string, meta AppMeta) (App, error)
	DeleteApp(groupID, appID string) error
	// TODO(REALMC-9462): remove this once /apps has "template_id" in the payload
	FindApp(groupID, appID string) (App, error)
	FindApps(filter AppFilter) ([]App, error)
	AppDescription(groupID, appID string) (AppDescription, error)

	CreateDraft(groupID, appID string) (AppDraft, error)
	DeployDraft(groupID, appID, draftID string) (AppDeployment, error)
	DiffDraft(groupID, appID, draftID string) (AppDraftDiff, error)
	DiscardDraft(groupID, appID, draftID string) error
	Deployments(groupID, appID string) ([]AppDeployment, error)
	Deployment(groupID, appID, deploymentID string) (AppDeployment, error)
	Draft(groupID, appID string) (AppDraft, error)

	Secrets(groupID, appID string) ([]Secret, error)
	CreateSecret(groupID, appID, name, value string) (Secret, error)
	DeleteSecret(groupID, appID, secretID string) error
	UpdateSecret(groupID, appID, secretID, name, value string) error

	CreateAPIKey(groupID, appID, apiKeyName string) (APIKey, error)
	CreateUser(groupID, appID, email, password string) (User, error)
	DeleteUser(groupID, appID, userID string) error
	DisableUser(groupID, appID, userID string) error
	EnableUser(groupID, appID, userID string) error
	FindUsers(groupID, appID string, filter UserFilter) ([]User, error)
	RevokeUserSessions(groupID, appID, userID string) error

	HostingAssets(groupID, appID string) ([]HostingAsset, error)
	HostingAssetUpload(groupID, appID, rootDir string, asset HostingAsset) error
	HostingAssetRemove(groupID, appID, path string) error
	HostingAssetAttributesUpdate(groupID, appID, path string, attrs ...HostingAssetAttribute) error
	HostingCacheInvalidate(groupID, appID, path string) error

	Functions(groupID, appID string) ([]Function, error)
	AppDebugExecuteFunction(groupID, appID, userID, name string, args []interface{}) (ExecutionResults, error)

	Logs(groupID, appID string, opts LogsOptions) (Logs, error)

	SchemaModels(groupID, appID, language string) ([]SchemaModel, error)

	AllTemplates() (Templates, error)
	ClientTemplate(groupID, appID, templateID string) (*zip.Reader, bool, error)
	CompatibleTemplates(groupID, appID string) (Templates, error)

	AllowedIPs(groupID, appID string) ([]AllowedIP, error)
	AllowedIPCreate(groupID, appID, address, comment string, useCurrent bool) (AllowedIP, error)
	AllowedIPUpdate(groupID, appID, allowedIPID, newAddress, newComment string) error
	AllowedIPDelete(groupID, appID, allowedIPID string) error

	Status() error
}

// NewClient creates a new Realm client
func NewClient(baseURL string) Client {
	return &client{baseURL, nil}
}

// NewAuthClient creates a new Realm client capable of managing the user's session
func NewAuthClient(baseURL string, profile *user.Profile) Client {
	return &client{baseURL, profile}
}

type client struct {
	baseURL string
	profile *user.Profile
}

func (c *client) doJSON(method, path string, payload interface{}, options api.RequestOptions) (*http.Response, error) {
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}

	options.Body = bytes.NewReader(body)
	options.ContentType = api.MediaTypeJSON

	return c.do(method, path, options)
}

func (c *client) do(method, path string, options api.RequestOptions) (*http.Response, error) {
	// fmt.Printf("do hit")
	// fmt.Printf(strconv.FormatBool(options.RefreshAuth));
	var bodyCopy bytes.Buffer
	var tee io.Reader
	if options.Body != nil {
		// fmt.Printf("not hit");
		tee = io.TeeReader(options.Body, &bodyCopy)
	}

	fmt.Println(method)
	fmt.Println((c.baseURL))
	fmt.Println(path)
	req, err := http.NewRequest(method, c.baseURL+path, tee)
	if err != nil {
		fmt.Printf("DO: 000")
		return nil, err
	}

	api.IncludeQuery(req, options.Query)

	req.Header.Set(requestOriginHeader, cliHeaderValue)

	if options.ContentType != "" {
		fmt.Printf("DO: 001: options.ContentType not empty not hit")
		req.Header.Set(api.HeaderContentType, options.ContentType)
	}

	if token, err := c.getAuthToken(options); err != nil {
		fmt.Println("DO: 002 -> getAuthToken entered")
		return nil, err
	} else if token != "" {
		fmt.Println("DO: 003: AuthToken not empty -- most likely a refresh token")
		req.Header.Set(api.HeaderAuthorization, "Bearer "+token)
	}

	client := &http.Client{}

	res, resErr := client.Do(req)
	if resErr != nil {
		fmt.Printf("DO: 004: there IS a response error")
		return nil, resErr
	}
	fmt.Printf("DO: 004/004: %d\n", res.StatusCode)
	if method == "POST" && res.StatusCode == 401 {
		return nil, ErrInvalidSession{}
	}
	if res.StatusCode >= 200 && res.StatusCode <= 299 {
		fmt.Println("DO: 005: status code is [200, 299]")
		return res, nil
	}
	defer res.Body.Close()

	parsedErr := parseResponseError(res)
	fmt.Printf("DO: error: %# v\n", pretty.Formatter(parsedErr))
	if err, ok := parsedErr.(ServerError); !ok {
		return nil, parsedErr
	} else if options.PreventRefresh || err.Code != errCodeInvalidSession {
		return nil, err
	}

	fmt.Println("DO: 006: before refreshAuth()")
	if refreshErr := c.refreshAuth(); refreshErr != nil { // loop gets stuck at refreshAuth call
		fmt.Println("DO: 007: makes it past refreshAuth! (i.e. there's a refresh error");
		c.profile.ClearSession()
		if err := c.profile.Save(); err != nil {
			fmt.Println("DO: issue saving profile")
			return nil, ErrInvalidSession{}
		}
		fmt.Println("DO: after profile session cleared, invalid session error returned")
		return nil, ErrInvalidSession{}
	}

	options.PreventRefresh = true
	options.Body = &bodyCopy

	fmt.Printf("DO: 008: end of Do")
	return c.do(method, path, options)
}
