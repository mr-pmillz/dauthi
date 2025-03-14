package xenmobile

import (
	"fmt"
	"strings"
	"time"

	"github.com/mr-pmillz/dauthi/utils"
)

// MDMA ...
type MDMA struct {
	Opts utils.ChargeOpts
	Logr *utils.Logger
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
  XenMobile Options:
    -a                     User-Agent for request [default: CitrixReceiver/com.zenprise build/22.11.0 Android/11 VpnCapable X1Class]

    -email                 User Email address
  `

	// Methods are available tool methods
	Methods = `
  XenMobile Methods:
    Disco                  XenMobile endpoint discovery query
    Prof                   Profile the XenMobile provisioning details
    Auth                   XenMobile user based authentication
	`

	discoveryAPI  = `https://discovery.cem.cloud.us/ads/root/domain/%s/`
	getServerInfo = `https://%s/zdm/cxf/public/getserverinfo`
	checkLogin    = `https://%s/zdm/cxf/checklogin`

	POSTcheckLogin = `login=%s&password=%s&isAvengerEnabled=false&isEmmCapable=true`
	auth           = "Auth"
)

// Init MDMA with default values and return obj
func Init(o utils.ChargeOpts) *MDMA {
	if o.Agent == "" {
		o.Agent = "CitrixReceiver/com.zenprise build/22.11.0 Android/11 VpnCapable X1Class"
	}
	if o.RUUID {
		o.UUID = utils.RandUUID(21)
	}
	log := utils.NewLogger("xenmobile")

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

// Clone copies an *MDMA for process threading
func (m *MDMA) Clone() *MDMA {
	clone := Init(m.Opts) // assign target
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

// Disco ...
func (m *MDMA) Disco() {
	m.Cycle.API.Name = `discoveryAPI`
	m.Cycle.API.URL = fmt.Sprintf(discoveryAPI, m.Opts.Endpoint)
	m.Cycle.API.Data = ""
	m.Cycle.API.Method = `GET`

	m.Cycle.API.WebCall()
	if m.Cycle.API.Resp.Status != 200 {
		m.Logr.Failf([]interface{}{m.Opts.Endpoint}, "Discovery Failed")
		return
	}

	m.Validate()
}

// Prof ...
func (m *MDMA) Prof() {
	m.Cycle.API.Name = `getServerInfo`
	m.Cycle.API.URL = fmt.Sprintf(getServerInfo, m.Opts.Endpoint)
	m.Cycle.API.Data = ""
	m.Cycle.API.Method = `GET`
	m.Cycle.API.Opts = &map[string]interface{}{
		"Header": map[string][]string{
			"User-Agent": []string{m.Opts.Agent}}}

	m.Cycle.API.WebCall()
	if m.Cycle.API.Resp.Status != 200 {
		m.Logr.Failf([]interface{}{m.Opts.Endpoint}, "Profile Failed")
		return
	}

	m.Validate()
}

// Auth ...
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

	m.Logr.Infof([]interface{}{m.Opts.Method}, "threading %d values across %d threads", m.Cycle.Length, m.Opts.Threads)

	for _, line := range lines {
		if len(lines) > 1 && line == "" {
			*m.Cycle.Buff <- true
			continue
		}

		target := m.Clone() // assign target

		if m.Opts.Method == auth {
			if line == "" {
				_ = target.Opts.UserName
			} else {
				target.Opts.UserName = line
			}
			target.Cycle.API.Name = `checkLogin`
			target.Cycle.API.URL = fmt.Sprintf(checkLogin, target.Opts.Endpoint)
			target.Cycle.API.Data = fmt.Sprintf(POSTcheckLogin, target.Opts.UserName, target.Opts.Password)
			target.Cycle.API.Method = `POST`
			target.Cycle.API.Opts = &map[string]interface{}{
				"Header": map[string][]string{
					"User-Agent":   []string{target.Opts.Agent},
					"Content-Type": []string{"application/x-www-form-urlencoded"}}}
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
				m.Logr.Infof([]interface{}{m.Opts.Endpoint, m.Opts.UserName, m.Opts.Password}, "Retrying Request")
				<-*m.Cycle.Block
				m.Thread()
				return
			}
			m.Logr.Failf([]interface{}{m.Opts.UserName, m.Opts.Password}, "Null Server Response")
		}
		m.Validate()

		// Sleep interval through Thread loop
		time.Sleep(time.Duration(m.Opts.Sleep) * time.Second)
		<-*m.Cycle.Block
		*m.Cycle.Buff <- true
	}()
}

// Validate ...
func (m *MDMA) Validate() {
	switch m.Opts.Method {
	case "disco":
		var check struct {
			WorkSpace struct {
				URL []struct {
					Value string `json:"url"`
				} `json:"serviceUrls"`
			} `json:"workspace"`
			DomainType string `json:"domainType"`
		}
		if m.Parser(&check, "json") {
			return
		}

		if len(check.WorkSpace.URL) > 0 {
			for _, url := range check.WorkSpace.URL {
				m.Logr.Successf([]interface{}{url.Value}, "Endpoint Discovery")
			}
		} else {
			m.Logr.Errorf([]interface{}{m.Opts.Method}, "Failed to identify Endpoints")
		}

	case "prof":
		var check struct {
			Enabled  bool `xml:"result>serverInfo>enrollmentConfig>enrollmentEnabled"`
			PIN      bool `xml:"result>serverInfo>enrollmentConfig>enrollmentPIN"`
			Password bool `xml:"result>serverInfo>enrollmentConfig>enrollmentPassword"`
			Type     int  `xml:"result>serverInfo>enrollmentConfig>enrollmentType"`
			User     bool `xml:"result>serverInfo>enrollmentConfig>enrollmentUsername"`
		}
		if m.Parser(&check, "xml") {
			return
		}

		if check.Enabled {
			m.Logr.Successf([]interface{}{check.Type}, "Enrollment Enabled")
		} else {
			m.Logr.Failf([]interface{}{check.Type}, "Enrollment Disabled")
		}
		if check.PIN {
			m.Logr.Successf([]interface{}{check.Type}, "PIN Authentication Enabled")
		}
		if check.Password {
			m.Logr.Successf([]interface{}{check.Type}, "Password Authentication Enabled")
		}
		if check.User {
			m.Logr.Successf([]interface{}{check.Type}, "Username Authentication Enabled")
		}

	case auth:
		var check struct {
			Answer bool `json:"result>checkLogin>answer"`
		}
		if m.Parser(&check, "json") {
			return
		}

		if check.Answer {
			m.Logr.Successf([]interface{}{m.Opts.UserName, m.Opts.Password}, "Authentication Successful")
			return
		}
		m.Logr.Failf([]interface{}{m.Opts.UserName, m.Opts.Password}, "Authentication Failed")
	}
}

// Call represents the switch function for activating all class methods
func (m *MDMA) Call() {
	switch m.Opts.Method {
	case "disco":
		if m.Opts.Endpoint == "" {
			m.Logr.Errorf([]interface{}{m.Opts.Method}, "Endpoint required")
		}
		m.Disco()

	case "prof":
		if m.Opts.Endpoint == "" {
			m.Logr.Errorf([]interface{}{m.Opts.Method}, "Endpoint required")
			return
		}
		m.Prof()

	case auth:
		if (m.Opts.UserName == "" && m.Opts.File == "") || m.Opts.Password == "" {
			m.Logr.Errorf([]interface{}{m.Opts.Method}, "User/Password or File/Password required")
			return
		}
		m.Auth()

	default:
		m.Logr.StdOut(Methods)
		m.Logr.Fatalf(nil, "Invalid Method Selected %v", m.Opts.Method)
	}
}
