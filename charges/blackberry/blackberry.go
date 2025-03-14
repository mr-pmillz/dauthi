package blackberry

import (
	"bytes"
	"fmt"
	URL "net/url"
	"strings"
	"time"

	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"

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
  BlackBerry Options:
    -a                     User-Agent for request [default: Agent/20.08.0.23/Android/11]

    -pub                   SPEKE secp521r1 public certificate
    -pri                   SPEKE secp521r1 private key
    -email                 User Email address
  `

	// Methods are available tool methods
	Methods = `
  BlackBerry Methods:
    Disco                  BlackBerry endpoint discovery query
    decrypt                Decrypt BlackBerry username details
    Prof                   Profile the BlackBerry provisioning details
    Auth-user              BlackBerry user based authentication
	`
	// HMACSHA512 static salt
	hmacsalt = "\xA4\x6B\xF8\x4C\xD3\x0B\xD0\x99\x49\xCA\x01\x12\xB0\x01\x4B\xE3"
	// HMACSHA512 static key
	hmackey = "\x3D\xAD\xA2\xC2\xCB\x99\x92\xF7\xE3\xFB\xE5\x13\x9E\x8B\x40\xD4\x34" +
		"\x87\x76\x90\xA2\x22\x28\xE2\xFA\x93\xA8\x04\x04\xB4\x80\x3C\xB2\x68\xB6\x04" +
		"\xEE\x75\x0B\xBC\x4C\x4F\x42\x71\x6F\xB9\xEF\x47\x04\x5C\xC5\x6D\xB8\xAF\xB5" +
		"\x6B\x99\xAB\x1F\xEF\xA5\xCD\x58\xA4"

	// aes256cbc static key
	aes256key = "\x32\xf4\x92\x98\x09\x9d\xba\xe9\x70\xd6\x6c\xaa\x29\x6a\xa2\xef\xf9" +
		"\x4e\xaf\x67\xb1\x5d\x37\xe1\x32\x84\x81\x2e\xbf\x86\x1d\xb2"

	// aes256cbc static IV
	aes256IV = "\xca\x42\x20\x38\x1a\x39\xd9\x48\xf1\x86\xd4\x03\x76\x34\x3f\x70"

	discoveryAPI = `https://discoveryservice.blackberry.com/discoveryPoxmlServlet/discoveryMdmInput`
	profileAPI   = `https://%s%s/mdm`
	enrollAPI    = `https://%s%s/mdm/enrol/%s`

	postDiscovery = `<requestInfoType xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" ` +
		`xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns="urn:schemas:rim:discovery:otarequest:mdm">` +
		`<clientVersion>12.40.1.157442</clientVersion><deviceId>unknown</deviceId><deviceModel>Pixel 2 XL` +
		`</deviceModel><deviceType>taimen</deviceType><manufacturer>Google</manufacturer><osFamily>android` +
		`</osFamily><osVersion>11</osVersion><userId>%s</userId></requestInfoType>`
	postEnrol = `<?xml version="1.0"?><enrollment version="3.0"><transaction-id>%s</transaction-id>` +
		`<speke-request><user-id>0;1;%s</user-id><client-public-key>%s</client-public-key></speke-request></enrollment>`
	_authUser = "Auth-user"
)

func b64encode(v []byte) string {
	return base64.StdEncoding.EncodeToString(v)
}

func b64decode(v string) []byte {
	data, _ := base64.StdEncoding.DecodeString(v)
	return data
}

func sha512hmac(time string) string {
	mac := hmac.New(sha512.New, []byte(hmackey))
	msg := fmt.Sprintf("unknowntaimen%s%s", time, hmacsalt)
	mac.Write([]byte(msg))
	return b64encode(mac.Sum(nil))
}

func pkcs5Padding(ciphertext []byte, blockSize int, after int) []byte {
	padding := blockSize - len(ciphertext)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padtext...)
}

func aes256encrypt(v string) string {
	bPlaintext := pkcs5Padding([]byte(v), aes.BlockSize, len(v))
	block, _ := aes.NewCipher([]byte(aes256key))
	ciphertext := make([]byte, len(bPlaintext))
	mode := cipher.NewCBCEncrypter(block, []byte(aes256IV))
	mode.CryptBlocks(ciphertext, bPlaintext)

	result := fmt.Sprintf("%s%s", aes256IV, ciphertext)
	return b64encode([]byte(result))
}

func aes256decrypt(v string) []byte {
	decoded := b64decode(v)
	pre := decoded[0:16]
	data := decoded[16:]
	block, _ := aes.NewCipher([]byte(aes256key))
	mode := cipher.NewCBCDecrypter(block, []byte(aes256IV))
	mode.CryptBlocks(data, data)
	return append(pre, data...)
}

// Init MDMA with default values and return obj
func Init(o utils.ChargeOpts) *MDMA {
	if o.Agent == "" {
		o.Agent = "Agent/20.08.0.23/Android/11"
	}
	log := utils.NewLogger("blackberry")

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

// Wrapper to parse JSON/XML objects
func (m *MDMA) parser(data interface{}, p string) bool {
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

func (m *MDMA) Disco() {
	tstamp := fmt.Sprintf("%v", time.Now().UnixMilli())

	m.Cycle.API.Name = `discoveryAPI`
	m.Cycle.API.URL = discoveryAPI
	m.Cycle.API.Data = fmt.Sprintf(postDiscovery, m.Opts.Email)
	m.Cycle.API.Method = `POST`
	m.Cycle.API.Opts = &map[string]interface{}{
		"Header": map[string][]string{
			"RequestVersion":  []string{"1.0"},
			"X-Timestamp":     []string{tstamp},
			"Content-Type":    []string{"application/xml"},
			"X-AuthToken":     []string{sha512hmac(tstamp)},
			"Accept":          []string{"application/xml"},
			"X-AuthType":      []string{"android"},
			"User-Agent":      []string{m.Opts.Agent},
			"Accept-Encoding": []string{"gzip, deflate"}}}

	m.Cycle.API.WebCall()
	if m.Cycle.API.Resp.Status != 200 {
		m.Logr.Failf([]interface{}{m.Opts.Endpoint}, "Discovery Failed")
		return
	}

	m.Validate()
}

func (m *MDMA) Prof() {
	parsedURL, _ := URL.Parse(m.Opts.Endpoint)

	m.Cycle.API.Name = `profileAPI`
	m.Cycle.API.URL = fmt.Sprintf(profileAPI, parsedURL.Host, parsedURL.Path)
	m.Cycle.API.Data = ""
	m.Cycle.API.Method = `OPTIONS`
	m.Cycle.API.Opts = &map[string]interface{}{
		"Header": map[string][]string{
			"User-Agent": []string{m.Opts.Agent}}}

	m.Cycle.API.WebCall()
	if m.Cycle.API.Resp.Header == nil {
		m.Logr.Failf([]interface{}{m.Opts.Endpoint}, "Profile Failed")
		return
	}
	m.Validate()
}

func (m *MDMA) Auth() {
	parsedURL, _ := URL.Parse(m.Opts.Endpoint)
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

	m.Logr.Infof([]interface{}{m.Opts.Method}, "buffing %d values across %d buffs", m.Cycle.Length, m.Opts.Threads)

	for _, line := range lines {
		if len(lines) > 1 && line == "" {
			*m.Cycle.Buff <- true
			continue
		}

		target := m.Clone() // assign target

		if m.Opts.Method == _authUser {
			if line == "" {
				_ = target.Opts.UserName
			} else {
				target.Opts.UserName = line
			}
			pubX, _ := hex.DecodeString(target.Opts.PubCert)
			target.Cycle.API.Name = `checkLogin`
			target.Cycle.API.URL = fmt.Sprintf(enrollAPI, parsedURL.Host, parsedURL.Path, utils.RandGUID())
			target.Cycle.API.Data = fmt.Sprintf(postEnrol, b64encode([]byte(utils.RandUUID(16))), aes256encrypt(target.Opts.UserName), b64encode(pubX))
			target.Cycle.API.Method = `PUT`
			target.Cycle.API.Opts = &map[string]interface{}{
				"Header": map[string][]string{
					"User-Agent":   []string{target.Opts.Agent},
					"Content-Type": []string{"text/plain"}}}
		}

		target.Thread()
	}

	for i := 0; i < m.Cycle.Length; i++ {
		<-*m.Cycle.Buff
	}
	close(*m.Cycle.Block)
	close(*m.Cycle.Buff)
}

// Thread represents the buffing process to loop multiple requests
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

		// Sleep interval through Buff loop
		time.Sleep(time.Duration(m.Opts.Sleep) * time.Second)
		<-*m.Cycle.Block
		*m.Cycle.Buff <- true
	}()
}

func (m *MDMA) Validate() {
	switch m.Opts.Method {
	case "Disco":
		var check struct {
			ResponseCode   int               `xml:"responseCode"`
			ActivationInfo string            `xml:"config>activationInfo"`
			Version        string            `json:"versionInfo"`
			Endpoint       map[string]string `json:"endpointInfo"`
		}
		if m.parser(&check, "xml") {
			return
		}
		if check.ResponseCode == 601 {
			m.Logr.Failf([]interface{}{m.Opts.Endpoint}, "Discovery Failed")
			return
		}

		m.Cycle.API.Resp.Body = b64decode(check.ActivationInfo)
		if m.parser(&check, "json") {
			return
		}

		m.Logr.Successf([]interface{}{m.Opts.Endpoint, check.Endpoint["serverAddress"]}, "Endpoint Discovered")

	case "Prof":
		m.Logr.Successf(nil, "Temporary Profile: \n%s\n", m.Cycle.API.Resp.Header)

	case _authUser:
		var check struct {
			Code   string `xml:"code"`
			MSG    string `xml:"message"`
			TranID string `xml:"transaction-id"`
		}
		if m.parser(&check, "xml") {
			return
		}
		m.Logr.Successf([]interface{}{m.Opts.UserName, m.Opts.Password}, "Authentication Successful")
	}
}

// Call represents the switch function for activating all class methods
func (m *MDMA) Call() {
	switch m.Opts.Method {
	case "Disco":
		if m.Opts.Email == "" {
			email := "dave@" + m.Opts.Endpoint
			m.Logr.Infof([]interface{}{m.Opts.Method}, "Using sample email: %s", email)
			m.Opts.Email = email
		}
		m.Disco()

	case "Prof":
		if m.Opts.Endpoint == "" {
			m.Logr.Errorf([]interface{}{m.Opts.Method}, "Endpoint required")
			return
		}
		m.Prof()

	case _authUser:
		if (m.Opts.UserName == "" && m.Opts.File == "") || m.Opts.PubCert == "" {
			m.Logr.Errorf([]interface{}{m.Opts.Method}, "User/PubCert or File/PubCert required")
			return
		}
		m.Auth()

	case "decrypt":
		if m.Opts.Endpoint == "" {
			m.Logr.Errorf([]interface{}{m.Opts.Method}, "CipherTXT required")
			return
		}
		data := aes256decrypt(m.Opts.Endpoint)
		m.Logr.Successf([]interface{}{m.Opts.Method}, "%x%s", data[0:16], data[16:])

	default:
		m.Logr.StdOut(Methods)
		m.Logr.Fatalf(nil, "Invalid Method Selected %v", m.Opts.Method)
	}
}
