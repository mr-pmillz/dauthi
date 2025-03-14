package charges

import (
	"github.com/mr-pmillz/dauthi/charges/airwatch"
	"github.com/mr-pmillz/dauthi/charges/blackberry"
	"github.com/mr-pmillz/dauthi/charges/intune"
	"github.com/mr-pmillz/dauthi/charges/mfa"
	"github.com/mr-pmillz/dauthi/charges/mobileiron"
	xenmobile "github.com/mr-pmillz/dauthi/charges/xenMobile"

	"github.com/mr-pmillz/dauthi/utils"
)

// Manager is an interface supporting charge classes
type Manager interface {
	Call()
}

// Attack Interface wrapper
type Attack struct {
	Manager
}

// charge constants
const (
	tools = `
  dauthi Charges:
    disco                  Global discovery of all charges

    airwatch               VMWare AirWatch
    blackberry             BlackBerry UEM
    intune                 Microsoft Intune
    mfa                    Various MFA Authenticators
    mobileiron             Ivanti MobileIron
    xenmobile              Citrix XenMobile
	`
)

// Init for Charge
func Init(t string, o *utils.ChargeOpts) *Attack {
	switch t {
	case "airwatch":
		return &Attack{airwatch.Init(*o)}

	case "mobileiron":
		return &Attack{mobileiron.Init(*o)}

	case "xenmobile":
		return &Attack{xenmobile.Init(*o)}

	case "blackberry":
		return &Attack{blackberry.Init(*o)}

	case "intune":
		return &Attack{intune.Init(*o)}

	// case "maas360":
	// 	return &Attack{maas360.Init(*o)}

	case "mfa":
		return &Attack{mfa.Init(*o)}

	case "disco":
		o.Method = "disco"
		airwatch.Init(*o).Call()
		mobileiron.Init(*o).Call()
		xenmobile.Init(*o).Call()
		blackberry.Init(*o).Call()
		intune.Init(*o).Call()

		return nil

	default:
		return nil
	}
}

// Usage Print charge usages
func Usage(t string) string {
	switch t {
	case "airwatch":
		return airwatch.Usage + airwatch.Methods

	case "mobileiron":
		return mobileiron.Usage + mobileiron.Methods

	case "xenmobile":
		return xenmobile.Usage + xenmobile.Methods

	case "blackberry":
		return blackberry.Usage + blackberry.Methods

	case "intune":
		return intune.Usage + intune.Methods

	// case "maas360":
	// 	return maas360.Usage + maas360.Methods

	case "mfa":
		return mfa.Usage + mfa.Methods

	case "full":
		return tools + Usage("airwatch") +
			Usage("mobileiron") +
			Usage("xenmobile") +
			Usage("blackberry") +
			Usage("intune") +
			Usage("maas360") +
			Usage("mfa")

	default:
		return tools
	}
}
