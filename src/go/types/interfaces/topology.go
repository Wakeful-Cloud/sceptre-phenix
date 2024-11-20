package ifaces

import (
	"regexp"
	"time"
)

// HexPattern is a regular expression that matches hexadecimal string
var HexPattern = regexp.MustCompile(`^x([0-9a-fA-F]+)$`)

type TopologySpec interface {
	// accepts name of default bridge
	Init(string) error
	Validate() error

	Nodes() []NodeSpec
	BootableNodes() []NodeSpec
	SchedulableNodes(string) []NodeSpec

	FindNodeByName(string) NodeSpec
	FindNodesWithLabels(...string) []NodeSpec
	FindDelayedNodes() []NodeSpec

	AddNode(string, string) NodeSpec
	RemoveNode(string)

	HasCommands() bool
}

type NodeSpec interface {
	Validate() error

	Annotations() map[string]interface{}
	Labels() map[string]string
	Type() string
	General() NodeGeneral
	Hardware() NodeHardware
	Network() NodeNetwork
	Injections() []NodeInjection
	Delay() NodeDelay
	Advanced() map[string]string
	Overrides() map[string]string
	Commands() []string
	External() bool

	SetInjections([]NodeInjection)

	AddLabel(string, string)
	AddHardware(string, int, int) NodeHardware
	AddNetworkInterface(NodeNetworkInterfaceType, string, string) NodeNetworkInterface
	AddNetworkRoute(string, string, int)
	AddInject(string, string, string, string)

	SetAdvanced(map[string]string)
	AddAdvanced(string, string)
	AddOverride(string, string)
	AddCommand(string)

	GetAnnotation(string) (interface{}, bool)
	Delayed() string
}

type NodeGeneral interface {
	Validate() error

	Hostname() string
	Description() string
	VMType() string
	Snapshot() *bool
	SetSnapshot(bool)
	DoNotBoot() *bool

	SetDoNotBoot(bool)
}

type NodeHardware interface {
	Validate() error

	CPU() string
	VCPU() int
	Memory() int
	OSType() string
	Drives() []NodeDrive

	SetVCPU(int)
	SetMemory(int)

	AddDrive(string, int) NodeDrive
}

type NodeDrive interface {
	Validate() error

	Image() string
	Interface() string
	CacheMode() string
	InjectPartition() *int

	SetInjectPartition(*int)
	SetImage(string)
}

type NodeNetwork interface {
	Validate() error

	Interfaces() []NodeNetworkInterface
	NumInterfaces(interfaceType NodeNetworkInterfaceType) int
	Routes() []NodeNetworkRoute
	OSPF() NodeNetworkOSPF
	Rulesets() []NodeNetworkRuleset
	NAT() []NodeNetworkNAT

	SetRulesets([]NodeNetworkRuleset)
	AddRuleset(NodeNetworkRuleset)

	InterfaceAddress(string) string
}

type NodeNetworkInterface interface {
	Validate() error

	Name() string
	Type() NodeNetworkInterfaceType
	Proto() string
	UDPPort() int
	BaudRate() int
	Device() string
	VLAN() string
	Bridge() string
	Autostart() bool
	MAC() string
	Driver() string
	MTU() int
	Address() string
	Mask() int
	Gateway() string
	DNS() []string
	QinQ() bool
	RulesetIn() string
	RulesetOut() string
	Wifi() NodeNetworkInterfaceWifi

	SetName(string)
	SetType(NodeNetworkInterfaceType)
	SetProto(string)
	SetUDPPort(int)
	SetBaudRate(int)
	SetDevice(string)
	SetVLAN(string)
	SetBridge(string)
	SetAutostart(bool)
	SetMAC(string)
	SetMTU(int)
	SetAddress(string)
	SetMask(int)
	SetGateway(string)
	SetDNS([]string)
	SetQinQ(bool)
	SetRulesetIn(string)
	SetRulesetOut(string)
}

// NodeNetworkInterfaceType is the type of network interface
type NodeNetworkInterfaceType string

const (
	// Ethernet interface
	NodeNetworkInterfaceTypeEthernet = "ethernet"

	// Wifi interface
	NodeNetworkInterfaceTypeWifi = "wifi"
)

// NodeNetworkInterfaceWifi is a Wifi interface
type NodeNetworkInterfaceWifi interface {
	Validate() error

	// Mode is the Wifi interface mode
	Mode() NodeNetworkInterfaceWifiMode

	// SSID is the Wifi network name
	SSID() string

	// Hidden is whether or not the Wifi network is hidden
	Hidden() bool

	// Auth is the authentication configuration for the Wifi interface
	Auth() NodeNetworkInterfaceWifiAuth

	// Position is the position of the Wifi station
	Position() NodeNetworkInterfaceWifiPosition

	// Extra is the extra configuration for the Wifi interface
	Extra() []NodeNetworkInterfaceWifiExtraItem

	// AP is the AP-mode configuration for the Wifi interface
	AP() NodeNetworkInterfaceWifiAp

	// Infrastructure is the infrastructure-mode configuration for the Wifi interface
	Infrastructure() NodeNetworkInterfaceWifiInfrastructure

	// SetMode sets the Wifi interface mode
	SetMode(NodeNetworkInterfaceWifiMode)

	// SetSSID sets the Wifi network name
	SetSSID(string)

	// SetHidden sets whether or not the Wifi network is hidden
	SetHidden(bool)
}

// NodeNetworkInterfaceWifiMode is the type of Wifi interface mode
type NodeNetworkInterfaceWifiMode string

const (
	// Access Point (AP) mode - turns the Wifi interface into a Wifi AP
	NodeNetworkInterfaceWifiModeAp NodeNetworkInterfaceWifiMode = "ap"

	// Infrastructure mode - connects to an existing Wifi network
	NodeNetworkInterfaceWifiModeInfrastructure NodeNetworkInterfaceWifiMode = "infrastructure"
)

// NodeNetworkInterfaceWifiAuth is the authentication configuration for a Wifi interface
type NodeNetworkInterfaceWifiAuth interface {
	Validate() error

	// Mode is the authentication mode for the Wifi interface
	Mode() NodeNetworkInterfaceWifiAuthMode

	// PSK is the 64-byte pre-shared hexadecimal key for the Wifi network
	HexPassword() string

	// Passphrase is the passphrase for the Wifi network
	AsciiPassword() string

	// The EAP method to use
	Method() NodeNetworkInterfaceWifiAuthMethod

	// The client/server identity to use for EAP.
	Identity() string

	// The client identity to pass over the unencrypted channel if the chosen EAP method supports passing a different tunnelled identity; ignored if mode is not infrastructure
	AnonymousIdentity() string

	// Path to a file with one or more trusted certificate authority (CA) certificates
	CaCertificate() string

	// Path to a file containing the certificate to be used by the client/server during authentication
	Certificate() string

	// Path to a file containing the private key corresponding to client/server-certificate
	Key() string

	// Password to use to decrypt the private key specified in key if it is encrypted
	KeyPassword() string

	// Phase 2 authentication mechanism
	Phase2Auth() string

	// SetMode sets the authentication mode for the Wifi interface
	SetMode(NodeNetworkInterfaceWifiAuthMode)

	// SetPassword sets the Wifi network password
	SetPassword(string)

	// SetMethod sets the EAP method to use
	SetMethod(NodeNetworkInterfaceWifiAuthMethod)

	// SetIdentity sets the identity to use for EAP
	SetIdentity(string)

	// SetAnonymousIdentity sets the identity to pass over the un
	SetAnonymousIdentity(string)

	// SetCaCertificate sets the path to a file with one or more trusted certificate authority (CA) certificates
	SetCaCertificate(string)

	// SetCertificate sets the path to a file containing the certificate to be used by the client/server during authentication
	SetCertificate(string)

	// SetKey sets the path to a file containing the private key corresponding to client/server-certificate
	SetKey(string)

	// SetKeyPassword sets the password to use to decrypt the private key specified in key if it is encrypted
	SetKeyPassword(string)

	// SetPhase2Auth sets the phase 2 authentication mechanism
	SetPhase2Auth(string)
}

// NodeNetworkInterfaceWifiAuthMode is the type of Wifi interface authentication mode
type NodeNetworkInterfaceWifiAuthMode string

const (
	// No key authentication
	NodeNetworkInterfaceWifiAuthModeNone NodeNetworkInterfaceWifiAuthMode = "none"

	// Wired Equivalent Privacy (WEP) authentication
	NodeNetworkInterfaceWifiAuthModeWep NodeNetworkInterfaceWifiAuthMode = "wep"

	// Wi-Fi Protected Access (WPA) Personal authentication (WPA-PSK)
	NodeNetworkInterfaceWifiAuthModeWpaPersonal NodeNetworkInterfaceWifiAuthMode = "wpa-personal"

	// Wi-Fi Protected Access 2 (WPA2) Personal authentication (WPA-PSK)
	NodeNetworkInterfaceWifiAuthModeWpa2Personal NodeNetworkInterfaceWifiAuthMode = "wpa2-personal"

	// Wi-Fi Protected Access 3 (WPA3) Personal authentication (SAE)
	NodeNetworkInterfaceWifiAuthModeWpa3Personal NodeNetworkInterfaceWifiAuthMode = "wpa3-personal"

	// Wi-Fi Protected Access (WPA) Enterprise authentication (WPA-EAP)
	NodeNetworkInterfaceWifiAuthModeWpaEnterprise NodeNetworkInterfaceWifiAuthMode = "wpa-enterprise"

	// Wi-Fi Protected Access 2 (WPA2) Enterprise authentication (WPA-EAP)
	NodeNetworkInterfaceWifiAuthModeWpa2Enterprise NodeNetworkInterfaceWifiAuthMode = "wpa2-enterprise"

	// Wi-Fi Protected Access 3 (WPA3) Enterprise authentication (WPA-EAP-SUITE-B-192)
	NodeNetworkInterfaceWifiAuthModeWpa3Enterprise NodeNetworkInterfaceWifiAuthMode = "wpa3-enterprise"
)

// NodeNetworkInterfaceWifiAuthMethod is the type of EAP Wifi interface authentication method
type NodeNetworkInterfaceWifiAuthMethod string

const (
	NodeNetworkInterfaceWifiAuthMethodLeap NodeNetworkInterfaceWifiAuthMethod = "leap"
	NodeNetworkInterfaceWifiAuthMethodPeap NodeNetworkInterfaceWifiAuthMethod = "peap"
	NodeNetworkInterfaceWifiAuthMethodTls  NodeNetworkInterfaceWifiAuthMethod = "tls"
	NodeNetworkInterfaceWifiAuthMethodTtls NodeNetworkInterfaceWifiAuthMethod = "ttls"
)

// NodeNetworkInterfaceWifiPosition is the position of a Wifi station
type NodeNetworkInterfaceWifiPosition interface {
	Validate() error

	// X coordinate of the wifi station (in meters; relative to the origin)
	X() int32

	// Y coordinate of the wifi station (in meters; relative to the origin)
	Y() int32

	// Z coordinate of the wifi station (in meters; relative to the origin)
	Z() int32

	// SetX sets the X coordinate of the wifi station (in meters; relative to the origin)
	SetX(int32)

	// SetY sets the Y coordinate of the wifi station (in meters; relative to the origin)
	SetY(int32)

	// SetZ sets the Z coordinate of the wifi station (in meters; relative to the origin)
	SetZ(int32)
}

// NodeNetworkInterfaceWifiExtraItem is an extra configuration item for a Wifi interface
type NodeNetworkInterfaceWifiExtraItem interface {
	Validate() error

	// Key is the configuration item key
	Key() string

	// Value is the configuration item value (Mutually exclusive with File)
	Value() string

	// Configuration item file path on the host; this file will be copied to the node and the path to the copied file will be used as the value (Mutually exclusive with Value)
	File() string

	// SetKey sets the configuration item key
	SetKey(string)

	// SetValue sets the configuration item value (Mutually exclusive with File)
	SetValue(string)

	// SetFile sets the configuration item file path on the host; this file will be copied to the node and the path to the copied file will be used as the value (Mutually exclusive with Value)
	SetFile(string)
}

// NodeNetworkInterfaceWifiAp is the AP-mode configuration (Only used if mode is ap)
type NodeNetworkInterfaceWifiAp interface {
	Validate() error

	// Generation is the 802.11 generation of the Wifi AP
	Generation() NodeNetworkInterfaceWifiApGeneration

	// SetGeneration sets the 802.11 generation of the Wifi AP
	SetGeneration(NodeNetworkInterfaceWifiApGeneration)
}

// NodeNetworkInterfaceWifiApGeneration is the type of Wifi AP generation
type NodeNetworkInterfaceWifiApGeneration string

const (
	// 802.11b (2.4 GHz)
	NodeNetworkInterfaceWifiApGeneration1 NodeNetworkInterfaceWifiApGeneration = "1"

	// 802.11a (5 GHz)
	NodeNetworkInterfaceWifiApGeneration2 NodeNetworkInterfaceWifiApGeneration = "2"

	// 802.11g (2.4 GHz)
	NodeNetworkInterfaceWifiApGeneration3 NodeNetworkInterfaceWifiApGeneration = "3"

	// 802.11n (2.4/5 GHz)
	NodeNetworkInterfaceWifiApGeneration4 NodeNetworkInterfaceWifiApGeneration = "4"

	// 802.11ac (5 GHz)
	NodeNetworkInterfaceWifiApGeneration5 NodeNetworkInterfaceWifiApGeneration = "5"

	// 802.11ax (2.4/5 GHz)
	NodeNetworkInterfaceWifiApGeneration6 NodeNetworkInterfaceWifiApGeneration = "6"

	// 802.11ax (2.4/5/6 GHz)
	NodeNetworkInterfaceWifiApGeneration6E NodeNetworkInterfaceWifiApGeneration = "6e"

	// 802.11be (2.4/5/6 GHz)
	NodeNetworkInterfaceWifiApGeneration7 NodeNetworkInterfaceWifiApGeneration = "7"
)

// NodeNetworkInterfaceWifiInfrastructure is the infrastructure-mode configuration (Only used if mode is infrastructure)
type NodeNetworkInterfaceWifiInfrastructure interface {
	Validate() error

	// Passive is whether or not to passively scan for networks
	Passive() bool

	// SetPassive sets whether or not to passively scan for networks
	SetPassive(bool)
}

type NodeNetworkRoute interface {
	Validate() error

	Destination() string
	Next() string
	Cost() *int
}

type NodeNetworkOSPF interface {
	Validate() error

	RouterID() string
	Areas() []NodeNetworkOSPFArea
	DeadInterval() *int
	HelloInterval() *int
	RetransmissionInterval() *int
}

type NodeNetworkOSPFArea interface {
	Validate() error

	AreaID() *int
	AreaNetworks() []NodeNetworkOSPFAreaNetwork
}

type NodeNetworkOSPFAreaNetwork interface {
	Validate() error

	Network() string
}

type NodeNetworkRuleset interface {
	Validate() error

	Name() string
	Description() string
	Default() string
	Rules() []NodeNetworkRulesetRule

	UnshiftRule() NodeNetworkRulesetRule
	RemoveRule(int)
}

type NodeNetworkRulesetRule interface {
	Validate() error

	ID() int
	Description() string
	Action() string
	Protocol() string
	Source() NodeNetworkRulesetRuleAddrPort
	Destination() NodeNetworkRulesetRuleAddrPort
	Stateful() bool

	SetDescription(string)
	SetAction(string)
	SetProtocol(string)
	SetSource(string, int)
	SetDestination(string, int)
	SetStateful(bool)
}

type NodeNetworkRulesetRuleAddrPort interface {
	Validate() error

	Address() string
	Port() int
}

type NodeNetworkNAT interface {
	Validate() error

	In() []string
	Out() string
}

type NodeInjection interface {
	Validate() error

	Src() string
	Dst() string
	Description() string
	Permissions() string
}

type NodeDelay interface {
	Validate() error

	Timer() time.Duration
	User() bool
	C2() []NodeC2Delay
}

type NodeC2Delay interface {
	Validate() error

	Hostname() string
	UseUUID() bool
}
