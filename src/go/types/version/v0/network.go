package v0

import (
	"fmt"
	"net"
	"strings"

	ifaces "phenix/types/interfaces"

	"github.com/hashicorp/go-multierror"
)

type Network struct {
	InterfacesF []*Interface `json:"interfaces" yaml:"interfaces" structs:"interfaces" mapstructure:"interfaces"`
	RoutesF     []Route      `json:"routes" yaml:"routes" structs:"routes" mapstructure:"routes"`
	OSPFF       *OSPF        `json:"ospf" yaml:"ospf" structs:"ospf" mapstructure:"ospf"`
	RulesetsF   []*Ruleset   `json:"rulesets" yaml:"rulesets" structs:"rulesets" mapstructure:"rulesets"`
}

func (this Network) Validate() error {
	var errs error = nil

	for _, iface := range this.InterfacesF {
		err := iface.Validate()
		if err != nil {
			errs = multierror.Append(errs, fmt.Errorf("validating interface %v: %w", iface, err))
		}
	}

	for _, route := range this.RoutesF {
		err := route.Validate()
		if err != nil {
			errs = multierror.Append(errs, fmt.Errorf("validating route %v: %w", route, err))
		}
	}

	if this.OSPFF != nil {
		err := this.OSPFF.Validate()
		if err != nil {
			errs = multierror.Append(errs, fmt.Errorf("validating ospf %v: %w", this.OSPFF, err))
		}
	}

	for _, ruleset := range this.RulesetsF {
		err := ruleset.Validate()
		if err != nil {
			errs = multierror.Append(errs, fmt.Errorf("validating ruleset %v: %w", ruleset, err))
		}
	}

	return errs
}

func (this Network) Interfaces() []ifaces.NodeNetworkInterface {
	interfaces := make([]ifaces.NodeNetworkInterface, len(this.InterfacesF))

	for i, iface := range this.InterfacesF {
		interfaces[i] = iface
	}

	return interfaces
}

func (this Network) NumInterfaces(typ ifaces.NodeNetworkInterfaceType) int {
	count := 0

	for _, iface := range this.InterfacesF {
		if iface.TypeF == typ {
			count++
		}
	}

	return count
}

func (this Network) Routes() []ifaces.NodeNetworkRoute {
	routes := make([]ifaces.NodeNetworkRoute, len(this.RoutesF))

	for i, r := range this.RoutesF {
		routes[i] = r
	}

	return routes
}

func (this Network) OSPF() ifaces.NodeNetworkOSPF {
	return this.OSPFF
}

func (this Network) Rulesets() []ifaces.NodeNetworkRuleset {
	sets := make([]ifaces.NodeNetworkRuleset, len(this.RulesetsF))

	for i, r := range this.RulesetsF {
		sets[i] = r
	}

	return sets
}

func (Network) NAT() []ifaces.NodeNetworkNAT {
	return nil
}

func (this *Network) SetRulesets(rules []ifaces.NodeNetworkRuleset) {
	sets := make([]*Ruleset, len(rules))

	for i, r := range rules {
		sets[i] = r.(*Ruleset)
	}

	this.RulesetsF = sets
}

func (this *Network) AddRuleset(rule ifaces.NodeNetworkRuleset) {
	this.RulesetsF = append(this.RulesetsF, rule.(*Ruleset))
}

func (this *Network) InterfaceAddress(name string) string {
	for _, iface := range this.InterfacesF {
		if strings.EqualFold(iface.NameF, name) {
			return iface.AddressF
		}
	}

	return ""
}

type Interface struct {
	NameF       string                          `json:"name" yaml:"name" structs:"name" mapstructure:"name"`
	TypeF       ifaces.NodeNetworkInterfaceType `json:"type" yaml:"type" structs:"type" mapstructure:"type"`
	ProtoF      string                          `json:"proto" yaml:"proto" structs:"proto" mapstructure:"proto"`
	UDPPortF    int                             `json:"udp_port" yaml:"udp_port" structs:"udp_port" mapstructure:"udp_port"`
	BaudRateF   int                             `json:"baud_rate" yaml:"baud_rate" structs:"baud_rate" mapstructure:"baud_rate"`
	DeviceF     string                          `json:"device" yaml:"device" structs:"device" mapstructure:"device"`
	VLANF       string                          `json:"vlan" yaml:"vlan" structs:"vlan" mapstructure:"vlan"`
	BridgeF     string                          `json:"bridge" yaml:"bridge" structs:"bridge" mapstructure:"bridge"`
	AutostartF  bool                            `json:"autostart" yaml:"autostart" structs:"autostart" mapstructure:"autostart"`
	MACF        string                          `json:"mac" yaml:"mac" structs:"mac" mapstructure:"mac"`
	DriverF     string                          `json:"driver" yaml:"driver" structs:"driver" mapstructure:"driver"`
	MTUF        int                             `json:"mtu" yaml:"mtu" structs:"mtu" mapstructure:"mtu"`
	AddressF    string                          `json:"address" yaml:"address" structs:"address" mapstructure:"address"`
	MaskF       int                             `json:"mask" yaml:"mask" structs:"mask" mapstructure:"mask"`
	GatewayF    string                          `json:"gateway" yaml:"gateway" structs:"gateway" mapstructure:"gateway"`
	DNSF        []string                        `json:"dns" yaml:"dns" structs:"dns" mapstructure:"dns"`
	QinQF       bool                            `json:"qinq" yaml:"qinq" structs:"qinq" mapstructure:"qinq"`
	WifiF       *InterfaceWifi                  `json:"wifi" yaml:"wifi" structs:"wifi" mapstructure:"wifi"`
	RulesetInF  string                          `json:"ruleset_in" yaml:"ruleset_in" structs:"ruleset_in" mapstructure:"ruleset_in"`
	RulesetOutF string                          `json:"ruleset_out" yaml:"ruleset_out" structs:"ruleset_out" mapstructure:"ruleset_out"`
}

func (this Interface) Validate() error {
	var errs error = nil

	if this.WifiF != nil {
		err := this.WifiF.Validate()
		if err != nil {
			errs = multierror.Append(errs, fmt.Errorf("validating wifi %v: %w", this.WifiF, err))
		}
	}

	return errs
}

func (this Interface) Name() string {
	return this.NameF
}

func (this Interface) Type() ifaces.NodeNetworkInterfaceType {
	return this.TypeF
}

func (this Interface) Proto() string {
	return this.ProtoF
}

func (this Interface) UDPPort() int {
	return this.UDPPortF
}

func (this Interface) BaudRate() int {
	return this.BaudRateF
}

func (this Interface) Device() string {
	return this.DeviceF
}

func (this Interface) VLAN() string {
	return this.VLANF
}

func (this Interface) Bridge() string {
	return this.BridgeF
}

func (this Interface) Autostart() bool {
	return this.AutostartF
}

func (this Interface) MAC() string {
	return this.MACF
}

func (this Interface) Driver() string {
	return this.DriverF
}

func (this Interface) MTU() int {
	return this.MTUF
}

func (this Interface) Address() string {
	return this.AddressF
}

func (this Interface) Mask() int {
	return this.MaskF
}

func (this Interface) Gateway() string {
	return this.GatewayF
}

func (this Interface) DNS() []string {
	return this.DNSF
}

func (this Interface) QinQ() bool {
	return this.QinQF
}

func (this Interface) RulesetIn() string {
	return this.RulesetInF
}

func (this Interface) RulesetOut() string {
	return this.RulesetOutF
}

func (this Interface) Wifi() ifaces.NodeNetworkInterfaceWifi {
	return this.WifiF
}

func (this *Interface) SetName(name string) {
	this.NameF = name
}

func (this *Interface) SetType(typ ifaces.NodeNetworkInterfaceType) {
	this.TypeF = typ
}

func (this *Interface) SetProto(proto string) {
	this.ProtoF = proto
}

func (this *Interface) SetUDPPort(port int) {
	this.UDPPortF = port
}

func (this *Interface) SetBaudRate(rate int) {
	this.BaudRateF = rate
}

func (this *Interface) SetDevice(dev string) {
	this.DeviceF = dev
}

func (this *Interface) SetVLAN(vlan string) {
	this.VLANF = vlan
}

func (this *Interface) SetBridge(br string) {
	this.BridgeF = br
}

func (this *Interface) SetAutostart(auto bool) {
	this.AutostartF = auto
}

func (this *Interface) SetMAC(mac string) {
	this.MACF = mac
}

func (this *Interface) SetMTU(mtu int) {
	this.MTUF = mtu
}

func (this *Interface) SetAddress(addr string) {
	this.AddressF = addr
}

func (this *Interface) SetMask(mask int) {
	this.MaskF = mask
}

func (this *Interface) SetGateway(gw string) {
	this.GatewayF = gw
}

func (this *Interface) SetDNS(dns []string) {
	this.DNSF = dns
}

func (this *Interface) SetQinQ(q bool) {
	this.QinQF = q
}

func (this *Interface) SetRulesetIn(rule string) {
	this.RulesetInF = rule
}

func (this *Interface) SetRulesetOut(rule string) {
	this.RulesetOutF = rule
}

type InterfaceWifi struct {
	ModeF           ifaces.NodeNetworkInterfaceWifiMode `json:"mode" yaml:"mode" structs:"mode" mapstructure:"mode"`
	SSIDF           string                              `json:"ssid" yaml:"ssid" structs:"ssid" mapstructure:"ssid"`
	HiddenF         bool                                `json:"hidden" yaml:"hidden" structs:"hidden" mapstructure:"hidden"`
	AuthF           InterfaceWifiAuth                   `json:"auth" yaml:"auth" structs:"auth" mapstructure:"auth"`
	PositionF       InterfaceWifiPosition               `json:"position" yaml:"position" structs:"position" mapstructure:"position"`
	ExtraF          []InterfaceWifiExtraItem            `json:"extra" yaml:"extra" structs:"extra" mapstructure:"extra"`
	APF             InterfaceWifiAp                     `json:"ap" yaml:"ap" structs:"ap" mapstructure:"ap"`
	InfrastructureF InterfaceWifiInfrastructure         `json:"infrastructure" yaml:"infrastructure" structs:"infrastructure" mapstructure:"infrastructure"`
}

func (this InterfaceWifi) Validate() error {
	var errs error = nil

	err := this.AuthF.Validate()
	if err != nil {
		errs = multierror.Append(errs, fmt.Errorf("validating auth %v: %w", this.AuthF, err))
	}

	err = this.PositionF.Validate()
	if err != nil {
		errs = multierror.Append(errs, fmt.Errorf("validating position %v: %w", this.PositionF, err))
	}

	for _, extraItem := range this.ExtraF {
		err := extraItem.Validate()
		if err != nil {
			errs = multierror.Append(errs, fmt.Errorf("validating extra item %v: %w", extraItem, err))
		}
	}

	err = this.APF.Validate()
	if err != nil {
		errs = multierror.Append(errs, fmt.Errorf("validating ap %v: %w", this.APF, err))
	}

	err = this.InfrastructureF.Validate()
	if err != nil {
		errs = multierror.Append(errs, fmt.Errorf("validating infrastructure %v: %w", this.InfrastructureF, err))
	}

	return errs
}

func (this InterfaceWifi) Mode() ifaces.NodeNetworkInterfaceWifiMode {
	return this.ModeF
}

func (this InterfaceWifi) SSID() string {
	return this.SSIDF
}

func (this InterfaceWifi) Hidden() bool {
	return this.HiddenF
}

func (this InterfaceWifi) Auth() ifaces.NodeNetworkInterfaceWifiAuth {
	return &this.AuthF
}

func (this InterfaceWifi) Position() ifaces.NodeNetworkInterfaceWifiPosition {
	return &this.PositionF
}

func (this InterfaceWifi) Extra() []ifaces.NodeNetworkInterfaceWifiExtraItem {
	extraItems := make([]ifaces.NodeNetworkInterfaceWifiExtraItem, len(this.ExtraF))

	for index, extraItem := range this.ExtraF {
		extraItems[index] = &extraItem
	}

	return extraItems
}

func (this InterfaceWifi) AP() ifaces.NodeNetworkInterfaceWifiAp {
	return &this.APF
}

func (this InterfaceWifi) Infrastructure() ifaces.NodeNetworkInterfaceWifiInfrastructure {
	return &this.InfrastructureF
}

func (this *InterfaceWifi) SetMode(mode ifaces.NodeNetworkInterfaceWifiMode) {
	this.ModeF = mode
}

func (this *InterfaceWifi) SetSSID(ssid string) {
	this.SSIDF = ssid
}

func (this *InterfaceWifi) SetHidden(hidden bool) {
	this.HiddenF = hidden
}

type InterfaceWifiAuth struct {
	ModeF              ifaces.NodeNetworkInterfaceWifiAuthMode   `json:"mode" yaml:"mode" structs:"mode" mapstructure:"mode"`
	PasswordF          string                                    `json:"password,omitempty" yaml:"password,omitempty" structs:"password,omitempty" mapstructure:"password,omitempty"`
	MethodF            ifaces.NodeNetworkInterfaceWifiAuthMethod `json:"method,omitempty" yaml:"method,omitempty" structs:"method,omitempty" mapstructure:"method,omitempty"`
	IdentityF          string                                    `json:"identity,omitempty" yaml:"identity,omitempty" structs:"identity,omitempty" mapstructure:"identity,omitempty"`
	AnonymousIdentityF string                                    `json:"anonymous_identity,omitempty" yaml:"anonymous_identity,omitempty" structs:"anonymous_identity,omitempty" mapstructure:"anonymous_identity,omitempty"`
	CaCertificateF     string                                    `json:"ca_certificate,omitempty" yaml:"ca_certificate,omitempty" structs:"ca_certificate,omitempty" mapstructure:"ca_certificate,omitempty"`
	CertificateF       string                                    `json:"certificate,omitempty" yaml:"certificate,omitempty" structs:"certificate,omitempty" mapstructure:"certificate,omitempty"`
	KeyF               string                                    `json:"key,omitempty" yaml:"key,omitempty" structs:"key,omitempty" mapstructure:"key,omitempty"`
	KeyPasswordF       string                                    `json:"key_password,omitempty" yaml:"key_password,omitempty" structs:"key_password,omitempty" mapstructure:"key_password,omitempty"`
	Phase2AuthF        string                                    `json:"phase2_auth,omitempty" yaml:"phase2_auth,omitempty" structs:"phase2_auth,omitempty" mapstructure:"phase2_auth,omitempty"`
}

func (this InterfaceWifiAuth) Validate() error {
	var errs error = nil

	switch this.ModeF {
	case ifaces.NodeNetworkInterfaceWifiAuthModeNone:
		if this.PasswordF != "" {
			errs = multierror.Append(errs, fmt.Errorf("password must be empty for mode %v", this.ModeF))
		}

		if this.MethodF != "" {
			errs = multierror.Append(errs, fmt.Errorf("method must be empty for mode %v", this.ModeF))
		}

		if this.IdentityF != "" {
			errs = multierror.Append(errs, fmt.Errorf("identity must be empty for mode %v", this.ModeF))
		}

		if this.AnonymousIdentityF != "" {
			errs = multierror.Append(errs, fmt.Errorf("anonymous identity must be empty for mode %v", this.ModeF))
		}

		if this.CaCertificateF != "" {
			errs = multierror.Append(errs, fmt.Errorf("ca certificate must be empty for mode %v", this.ModeF))
		}

		if this.CertificateF != "" {
			errs = multierror.Append(errs, fmt.Errorf("certificate must be empty for mode %v", this.ModeF))
		}

		if this.KeyF != "" {
			errs = multierror.Append(errs, fmt.Errorf("key must be empty for mode %v", this.ModeF))
		}

		if this.KeyPasswordF != "" {
			errs = multierror.Append(errs, fmt.Errorf("key password must be empty for mode %v", this.ModeF))
		}

		if this.Phase2AuthF != "" {
			errs = multierror.Append(errs, fmt.Errorf("phase2 auth must be empty for mode %v", this.ModeF))
		}

	case ifaces.NodeNetworkInterfaceWifiAuthModeWep, ifaces.NodeNetworkInterfaceWifiAuthModeWpaPersonal, ifaces.NodeNetworkInterfaceWifiAuthModeWpa2Personal, ifaces.NodeNetworkInterfaceWifiAuthModeWpa3Personal:
		if this.PasswordF == "" {
			errs = multierror.Append(errs, fmt.Errorf("password must be set for mode %v", this.ModeF))
		} else if ifaces.HexPattern.MatchString(this.PasswordF) {
			switch this.ModeF {
			case ifaces.NodeNetworkInterfaceWifiAuthModeWep:
				if len(this.PasswordF) != 10 && len(this.PasswordF) != 26 && len(this.PasswordF) != 32 {
					errs = multierror.Append(errs, fmt.Errorf("password must be 10, 26, or 32 hex characters for mode %v", this.ModeF))
				}
			default:
				if len(this.PasswordF) != 64 {
					errs = multierror.Append(errs, fmt.Errorf("password must be 64 hex characters for mode %v", this.ModeF))
				}
			}
		} else {
			switch this.ModeF {
			case ifaces.NodeNetworkInterfaceWifiAuthModeWep:
				if len(this.PasswordF) != 5 && len(this.PasswordF) != 13 && len(this.PasswordF) != 16 {
					errs = multierror.Append(errs, fmt.Errorf("password must be 5, 13, or 16 ASCII characters for mode %v", this.ModeF))
				}
			default:
				if len(this.PasswordF) < 8 || len(this.PasswordF) > 63 {
					errs = multierror.Append(errs, fmt.Errorf("password must be 8-63 ASCII characters for mode %v", this.ModeF))
				}
			}
		}

		if this.MethodF != "" {
			errs = multierror.Append(errs, fmt.Errorf("method must be empty for mode %v", this.ModeF))
		}

		if this.IdentityF != "" {
			errs = multierror.Append(errs, fmt.Errorf("identity must be empty for mode %v", this.ModeF))
		}

		if this.AnonymousIdentityF != "" {
			errs = multierror.Append(errs, fmt.Errorf("anonymous identity must be empty for mode %v", this.ModeF))
		}

		if this.CaCertificateF != "" {
			errs = multierror.Append(errs, fmt.Errorf("ca certificate must be empty for mode %v", this.ModeF))
		}

		if this.CertificateF != "" {
			errs = multierror.Append(errs, fmt.Errorf("certificate must be empty for mode %v", this.ModeF))
		}

		if this.KeyF != "" {
			errs = multierror.Append(errs, fmt.Errorf("key must be empty for mode %v", this.ModeF))
		}

		if this.KeyPasswordF != "" {
			errs = multierror.Append(errs, fmt.Errorf("key password must be empty for mode %v", this.ModeF))
		}

		if this.Phase2AuthF != "" {
			errs = multierror.Append(errs, fmt.Errorf("phase2 auth must be empty for mode %v", this.ModeF))
		}

	case ifaces.NodeNetworkInterfaceWifiAuthModeWpaEnterprise, ifaces.NodeNetworkInterfaceWifiAuthModeWpa2Enterprise, ifaces.NodeNetworkInterfaceWifiAuthModeWpa3Enterprise:
		if this.MethodF == "" {
			errs = multierror.Append(errs, fmt.Errorf("method must be set for mode %v", this.ModeF))
		}

		if this.CaCertificateF == "" {
			errs = multierror.Append(errs, fmt.Errorf("ca certificate must be set for mode %v", this.ModeF))
		}

		if this.CertificateF == "" {
			errs = multierror.Append(errs, fmt.Errorf("certificate must be set for mode %v", this.ModeF))
		}

		if this.KeyF == "" {
			errs = multierror.Append(errs, fmt.Errorf("key must be set for mode %v", this.ModeF))
		}

	default:
	}

	return nil
}

func (this InterfaceWifiAuth) Mode() ifaces.NodeNetworkInterfaceWifiAuthMode {
	return this.ModeF
}

func (this InterfaceWifiAuth) HexPassword() string {
	matches := ifaces.HexPattern.FindStringSubmatch(this.PasswordF)

	if len(matches) > 0 {
		return matches[0]
	} else {
		return ""
	}
}

func (this InterfaceWifiAuth) AsciiPassword() string {
	if ifaces.HexPattern.MatchString(this.PasswordF) {
		return ""
	} else {
		return this.PasswordF
	}
}

func (this InterfaceWifiAuth) Method() ifaces.NodeNetworkInterfaceWifiAuthMethod {
	return this.MethodF
}

func (this InterfaceWifiAuth) Identity() string {
	return this.IdentityF
}

func (this InterfaceWifiAuth) AnonymousIdentity() string {
	return this.AnonymousIdentityF
}

func (this InterfaceWifiAuth) CaCertificate() string {
	return this.CaCertificateF
}

func (this InterfaceWifiAuth) Certificate() string {
	return this.CertificateF
}

func (this InterfaceWifiAuth) Key() string {
	return this.KeyF
}

func (this InterfaceWifiAuth) KeyPassword() string {
	return this.KeyPasswordF
}

func (this InterfaceWifiAuth) Phase2Auth() string {
	return this.Phase2AuthF
}

func (this *InterfaceWifiAuth) SetMode(Mode ifaces.NodeNetworkInterfaceWifiAuthMode) {
	this.ModeF = Mode
}

func (this *InterfaceWifiAuth) SetPassword(password string) {
	this.PasswordF = password
}

func (this *InterfaceWifiAuth) SetMethod(method ifaces.NodeNetworkInterfaceWifiAuthMethod) {
	this.MethodF = method
}

func (this *InterfaceWifiAuth) SetIdentity(identity string) {
	this.IdentityF = identity
}

func (this *InterfaceWifiAuth) SetAnonymousIdentity(anonymousIdentity string) {
	this.AnonymousIdentityF = anonymousIdentity
}

func (this *InterfaceWifiAuth) SetCaCertificate(caCertificate string) {
	this.CaCertificateF = caCertificate
}

func (this *InterfaceWifiAuth) SetCertificate(certificate string) {
	this.CertificateF = certificate
}

func (this *InterfaceWifiAuth) SetKey(key string) {
	this.KeyF = key
}

func (this *InterfaceWifiAuth) SetKeyPassword(keyPassword string) {
	this.KeyPasswordF = keyPassword
}

func (this *InterfaceWifiAuth) SetPhase2Auth(phase2Auth string) {
	this.Phase2AuthF = phase2Auth
}

type InterfaceWifiPosition struct {
	XF int32 `json:"x" yaml:"x" structs:"x" mapstructure:"x"`
	YF int32 `json:"y" yaml:"y" structs:"y" mapstructure:"y"`
	ZF int32 `json:"z" yaml:"z" structs:"z" mapstructure:"z"`
}

func (this InterfaceWifiPosition) Validate() error {
	return nil
}

func (this InterfaceWifiPosition) X() int32 {
	return this.XF
}

func (this InterfaceWifiPosition) Y() int32 {
	return this.YF
}

func (this InterfaceWifiPosition) Z() int32 {
	return this.ZF
}

func (this *InterfaceWifiPosition) SetX(x int32) {
	this.XF = x
}

func (this *InterfaceWifiPosition) SetY(y int32) {
	this.YF = y
}

func (this *InterfaceWifiPosition) SetZ(z int32) {
	this.ZF = z
}

type InterfaceWifiExtraItem struct {
	KeyF   string `json:"key" yaml:"key" structs:"key" mapstructure:"key"`
	ValueF string `json:"value" yaml:"value" structs:"value" mapstructure:"value"`
	FileF  string `json:"file" yaml:"file" structs:"file" mapstructure:"file"`
}

func (this InterfaceWifiExtraItem) Validate() error {
	if (this.ValueF == "") == (this.FileF == "") {
		return fmt.Errorf("either value xor file must be set")
	}

	return nil
}

func (this InterfaceWifiExtraItem) Key() string {
	return this.KeyF
}

func (this InterfaceWifiExtraItem) Value() string {
	return this.ValueF
}

func (this InterfaceWifiExtraItem) File() string {
	return this.FileF
}

func (this *InterfaceWifiExtraItem) SetKey(key string) {
	this.KeyF = key
}

func (this *InterfaceWifiExtraItem) SetValue(val string) {
	this.ValueF = val
}

func (this *InterfaceWifiExtraItem) SetFile(file string) {
	this.FileF = file
}

type InterfaceWifiAp struct {
	GenerationF ifaces.NodeNetworkInterfaceWifiApGeneration `json:"generation" yaml:"generation" structs:"generation" mapstructure:"generation"`
}

func (this InterfaceWifiAp) Validate() error {
	return nil
}

func (this InterfaceWifiAp) Generation() ifaces.NodeNetworkInterfaceWifiApGeneration {
	return this.GenerationF
}

func (this *InterfaceWifiAp) SetGeneration(generation ifaces.NodeNetworkInterfaceWifiApGeneration) {
	this.GenerationF = generation
}

type InterfaceWifiInfrastructure struct {
	PassiveF bool `json:"passive" yaml:"passive" structs:"passive" mapstructure:"passive"`
}

func (this InterfaceWifiInfrastructure) Validate() error {
	return nil
}

func (this InterfaceWifiInfrastructure) Passive() bool {
	return this.PassiveF
}

func (this *InterfaceWifiInfrastructure) SetPassive(passive bool) {
	this.PassiveF = passive
}

type Route struct {
	DestinationF string `json:"destination" yaml:"destination" structs:"destination" mapstructure:"destination"`
	NextF        string `json:"next" yaml:"next" structs:"next" mapstructure:"next"`
	CostF        *int   `json:"cost" yaml:"cost" structs:"cost" mapstructure:"cost"`
}

func (this Route) Validate() error {
	return nil
}

func (this Route) Destination() string {
	return this.DestinationF
}

func (this Route) Next() string {
	return this.NextF
}

func (this Route) Cost() *int {
	return this.CostF
}

type OSPF struct {
	RouterIDF               string `json:"router_id" yaml:"router_id" structs:"router_id" mapstructure:"router_id"`
	AreasF                  []Area `json:"areas" yaml:"areas" structs:"areas" mapstructure:"areas"`
	DeadIntervalF           *int   `json:"dead_interval" yaml:"dead_interval" structs:"dead_interval" mapstructure:"dead_interval"`
	HelloIntervalF          *int   `json:"hello_interval" yaml:"hello_interval" structs:"hello_interval" mapstructure:"hello_interval"`
	RetransmissionIntervalF *int   `json:"retransmission_interval" yaml:"retransmission_interval" structs:"retransmission_interval" mapstructure:"retransmission_interval"`
}

func (this OSPF) Validate() error {
	var errs error = nil

	for _, area := range this.AreasF {
		err := area.Validate()
		if err != nil {
			errs = multierror.Append(errs, fmt.Errorf("validating area %v: %w", area, err))
		}
	}

	return errs
}

func (this OSPF) RouterID() string {
	return this.RouterIDF
}

func (this OSPF) Areas() []ifaces.NodeNetworkOSPFArea {
	areas := make([]ifaces.NodeNetworkOSPFArea, len(this.AreasF))

	for i, a := range this.AreasF {
		areas[i] = a
	}

	return areas
}

func (this OSPF) DeadInterval() *int {
	return this.DeadIntervalF
}

func (this OSPF) HelloInterval() *int {
	return this.HelloIntervalF
}

func (this OSPF) RetransmissionInterval() *int {
	return this.RetransmissionIntervalF
}

type Area struct {
	AreaIDF       *int          `json:"area_id" yaml:"area_id" structs:"area_id" mapstructure:"area_id"`
	AreaNetworksF []AreaNetwork `json:"area_networks" yaml:"area_networks" structs:"area_networks" mapstructure:"area_networks"`
}

func (this Area) Validate() error {
	var errs error = nil

	for _, areaNetwork := range this.AreaNetworksF {
		err := areaNetwork.Validate()
		if err != nil {
			errs = multierror.Append(errs, fmt.Errorf("validating area network %v: %w", areaNetwork, err))
		}
	}

	return errs
}

func (this Area) AreaID() *int {
	return this.AreaIDF
}

func (this Area) AreaNetworks() []ifaces.NodeNetworkOSPFAreaNetwork {
	nets := make([]ifaces.NodeNetworkOSPFAreaNetwork, len(this.AreaNetworksF))

	for i, n := range this.AreaNetworksF {
		nets[i] = n
	}

	return nets
}

type AreaNetwork struct {
	NetworkF string `json:"network" yaml:"network" structs:"network" mapstructure:"network"`
}

func (this AreaNetwork) Validate() error {
	return nil
}

func (this AreaNetwork) Network() string {
	return this.NetworkF
}

type Ruleset struct {
	NameF        string  `json:"name" yaml:"name" structs:"name" mapstructure:"name"`
	DescriptionF string  `json:"description" yaml:"description" structs:"description" mapstructure:"description"`
	DefaultF     string  `json:"default" yaml:"default" structs:"default" mapstructure:"default"`
	RulesF       []*Rule `json:"rules" yaml:"rules" structs:"rules" mapstructure:"rules"`
}

func (this Ruleset) Validate() error {
	var errs error = nil

	for _, rule := range this.RulesF {
		err := rule.Validate()
		if err != nil {
			errs = multierror.Append(errs, fmt.Errorf("validating rule %v: %w", rule, err))
		}
	}

	return errs
}

func (this Ruleset) Name() string {
	return this.NameF
}

func (this Ruleset) Description() string {
	return this.DescriptionF
}

func (this Ruleset) Default() string {
	return this.DefaultF
}

func (this Ruleset) Rules() []ifaces.NodeNetworkRulesetRule {
	rules := make([]ifaces.NodeNetworkRulesetRule, len(this.RulesF))

	for i, r := range this.RulesF {
		rules[i] = r
	}

	return rules
}

func (this *Ruleset) UnshiftRule() ifaces.NodeNetworkRulesetRule {
	min := -1

	for _, rule := range this.RulesF {
		if min == -1 || rule.IDF < min {
			min = rule.IDF
		}
	}

	if min == 0 {
		return nil
	}

	r := &Rule{IDF: min - 10}

	if r.IDF < 1 {
		r.IDF = 1
	}

	this.RulesF = append([]*Rule{r}, this.RulesF...)

	return r
}

func (this *Ruleset) RemoveRule(id int) {
	idx := -1

	for i, rule := range this.RulesF {
		if rule.IDF == id {
			idx = i
			break
		}
	}

	if idx != -1 {
		this.RulesF = append(this.RulesF[:idx], this.RulesF[idx+1:]...)
	}
}

type Rule struct {
	IDF          int       `json:"id" yaml:"id" structs:"id" mapstructure:"id"`
	DescriptionF string    `json:"description" yaml:"description" structs:"description" mapstructure:"description"`
	ActionF      string    `json:"action" yaml:"action" structs:"action" mapstructure:"action"`
	ProtocolF    string    `json:"protocol" yaml:"protocol" structs:"protocol" mapstructure:"protocol"`
	SourceF      *AddrPort `json:"source" yaml:"source" structs:"source" mapstructure:"source"`
	DestinationF *AddrPort `json:"destination" yaml:"destination" structs:"destination" mapstructure:"destination"`
}

func (this Rule) Validate() error {
	return nil
}

func (this Rule) ID() int {
	return this.IDF
}

func (this Rule) Description() string {
	return this.DescriptionF
}

func (this Rule) Action() string {
	return this.ActionF
}

func (this Rule) Protocol() string {
	return this.ProtocolF
}

func (this Rule) Source() ifaces.NodeNetworkRulesetRuleAddrPort {
	return this.SourceF
}

func (this Rule) Destination() ifaces.NodeNetworkRulesetRuleAddrPort {
	return this.DestinationF
}

func (Rule) Stateful() bool {
	return false
}

func (this *Rule) SetDescription(d string) {
	this.DescriptionF = d
}

func (this *Rule) SetAction(a string) {
	this.ActionF = a
}

func (this *Rule) SetProtocol(p string) {
	this.ProtocolF = p
}

func (this *Rule) SetSource(a string, p int) {
	this.SourceF = &AddrPort{AddressF: a, PortF: p}
}

func (this *Rule) SetDestination(a string, p int) {
	this.DestinationF = &AddrPort{AddressF: a, PortF: p}
}

func (Rule) SetStateful(bool) {}

type AddrPort struct {
	AddressF string `json:"address" yaml:"address" structs:"address" mapstructure:"address"`
	PortF    int    `json:"port" yaml:"port" structs:"port" mapstructure:"port"`
}

func (this AddrPort) Validate() error {
	return nil
}

func (this AddrPort) Address() string {
	return this.AddressF
}

func (this AddrPort) Port() int {
	return this.PortF
}

func (this *Network) SetDefaults() {
	for idx, iface := range this.InterfacesF {
		if iface.BridgeF == "" {
			iface.BridgeF = "phenix"
			this.InterfacesF[idx] = iface
		}
	}
}

func (this Network) InterfaceConfig() string {
	configs := make([]string, len(this.InterfacesF))

	for i, iface := range this.InterfacesF {
		config := []string{}

		if iface.WifiF != nil {
			config = append(config,
				"wifi",
				fmt.Sprintf("%d", iface.WifiF.PositionF.XF),
				fmt.Sprintf("%d", iface.WifiF.PositionF.YF),
				fmt.Sprintf("%d", iface.WifiF.PositionF.ZF),
			)
		} else {
			config = append(config, iface.BridgeF, iface.VLANF)

			if iface.MACF != "" {
				config = append(config, iface.MACF)
			}

			if iface.DriverF != "" {
				config = append(config, iface.DriverF)
			}

			if iface.QinQF {
				config = append(config, "qinq")
			}
		}

		configs[i] = strings.Join(config, ",")
	}

	return strings.Join(configs, " ")
}

func (this Interface) LinkAddress() string {
	addr := fmt.Sprintf("%s/%d", this.AddressF, this.MaskF)

	_, n, err := net.ParseCIDR(addr)
	if err != nil {
		return addr
	}

	return n.String()
}

func (this Interface) NetworkMask() string {
	addr := fmt.Sprintf("%s/%d", this.AddressF, this.MaskF)

	_, n, err := net.ParseCIDR(addr)
	if err != nil {
		// This should really mess someone up...
		return "0.0.0.0"
	}

	m := n.Mask

	return fmt.Sprintf("%d.%d.%d.%d", m[0], m[1], m[2], m[3])
}
