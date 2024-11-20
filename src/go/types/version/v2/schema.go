package v2

var OpenAPI = []byte(`
openapi: "3.0.0"
info:
  title: phenix config specs
  version: "2.0"
paths: {}
components:
  schemas:
    Image:
      type: object
      required:
      - format
      - mirror
      - release
      - size
      - variant
      properties:
        compress:
          type: boolean
          default: false
          example: false
        deb_append:
          type: string
          example: --components=main,restricted
        format:
          type: string
          example: qcow2
        mirror:
          type: string
          example: http://us.archive.ubuntu.com/ubuntu/
        overlays:
          type: array
          nullable: true
          items:
            type: string
          example:
          - /phenix/vmdb/overlays/example-overlay
        packages:
          type: array
          nullable: true
          items:
            type: string
          example:
          - isc-dhcp-client
          - openssh-server
        ramdisk:
          type: boolean
          default: false
          example: false
        release:
          type: string
          example: focal
        script_order:
          type: array
          nullable: true
          items:
            type: string
          example:
          - POSTBUILD_APT_CLEANUP
        scripts:
          type: object
          nullable: true
          additionalProperties:
            type: string
          example:
            POSTBUILD_APT_CLEANUP: |
              apt clean || apt-get clean || echo "unable to clean apt cache"
        size:
          type: string
          example: 10G
        variant:
          type: string
          example: minbase
    Role:
      type: object
      required:
      - policies
      - roleName
      properties:
        policies:
          type: array
          items:
            type: object
            properties:
              resources:
                type: array
                items:
                  type: string
              resourceNames:
                type: array
                items:
                  type: string
              verbs:
                type: array
                items:
                  type: string
          example:
          - resources:
            - experiments
            - experiments/*
            resourceNames:
            - '*'
            verbs:
            - list
            - get
        roleName:
          type: string
          example: Example Role
    User:
      type: object
      required:
      - first_name
      - last_name
      - username
      properties:
        first_name:
          type: string
          example: John
        last_name:
          type: string
          example: Doe
        password:
          type: string
          example: '<encrypted password>'
          readOnly: true
        rbac:
          allOf:
          - $ref: "#/components/schemas/Role"
          readOnly: true
        username:
          type: string
          example: johndoe@example.com
    Topology:
      type: object
      required:
      - nodes
      properties:
        nodes:
          type: array
          items:
            oneOf:
            - $ref: '#/components/schemas/minimega_node'
            - $ref: '#/components/schemas/external_node'
    Scenario:
      type: object
      nullable: true
      required:
      - apps
      properties:
        apps:
          type: array
          nullable: true
          items:
            type: object
            required:
            - name
            properties:
              name:
                type: string
                example: example-app
              assetDir:
                type: string
                example: /phenix/topologies/example-topo/assets
              metadata:
                type: object
                nullable: true
                additionalProperties: true
                example:
                  setting0: true
                  setting1: 42
                  setting2: universe key
              hosts:
                type: array
                items:
                  type: object
                  required:
                  - hostname
                  properties:
                    hostname:
                      type: string
                      example: example-host
                    metadata:
                      type: object
                      nullable: true
                      additionalProperties: true
                      example:
                        setting0: true
                        setting1: 42
                        setting2: universe key
    Experiment:
      type: object
      required:
      - topology
      properties:
        topology:
          $ref: "#/components/schemas/Topology"
        scenario:
          $ref: "#/components/schemas/Scenario"
        baseDir:
          type: string
          example: /phenix/topologies/example-topo
        experimentName:
          type: string
          example: example-exp
          readOnly: true
        vlans:
          type: object
          nullable: true
          properties:
            aliases:
              type: object
              nullable: true
              additionalProperties:
                type: integer
              example:
                MGMT: 200
            min:
              type: integer
            max:
              type: integer
        schedule:
          type: object
          nullable: true
          additionalProperties:
            type: string
          example:
            ADServer: compute1
    minimega_node:
      type: object
      required:
      - type
      - general
      - hardware
      properties:
        type:
          type: string
          default: VirtualMachine
          example: VirtualMachine
        general:
          type: object
          required:
          - hostname
          properties:
            hostname:
              type: string
              example: ADServer
            description:
              type: string
              example: Active Directory Server
            vm_type:
              type: string
              enum:
              - kvm
              - container
              - ""
              default: kvm
              example: kvm
            snapshot:
              type: boolean
              default: false
              example: false
              nullable: true
            do_not_boot:
              type: boolean
              default: false
              example: false
              nullable: true
        hardware:
          type: object
          required:
          - os_type
          - drives
          properties:
            cpu:
              type: string
              default: Broadwell
              example: Broadwell
            vcpus:
              oneOf:
              - type: integer
              - type: string
              default: 1
              example: 4
            memory:
              oneOf:
              - type: integer
              - type: string
              default: 1024
              example: 8192
            os_type:
              type: string
              enum:
              - centos
              - linux
              - minirouter
              - rhel
              - vyatta
              - vyos
              - windows
              default: linux
              example: windows
            drives:
              type: array
              minItems: 1
              items:
                type: object
                required:
                - image
                properties:
                  image:
                    type: string
                    minLength: 1
                    example: ubuntu.qc2
                  interface:
                    type: string
                    enum:
                    - ahci
                    - ide
                    - scsi
                    - sd
                    - mtd
                    - floppy
                    - pflash
                    - virtio
                    - ""
                    default: ide
                    example: ide
                  cache_mode:
                    type: string
                    enum:
                    - none
                    - writeback
                    - unsafe
                    - directsync
                    - writethrough
                    - ""
                    default: writeback
                    example: writeback
                  inject_partition:
                    type: integer
                    default: 1
                    example: 2
                    nullable: true
        network:
          type: object
          nullable: true
          required:
          - interfaces
          properties:
            interfaces:
              type: array
              nullable: true
              items:
                type: object
                oneOf:
                - $ref: '#/components/schemas/static_iface'
                - $ref: '#/components/schemas/dhcp_iface'
                - $ref: '#/components/schemas/serial_iface'
            routes:
              type: array
              nullable: true
              items:
                type: object
                required:
                - destination
                - next
                properties:
                  destination:
                    type: string
                    example: 192.168.0.0/24
                  next:
                    type: string
                    example: 192.168.1.254
                  cost:
                    type: integer
                    default: 1
                    example: 1
                    nullable: true
            ospf:
              type: object
              nullable: true
              required:
              - router_id
              - areas
              properties:
                router_id:
                  type: string
                  example: 0.0.0.1
                areas:
                  type: array
                  items:
                    type: object
                    required:
                    - area_id
                    - area_networks
                    properties:
                      area_id:
                        type: integer
                        example: 1
                        default: 1
                      area_networks:
                        type: array
                        items:
                          type: object
                          required:
                          - network
                          properties:
                            network:
                              type: string
                              example: 10.1.25.0/24
            rulesets:
              type: array
              nullable: true
              items:
                type: object
                required:
                - name
                - default
                - rules
                properties:
                  name:
                    type: string
                    example: OutToDMZ
                  description:
                    type: string
                    example: From Corp to the DMZ network
                  default:
                    type: string
                    enum:
                    - accept
                    - drop
                    - reject
                    example: drop
                  rules:
                    type: array
                    items:
                      type: object
                      required:
                      - id
                      - action
                      - protocol
                      properties:
                        id:
                          type: integer
                          example: 10
                        description:
                          type: string
                          example: Allow UDP 10.1.26.80 ==> 10.2.25.0/24:123
                        action:
                          type: string
                          enum:
                          - accept
                          - drop
                          - reject
                          example: accept
                        protocol:
                          type: string
                          enum:
                          - tcp
                          - udp
                          - tcp_udp
                          - icmp
                          - esp
                          - ah
                          - all
                          default: tcp
                          example: tcp
                        source:
                          type: object
                          nullable: true
                          required:
                          - address
                          properties:
                            address:
                              type: string
                              example: 10.1.24.60
                            port:
                              type: integer
                              example: 3389
                        destination:
                          type: object
                          nullable: true
                          required:
                          - address
                          properties:
                            address:
                              type: string
                              example: 10.1.24.60
                            port:
                              type: integer
                              example: 3389
        injections:
          type: array
          nullable: true
          items:
            type: object
            required:
            - src
            - dst
            properties:
              src:
                type: string
                example: foo.xml
              dst:
                type: string
                example: /etc/phenix/foo.xml
              description:
                type: string
                example: phenix config file
              permissions:
                type: string
                example: '0664'
        delay:
          type: object
          nullable: true
          properties:
            timer:
              type: string
              example: 5m
            user:
              type: boolean
            c2:
              type: array
              nullable: true
              items:
                type: object
                properties:
                  hostname:
                    type: string
                  useUUID:
                    type: boolean
        advanced:
          type: object
          nullable: true
          additionalProperties:
            type: string
        commands:
          type: array
          nullable: true
          items:
            type: string
          example:
          - exec df -h
    external_node:
      type: object
      required:
      - external
      - type
      - general
      properties:
        external:
          type: boolean
        type:
          type: string
          default: HIL
          example: HIL
        general:
          type: object
          required:
          - hostname
          properties:
            hostname:
              type: string
              example: ADServer
            description:
              type: string
              example: Active Directory Server
            vm_type:
              type: string
              enum:
              - vm
              - container
              - ""
              default: vm
              example: vm
        hardware:
          type: object
          nullable: true
          required:
          - os_type
          properties:
            cpu:
              type: string
              default: Broadwell
              example: Broadwell
            vcpus:
              oneOf:
              - type: integer
              - type: string
              default: 1
              example: 4
            memory:
              oneOf:
              - type: integer
              - type: string
              default: 1024
              example: 8192
            os_type:
              type: string
              default: linux
              example: windows
        network:
          type: object
          nullable: true
          required:
          - interfaces
          properties:
            interfaces:
              type: array
              items:
                type: object
                required:
                - name
                properties:
                  name:
                    type: string
                    example: eth0
                  proto:
                    type: string
                    enum:
                    - static
                    - dhcp
                    - manual
                    - ""
                    default: dhcp
                    example: static
                  address:
                    type: string
                    format: ipv4
                    example: 192.168.1.100
                  mask:
                    type: integer
                    minimum: 0
                    maximum: 32
                    default: 24
                    example: 24
                  gateway:
                    type: string
                    format: ipv4
                    example: 192.168.1.1
                  vlan:
                    type: string
                    example: EXP-1
    iface:
      type: object
      required:
      - name
      - vlan
      properties:
        name:
          type: string
          example: eth0
        vlan:
          type: string
          example: EXP-1
        autostart:
          type: boolean
          default: true
        mac:
          type: string
          example: 00:11:22:33:44:55
        mtu:
          type: integer
          default: 1500
          example: 1500
        bridge:
          type: string
          default: phenix
        driver:
          type: string
          example: e1000
        qinq:
          type: boolean
          default: false
    iface_address:
      type: object
      required:
      - address
      - mask
      properties:
        address:
          type: string
          format: ipv4
          example: 192.168.1.100
        mask:
          type: integer
          minimum: 0
          maximum: 32
          default: 24
          example: 24
        gateway:
          type: string
          format: ipv4
          example: 192.168.1.1
        dns:
          nullable: true
          oneOf:
          - type: string
          - type: array
            items:
              type: string
          example:
          - 192.168.1.1
          - 192.168.1.2
    iface_rulesets:
      type: object
      properties:
        ruleset_out:
          type: string
          example: OutToInet
        ruleset_in:
          type: string
          example: InFromInet
    iface_wifi:
      type: object
      properties:
        wifi:
          type: object
          nullable: true
          properties:
            mode:
              type: string
              description: |
                Wifi mode
                - ap: Access Point (AP) mode - turns the Wifi interface into a Wifi AP
                - infrastructure: infrastructure mode - connects to an existing Wifi network
              enum:
                - ap
                - infrastructure
              example: infrastructure
            ssid:
              type: string
              minLength: 1
              maxLength: 32
              description: Wifi SSID
              example: Phenix Wifi
            hidden:
              type: boolean
              description: Hide the SSID
              example: false
            auth:
              description: Wifi authentication configuration (Heavily inspired by [netplan](https://netplan.readthedocs.io/en/latest/netplan-yaml/#authentication))
              type: object
              properties:
                mode:
                  type: string
                  description: |
                    The authentication mode to use.
                    - none: No key authentication
                    - wep: Wired Equivalent Privacy (WEP) authentication
                    - wpa-personal (WPA-PSK): Wi-Fi Protected Access (WPA) Personal authentication
                    - wpa2-personal (WPA-PSK): Wi-Fi Protected Access 2 (WPA2) Personal authentication
                    - wpa3-personal (SAE): Wi-Fi Protected Access 3 (WPA3) Personal authentication
                    - wpa-enterprise (WPA-EAP): Wi-Fi Protected Access (WPA) Enterprise authentication
                    - wpa2-enterprise (WPA-EAP): Wi-Fi Protected Access 2 (WPA2) Enterprise authentication
                    - wpa3-enterprise (WPA-EAP-SUITE-B-192): Wi-Fi Protected Access 3 (WPA3) Enterprise authentication
                  enum:
                    - none
                    - wep
                    - wpa-personal
                    - wpa2-personal
                    - wpa3-personal
                    - wpa-enterprise
                    - wpa2-enterprise
                    - wpa3-enterprise
                  example: wpa2-personal
                password:
                  type: string
                  nullable: true
                  description: The password string for EAP, or the pre-shared key for WPA-PSK. Prefix with an x to indicate a hex key.
                  example: "12345678"
                method:
                  type: string
                  nullable: true
                  description: The EAP method to use.
                  enum:
                    - leap
                    - peap
                    - tls
                    - ttls
                  example: tls
                identity:
                  type: string
                  nullable: true
                  description: The client/server identity to use for EAP.
                anonymous_identity:
                  type: string
                  nullable: true
                  description: The client identity to pass over the unencrypted channel if the chosen EAP method supports passing a different tunnelled identity. Ignored if mode is not infrastructure.
                ca_certificate:
                  type: string
                  nullable: true
                  description: Path to a file with one or more trusted certificate authority (CA) certificates.
                certificate:
                  type: string
                  nullable: true
                  description: Path to a file containing the certificate to be used by the client/server during authentication.
                key:
                  type: string
                  nullable: true
                  description: Path to a file containing the private key corresponding to client/server-certificate.
                key_password:
                  type: string
                  nullable: true
                  description: Password to use to decrypt the private key specified in key if it is encrypted.
                phase2_auth:
                  type: string
                  nullable: true
                  description: Phase 2 authentication mechanism. Ignored if mode is not infrastructure.
            position:
              type: object
              nullable: true
              description: Wifi position (in meters; relative to the origin).
              properties:
                x:
                  type: integer
                  format: int32
                  example: 0
                y:
                  type: integer
                  format: int32
                  example: 0
                z:
                  type: integer
                  format: int32
                  example: 0
              example:
                x: 3
                y: -4
                z: 5
            extra:
              type: array
              nullable: true
              items:
                type: object
                allOf:
                  - type: object
                    required:
                      - key
                    properties:
                      key:
                        type: string
                        description: Configuration item key.
                  - oneOf:
                    - type: object
                      required:
                        - value
                      properties:
                        value:
                          type: string
                          description: Configuration item literal value.
                    - type: object
                      required:
                        - file
                      properties:
                        file:
                          type: string
                          description: Configuration item file path on the host. This file will be copied to the node and the path to the copied file will be used as the value.
              description: Extra hostapd/wpa_supplicant configuration (if mode is ap/client, respectively). **This is appended to the generated configuration, so be careful not to duplicate keys.**
              example:
                # From https://github.com/Raizo62/vwifi/blob/f8f29b02f786f59f90309947d5b4b23e7d6e8cc7/tests/hostapd_wpa.conf
                - key: interface
                  value: wlan0
                - key: driver
                  value: nl80211
                - key: hw_mode
                  value: g
                - key: channel
                  value: "1"
                - key: ssid
                  value: mac80211_wpa
                - key: wpa
                  value: "2"
                - key: wpa_key_mgmt
                  value: WPA-PSK
                - key: wpa_pairwise
                  value: CCMP
                - key: wpa_passphrase
                  value: "12345678"
            ap:
              type: object
              description: AP-mode configuration. Only used if mode is ap.
              properties:
                generation:
                  type: string
                  description: |
                    Wifi generation.
                    - 1: 802.11b (2.4 GHz)
                    - 2: 802.11a (5 GHz)
                    - 3: 802.11g (2.4 GHz)
                    - 4: 802.11n (2.4/5 GHz)
                    - 5: 802.11ac (5 GHz)
                    - 6: 802.11ax (2.4/5 GHz)
                    - 6e: 802.11ax (2.4/5/6 GHz)
                    - 7: 802.11be (2.4/5/6 GHz)
                  enum:
                    - ""
                    - "1"
                    - "2"
                    - "3"
                    - "4"
                    - "5"
                    - "6"
                    - "6e"
                    - "7"
                  example: "4"
            infrastructure:
              type: object
              description: Infrastructure-mode configuration. Only used if mode is infrastructure.
              properties:
                passive:
                  type: boolean
                  description: Whether or not to passively scan for networks.
                  example: false
    static_iface:
      allOf:
      - $ref: '#/components/schemas/iface'
      - $ref: '#/components/schemas/iface_address'
      - $ref: '#/components/schemas/iface_rulesets'
      - $ref: '#/components/schemas/iface_wifi'
      required:
      - type
      - proto
      properties:
        type:
          type: string
          enum:
          - ethernet
          - wifi
          default: ethernet
          example: ethernet
        proto:
          type: string
          enum:
          - static
          - ospf
          default: static
          example: static
    dhcp_iface:
      allOf:
      - $ref: '#/components/schemas/iface'
      - $ref: '#/components/schemas/iface_rulesets'
      - $ref: '#/components/schemas/iface_wifi'
      required:
      - type
      - proto
      properties:
        type:
          type: string
          enum:
          - ethernet
          - wifi
          default: ethernet
          example: ethernet
        proto:
          type: string
          enum:
          - dhcp
          - manual
          default: dhcp
          example: dhcp
    serial_iface:
      allOf:
      - $ref: '#/components/schemas/iface'
      - $ref: '#/components/schemas/iface_address'
      - $ref: '#/components/schemas/iface_rulesets'
      required:
      - type
      - proto
      - udp_port
      - baud_rate
      - device
      properties:
        type:
          type: string
          enum:
          - serial
          default: serial
          example: serial
        proto:
          type: string
          enum:
          - static
          default: static
          example: static
        udp_port:
          type: integer
          minimum: 0
          maximum: 65535
          default: 8989
          example: 8989
        baud_rate:
          type: integer
          enum:
          - 110
          - 300
          - 600
          - 1200
          - 2400
          - 4800
          - 9600
          - 14400
          - 19200
          - 38400
          - 57600
          - 115200
          - 128000
          - 256000
          default: 9600
          example: 9600
        device:
          type: string
          default: /dev/ttyS0
          example: /dev/ttyS0
`)
