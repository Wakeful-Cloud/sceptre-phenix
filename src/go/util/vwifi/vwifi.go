// Copyright 2024 Colorado School of Mines CSCI 370 FA24 NREL 2 Group

package vwifi

import (
	"fmt"
	"path/filepath"
	"phenix/tmpl"
	ifaces "phenix/types/interfaces"
)

// FileToInject represents a file that needs to be injected into the guest
type FileToInject struct {
	// Src is the path to the file on the host
	Src string

	// Dst is the path to the file on the guest
	Dst string

	// Description is a human-readable description of the file
	Description string

	// Permissions is the permissions that the file should have on the guest
	Permissions string
}

// FileInjectionMode represents the mode with which file injections are computed
type FileInjectionMode string

const (
	// FileInjectionModeRegular represents the regular file injection mode
	FileInjectionModeRegular FileInjectionMode = "regular"

	// FileInjectionModeVyatta represents the Vyatta/VyOS file injection mode
	FileInjectionModeVyatta FileInjectionMode = "vyatta"
)

// GetFilesToInject returns a list of files that need to be injected into the guest
func GetFilesToInject(hostDirectory string, nodeName string, node ifaces.NodeSpec, mode FileInjectionMode) ([]FileToInject, error) {
	files := []FileToInject{}

	switch mode {
	case FileInjectionModeVyatta:
		// Add the interfaces file
		interfacesFile := filepath.Join(hostDirectory, fmt.Sprintf("%s-interfaces", nodeName))

		files = append(files, FileToInject{
			Src:         interfacesFile,
			Dst:         "/etc/phenix/startup/4_vyatta_interfaces-start.sh",
			Description: "Vyatta/VyOS interfaces configuration",
			Permissions: "0644",
		})

		if err := tmpl.CreateFileFromTemplate("vyatta_interfaces.tmpl", node, interfacesFile); err != nil {
			return nil, fmt.Errorf("generating interfaces: %w", err)
		}
	}

	for _, iface := range node.Network().Interfaces() {
		if iface.Type() != ifaces.NodeNetworkInterfaceTypeWifi {
			continue
		}

		filesPrefix := "/etc"

		switch iface.Wifi().Mode() {
		case ifaces.NodeNetworkInterfaceWifiModeAp:
			// Update the files prefix
			filesPrefix = filepath.Join(filesPrefix, "hostapd")

			// Add the hostapd file
			hostapdFile := filepath.Join(hostDirectory, fmt.Sprintf("%s-hostapd-%s.conf", nodeName, iface.Name()))

			files = append(files, FileToInject{
				Src:         hostapdFile,
				Dst:         filepath.Join(filesPrefix, fmt.Sprintf("%s.conf", iface.Name())),
				Description: fmt.Sprintf("hostapd configuration for %s", iface.Name()),
				Permissions: "0644",
			})

			if err := tmpl.CreateFileFromTemplate("linux_hostapd.tmpl", iface, hostapdFile); err != nil {
				return nil, fmt.Errorf("generating hostapd %s.conf: %w", iface.Name(), err)
			}

			// Add the eap_user file
			switch iface.Wifi().Auth().Mode() {
			case ifaces.NodeNetworkInterfaceWifiAuthModeWpaEnterprise, ifaces.NodeNetworkInterfaceWifiAuthModeWpa2Enterprise, ifaces.NodeNetworkInterfaceWifiAuthModeWpa3Enterprise:
				eapUserFile := filepath.Join(hostDirectory, fmt.Sprintf("%s-eap_user-%s", nodeName, iface.Name()))

				files = append(files, FileToInject{
					Src:         eapUserFile,
					Dst:         filepath.Join(filesPrefix, fmt.Sprintf("%s-eap_user", iface.Name())),
					Description: fmt.Sprintf("eap_user configuration for %s", iface.Name()),
					Permissions: "0644",
				})

				if err := tmpl.CreateFileFromTemplate("linux_eap_user.tmpl", iface, eapUserFile); err != nil {
					return nil, fmt.Errorf("generating eap_user %s: %w", iface.Name(), err)
				}
			}

		case ifaces.NodeNetworkInterfaceWifiModeInfrastructure:
			// Update the files prefix
			filesPrefix = filepath.Join(filesPrefix, "wpa_supplicant")

			// Add the wpa_supplicant file
			wpaSupplicantFile := filepath.Join(hostDirectory, fmt.Sprintf("%s-wpa_supplicant-%s.conf", nodeName, iface.Name()))

			files = append(files, FileToInject{
				Src:         wpaSupplicantFile,
				Dst:         filepath.Join(filesPrefix, fmt.Sprintf("wpa_supplicant-%s.conf", iface.Name())),
				Description: fmt.Sprintf("wpa_supplicant configuration for %s", iface.Name()),
				Permissions: "0644",
			})

			if err := tmpl.CreateFileFromTemplate("linux_wpa_supplicant.tmpl", iface, wpaSupplicantFile); err != nil {
				return nil, fmt.Errorf("generating wpa_supplicant-%s.conf: %w", iface.Name(), err)
			}
		}

		// Add EAP files
		if iface.Wifi().Auth().CaCertificate() != "" {
			files = append(files, FileToInject{
				Src:         iface.Wifi().Auth().CaCertificate(),
				Dst:         filepath.Join(filesPrefix, fmt.Sprintf("%s-ca.cert", iface.Name())),
				Description: fmt.Sprintf("CA certificate for %s", iface.Name()),
				Permissions: "0644",
			})
		}

		if iface.Wifi().Auth().Certificate() != "" {
			files = append(files, FileToInject{
				Src:         iface.Wifi().Auth().Certificate(),
				Dst:         filepath.Join(filesPrefix, fmt.Sprintf("%s-cert.cert", iface.Name())),
				Description: fmt.Sprintf("Certificate for %s", iface.Name()),
				Permissions: "0644",
			})
		}

		if iface.Wifi().Auth().Key() != "" {
			files = append(files, FileToInject{
				Src:         iface.Wifi().Auth().Key(),
				Dst:         filepath.Join(filesPrefix, fmt.Sprintf("%s-key.key", iface.Name())),
				Description: fmt.Sprintf("Key for %s", iface.Name()),
				Permissions: "0600",
			})
		}

		// Add extra files
		for index, extraItem := range iface.Wifi().Extra() {
			// Skip if no file is provided
			if extraItem.File() == "" {
				continue
			}

			files = append(files, FileToInject{
				Src:         extraItem.File(),
				Dst:         filepath.Join(filesPrefix, fmt.Sprintf("%s-extra-%d", iface.Name(), index)),
				Description: fmt.Sprintf("Extra file %d for %s", index, iface.Name()),
				Permissions: "0644",
			})
		}
	}

	return files, nil
}
