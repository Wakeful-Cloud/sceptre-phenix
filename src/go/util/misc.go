package util

import (
	"fmt"
	"math/rand"
	"time"

	"github.com/google/gopacket/macs"
)

var validMACPrefix [][3]byte

func init() {
	for k := range macs.ValidMACPrefixMap {
		validMACPrefix = append(validMACPrefix, k)
	}
}

func RandomMac() string {
	r := rand.New(rand.NewSource(time.Now().UnixNano()))

	prefix := validMACPrefix[r.Intn(len(validMACPrefix))]

	mac := fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", prefix[0], prefix[1], prefix[2], r.Intn(256), r.Intn(256), r.Intn(256))

	return mac
}
