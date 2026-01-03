//go:build darwin

package internal

import (
	"fmt"
	"os/exec"

	"github.com/songgao/water"
)

func GetWaterConfig() water.Config {
	return water.Config{DeviceType: water.TUN}
}

func ConfigureInterface(devName, ipStr string, mtu int) error {
	// macOS P-t-P style
	cmd := exec.Command("ifconfig", devName, ipStr, "10.100.0.2", "mtu", fmt.Sprintf("%d", mtu), "up")
	return cmd.Run()
}
