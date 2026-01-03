//go:build linux

package internal

import (
	"fmt"
	"os/exec"

	"github.com/songgao/water"
)

func GetWaterConfig() water.Config {
	return water.Config{
		DeviceType: water.TUN,
		PlatformSpecificParams: water.PlatformSpecificParams{
			Name: "tun0", // 固定
		},
	}
}

func ConfigureInterface(devName, ipStr string, mtu int) error {
	// ip addr add 10.100.0.1/24 dev tun0
	cmd1 := exec.Command("ip", "addr", "add", ipStr+"/24", "dev", devName)
	if err := cmd1.Run(); err != nil {
		return fmt.Errorf("ip addr error: %v", err)
	}

	// ip link set dev tun0 mtu 1300 up
	cmd2 := exec.Command("ip", "link", "set", "dev", devName, "mtu", fmt.Sprintf("%d", mtu), "up")
	return cmd2.Run()
}
