//go:build linux

package main

import (
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"syscall"

	"github.com/songgao/water"
)

// Linux用: 名前を tun0 に固定
func getWaterConfig() water.Config {
	return water.Config{
		DeviceType: water.TUN,
		PlatformSpecificParams: water.PlatformSpecificParams{
			Name: "tun0",
		},
	}
}

// Linux用: ip addr, ip link
func configureInterface(devName, clientIP, gatewayIP string, mtu int) error {
	// Flush existing addresses to allow reconfiguration after reconnect
	flushCmd := exec.Command("ip", "addr", "flush", "dev", devName)
	flushCmd.Run() // Ignore errors - interface might not have addresses yet

	// Point-to-Point 設定: ip addr add 10.100.0.2 peer 10.100.0.1 dev tun0
	cmd1 := exec.Command("ip", "addr", "add", clientIP, "peer", gatewayIP, "dev", devName)
	if out, err := cmd1.CombinedOutput(); err != nil {
		return fmt.Errorf("ip addr failed: %v %s", err, out)
	}

	// MTU設定とUP
	cmd2 := exec.Command("ip", "link", "set", "dev", devName, "mtu", fmt.Sprintf("%d", mtu), "up")
	if out, err := cmd2.CombinedOutput(); err != nil {
		return fmt.Errorf("ip link failed: %v %s", err, out)
	}
	return nil
}

// Linux用: ip route
func addRoute(cidr, gateway, devName string) error {
	// ip route add 8.8.8.8/32 via 10.100.0.1
	cmd := exec.Command("ip", "route", "add", cidr, "via", gateway)
	if err := cmd.Run(); err != nil {
		// EEXIST error (route already exists) is not a problem
		// We can safely ignore this error on reconnect
		return nil
	}
	return nil
}

// Linux用クリーンアップ (コンテナなら終了時に消えるので本来不要だが実装しておく)
func setupCleanup(cidr, gateway, devName string) {
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-c
		fmt.Println("\nCleaning up...")
		// ルート削除等はコンテナ破棄で消えるので特に何もしないか、明示的に消す
		os.Exit(0)
	}()
}
