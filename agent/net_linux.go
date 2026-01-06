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

// For Linux: Fix name to tun0
func getWaterConfig() water.Config {
	return water.Config{
		DeviceType: water.TUN,
		PlatformSpecificParams: water.PlatformSpecificParams{
			Name: "tun0",
		},
	}
}

// For Linux: ip addr, ip link
func configureInterface(devName, clientIP, gatewayIP string, mtu int) error {
	// Flush existing addresses to allow reconfiguration after reconnect
	flushCmd := exec.Command("ip", "addr", "flush", "dev", devName)
	flushCmd.Run() // Ignore errors - interface might not have addresses yet

	// Point-to-Point configuration: ip addr add 10.100.0.2 peer 10.100.0.1 dev tun0
	cmd1 := exec.Command("ip", "addr", "add", clientIP, "peer", gatewayIP, "dev", devName)
	if out, err := cmd1.CombinedOutput(); err != nil {
		return fmt.Errorf("ip addr failed: %v %s", err, out)
	}

	// Set MTU and bring UP
	cmd2 := exec.Command("ip", "link", "set", "dev", devName, "mtu", fmt.Sprintf("%d", mtu), "up")
	if out, err := cmd2.CombinedOutput(); err != nil {
		return fmt.Errorf("ip link failed: %v %s", err, out)
	}
	return nil
}

// For Linux: ip route
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

// For Linux cleanup (not necessary for containers as they are destroyed on exit, but implemented anyway)
func setupCleanup(cidr, gateway, devName string) {
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-c
		fmt.Println("\nCleaning up...")
		// Routes are deleted when container is destroyed, so no action needed or explicit cleanup
		os.Exit(0)
	}()
}
