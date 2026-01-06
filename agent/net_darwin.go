//go:build darwin

package main

import (
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"syscall"

	"github.com/songgao/water"
)

// For macOS: Let OS determine device name
func getWaterConfig() water.Config {
	return water.Config{
		DeviceType: water.TUN,
	}
}

// For macOS: ifconfig
func configureInterface(devName, clientIP, gatewayIP string, mtu int) error {
	cmd := exec.Command("ifconfig", devName, clientIP, gatewayIP, "mtu", fmt.Sprintf("%d", mtu), "up")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%v: %s", err, output)
	}
	return nil
}

// For macOS: route add
func addRoute(cidr, gateway, devName string) error {
	// On macOS, Gateway specification is more common than device specification
	cmd := exec.Command("route", "-n", "add", "-net", cidr, gateway)
	return cmd.Run()
}

// Cleanup
func setupCleanup(cidr, gateway, devName string) {
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-c
		fmt.Println("\nCleaning up...")
		exec.Command("route", "-n", "delete", "-net", cidr, gateway).Run()
		os.Exit(0)
	}()
}
