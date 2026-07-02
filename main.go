package main

import (
	"fmt"
	"os"
	"strings"

	"cidr-cli/internal/cidr"
)

func main() {
	if len(os.Args) < 2 {
		printTable()
		return
	}

	switch os.Args[1] {
	case "contains", "c":
		containsCmd(os.Args[2:])
	case "info", "i":
		infoCmd(os.Args[2:])
	case "help", "-h", "--help":
		printHelp()
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n\n", os.Args[1])
		printHelp()
		os.Exit(1)
	}
}

func printTable() {
	rows := cidr.GenerateTable()
	fmt.Println("CIDR Reference Table")
	fmt.Println(strings.Repeat("-", 72))
	fmt.Printf("%-6s %-20s %-18s %-18s %s\n", "Prefix", "IPs", "Netmask", "Wildcard", "Class")
	fmt.Println(strings.Repeat("-", 72))
	for _, r := range rows {
		class := r.Class
		if class == "" {
			class = "-"
		}
		fmt.Printf("/%-5d %-20s %-18s %-18s %s\n",
			r.Prefix,
			cidr.FormatCount(r.IPCount),
			r.Netmask,
			r.Wildcard,
			class,
		)
	}
	fmt.Println(strings.Repeat("-", 72))
	fmt.Printf("%-6s %-20s %-18s %-18s %s\n", "Prefix", "IPs", "Netmask", "Wildcard", "Class")
}

func containsCmd(args []string) {
	if len(args) < 2 {
		fmt.Fprintf(os.Stderr, "Usage: cidr contains <ip> <cidr>\n")
		os.Exit(1)
	}
	ipStr := args[0]
	cidrStr := args[1]

	found, err := cidr.Contains(ipStr, cidrStr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	if found {
		fmt.Printf("%s is within %s\n", ipStr, cidrStr)
	} else {
		fmt.Printf("%s is NOT within %s\n", ipStr, cidrStr)
	}
}

func infoCmd(args []string) {
	if len(args) < 1 {
		fmt.Fprintf(os.Stderr, "Usage: cidr info <cidr>\n")
		os.Exit(1)
	}
	cidrStr := args[0]

	info, err := cidr.NetworkInfo(cidrStr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("CIDR Block Information")
	fmt.Println(strings.Repeat("-", 48))
	fmt.Printf("  CIDR:           %s\n", info.CIDR)
	fmt.Printf("  Network:        %s\n", info.Network)
	fmt.Printf("  Netmask:        %s\n", info.Netmask)
	fmt.Printf("  Wildcard:       %s\n", info.Wildcard)
	fmt.Printf("  Prefix Length:  /%d\n", info.PrefixLength)
	fmt.Printf("  Total Hosts:    %s\n", cidr.FormatCount(info.TotalHosts))
	fmt.Printf("  Usable Hosts:   %s\n", cidr.FormatCount(info.UsableHosts))
	fmt.Printf("  First Host:     %s\n", info.FirstHost)
	fmt.Printf("  Last Host:      %s\n", info.LastHost)
	fmt.Printf("  Broadcast:      %s\n", info.Broadcast)
	fmt.Printf("  Legacy Class:   %s\n", info.Class)
}

func printHelp() {
	fmt.Println("Usage: cidr [command] [arguments]")
	fmt.Println()
	fmt.Println("Commands:")
	fmt.Println("  (no arguments)   Show CIDR prefix reference table (/0–/32)")
	fmt.Println("  contains <ip> <cidr>   Check if an IP is within a CIDR range")
	fmt.Println("  info <cidr>      Show detailed information about a CIDR block")
	fmt.Println("  help             Show this help message")
	fmt.Println()
	fmt.Println("Examples:")
	fmt.Println("  cidr")
	fmt.Println("  cidr contains 192.168.1.100 192.168.1.0/24")
	fmt.Println("  cidr info 10.0.0.0/8")
}
