package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

func promptUser(reader *bufio.Reader, message string, defaultValue string) string {
	if defaultValue != "" {
		fmt.Printf("%s [%s]: ", message, defaultValue)
	} else {
		fmt.Print(message + ": ")
	}
	input, _ := reader.ReadString('\n')
	input = strings.TrimSpace(input)
	if input == "" && defaultValue != "" {
		return defaultValue
	}
	return input
}

func getDefaultOutputDir() string {
	if runtime.GOOS == "windows" {
		return "."
	}
	// On Linux, if running as root and /etc/wireguard exists, suggest it
	if os.Geteuid() == 0 {
		if fi, err := os.Stat("/etc/wireguard"); err == nil && fi.IsDir() {
			return "/etc/wireguard"
		}
	}
	return "."
}

func main() {
	var (
		flagLink   string
		flagName   string
		flagOutDir string
		flagYes    bool
		flagStdout bool
	)

	flag.StringVar(&flagLink, "link", "", "WireGuard link (wireguard://... or wg://...)")
	flag.StringVar(&flagLink, "l", "", "WireGuard link (shorthand)")
	flag.StringVar(&flagName, "name", "", "Configuration name (without .conf)")
	flag.StringVar(&flagName, "n", "", "Configuration name (shorthand)")
	flag.StringVar(&flagOutDir, "output", "", "Output directory (default: current directory)")
	flag.StringVar(&flagOutDir, "o", "", "Output directory (shorthand)")
	flag.BoolVar(&flagYes, "yes", false, "Overwrite existing file without confirmation")
	flag.BoolVar(&flagYes, "y", false, "Overwrite existing file (shorthand)")
	flag.BoolVar(&flagStdout, "stdout", false, "Print configuration to stdout instead of saving to file")

	flag.Parse()

	reader := bufio.NewReader(os.Stdin)
	isInteractive := flagLink == ""

	// Ensure console doesn't close immediately on Windows interactive exit
	defer func() {
		if isInteractive && runtime.GOOS == "windows" {
			fmt.Print("\nPress Enter to exit...")
			_, _ = reader.ReadString('\n')
		}
	}()

	rawLink := flagLink
	configName := flagName
	outputDir := flagOutDir

	if isInteractive {
		fmt.Println("============================================")
		fmt.Println("        Wireguard link to Config            ")
		fmt.Println("============================================")
		fmt.Println()

		for {
			rawLink = promptUser(reader, "Enter WireGuard link", "")
			if rawLink != "" {
				break
			}
			fmt.Println("Error: Link cannot be empty. Please try again.")
		}
	}

	// Parse the link
	cfg, err := ParseWireGuardLink(rawLink)
	if err != nil {
		fmt.Fprintf(os.Stderr, "\nError parsing WireGuard link: %v\n", err)
		os.Exit(1)
	}

	// Determine config name
	if configName == "" {
		if isInteractive {
			defaultName := cfg.Name
			if defaultName == "" {
				defaultName = "wg0"
			}
			inputName := promptUser(reader, "Enter configuration name", defaultName)
			configName = inputName
		} else {
			if cfg.Name != "" {
				configName = cfg.Name
			} else {
				configName = "wg0"
			}
		}
	}

	sanitizedName, err := SanitizeConfigName(configName)
	if err != nil {
		fmt.Fprintf(os.Stderr, "\nError: %v\n", err)
		os.Exit(1)
	}
	cfg.Name = sanitizedName

	// If stdout was requested, print and exit
	if flagStdout {
		fmt.Print(cfg.ToConf())
		return
	}

	// Determine output directory
	if outputDir == "" {
		defaultDir := getDefaultOutputDir()
		if isInteractive {
			outputDir = promptUser(reader, "Enter output directory", defaultDir)
		} else {
			outputDir = defaultDir
		}
	}

	// Expand directory path
	absOutputDir, err := filepath.Abs(outputDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "\nError resolving directory path: %v\n", err)
		os.Exit(1)
	}

	targetFilePath := filepath.Join(absOutputDir, cfg.Name+".conf")

	// Check if file exists
	if _, err := os.Stat(targetFilePath); err == nil {
		if !flagYes {
			if isInteractive {
				ans := promptUser(reader, fmt.Sprintf("File '%s' already exists. Overwrite? [y/N]", targetFilePath), "n")
				ans = strings.ToLower(ans)
				if ans != "y" && ans != "yes" {
					fmt.Println("Operation cancelled.")
					return
				}
			} else {
				fmt.Fprintf(os.Stderr, "Error: File '%s' already exists. Use -y or --yes to overwrite.\n", targetFilePath)
				os.Exit(1)
			}
		}
	}

	// Ensure directory exists
	if err := os.MkdirAll(absOutputDir, 0755); err != nil {
		fmt.Fprintf(os.Stderr, "\nError creating directory '%s': %v\n", absOutputDir, err)
		os.Exit(1)
	}

	// Write file
	confContent := cfg.ToConf()
	err = os.WriteFile(targetFilePath, []byte(confContent), 0600)
	if err != nil {
		fmt.Fprintf(os.Stderr, "\nError writing file '%s': %v\n", targetFilePath, err)
		os.Exit(1)
	}

	// Chmod explicitly on POSIX systems (0600 ensures only current user can read private key)
	if runtime.GOOS != "windows" {
		_ = os.Chmod(targetFilePath, 0600)
	}

	fmt.Println("\n[✔] Success: WireGuard configuration generated successfully!")
	fmt.Printf("Config Name : %s\n", cfg.Name)
	fmt.Printf("File Path   : %s\n", targetFilePath)
	if cfg.MTU != "" {
		fmt.Printf("MTU         : %s\n", cfg.MTU)
	}
	if cfg.PersistentKeepalive != "" {
		fmt.Printf("Keepalive   : %s seconds\n", cfg.PersistentKeepalive)
	}
	if runtime.GOOS != "windows" {
		fmt.Println("Permissions : 600 (Private)")
	}
}
