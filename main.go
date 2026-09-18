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

// Version can be set at build time via -ldflags="-X main.Version=x.y.z"
var Version = "1.0.0"

// saveConfigFile writes the configuration to disk with chosen permissions.
func saveConfigFile(targetFilePath string, confContent string, chmod600 bool, overwrite bool, reader *bufio.Reader, isInteractive bool) (bool, error) {
	if _, err := os.Stat(targetFilePath); err == nil {
		if !overwrite {
			if isInteractive {
				ans := promptUser(reader, fmt.Sprintf("File '%s' already exists. Overwrite? [y/N]", filepath.Base(targetFilePath)), "n")
				ans = strings.ToLower(ans)
				if ans != "y" && ans != "yes" {
					fmt.Printf("Skipped '%s'.\n", filepath.Base(targetFilePath))
					return false, nil
				}
			} else {
				return false, fmt.Errorf("file '%s' already exists. Use -y or --yes to overwrite", targetFilePath)
			}
		}
	}

	fileMode := os.FileMode(0644)
	if chmod600 {
		fileMode = os.FileMode(0600)
	}

	err := os.WriteFile(targetFilePath, []byte(confContent), fileMode)
	if err != nil {
		return false, fmt.Errorf("error writing file '%s': %w", targetFilePath, err)
	}

	if runtime.GOOS != "windows" && chmod600 {
		_ = os.Chmod(targetFilePath, 0600)
	}

	return true, nil
}

func main() {
	var (
		flagLink     string
		flagFile     string
		flagName     string
		flagOutDir   string
		flagYes      bool
		flagStdout   bool
		flagChmod600 bool
		flagVersion  bool
	)

	flag.StringVar(&flagLink, "link", "", "WireGuard link (wireguard://... or wg://...)")
	flag.StringVar(&flagLink, "l", "", "WireGuard link (shorthand)")
	flag.StringVar(&flagFile, "file", "", "Path to file containing WireGuard link(s)")
	flag.StringVar(&flagFile, "f", "", "Path to file containing WireGuard link(s) (shorthand)")
	flag.StringVar(&flagName, "name", "", "Configuration name (without .conf, for single link)")
	flag.StringVar(&flagName, "n", "", "Configuration name (shorthand)")
	flag.StringVar(&flagOutDir, "output", "", "Output directory (default: current directory)")
	flag.StringVar(&flagOutDir, "o", "", "Output directory (shorthand)")
	flag.BoolVar(&flagYes, "yes", false, "Overwrite existing files without confirmation")
	flag.BoolVar(&flagYes, "y", false, "Overwrite existing files (shorthand)")
	flag.BoolVar(&flagStdout, "stdout", false, "Print configuration to stdout instead of saving to file")
	flag.BoolVar(&flagChmod600, "chmod-600", false, "Set restrictive file permissions (chmod 600)")
	flag.BoolVar(&flagChmod600, "p", false, "Set restrictive file permissions (chmod 600, shorthand)")
	flag.BoolVar(&flagVersion, "version", false, "Show version information")
	flag.BoolVar(&flagVersion, "v", false, "Show version information (shorthand)")

	flag.Parse()

	if flagVersion {
		fmt.Printf("Wireguard link to Config v%s\n", Version)
		return
	}

	reader := bufio.NewReader(os.Stdin)
	isInteractive := (flagLink == "" && flagFile == "")

	// Ensure console doesn't close immediately on Windows interactive exit
	defer func() {
		if isInteractive && runtime.GOOS == "windows" {
			fmt.Print("\nPress Enter to exit...")
			_, _ = reader.ReadString('\n')
		}
	}()

	var configs []*Config
	var isBatch bool

	if isInteractive {
		fmt.Println("============================================")
		fmt.Printf("      Wireguard link to Config v%s\n", Version)
		fmt.Println("============================================")
		fmt.Println()

		var rawInput string
		for {
			rawInput = promptUser(reader, "Enter WireGuard link or file path (.txt)", "")
			if rawInput != "" {
				break
			}
			fmt.Println("Error: Input cannot be empty. Please try again.")
		}

		// Check if input is a local file
		if fi, err := os.Stat(rawInput); err == nil && !fi.IsDir() {
			content, err := os.ReadFile(rawInput)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error reading file '%s': %v\n", rawInput, err)
				os.Exit(1)
			}
			cfgs, errs := ParseBatchLinks(string(content))
			if len(errs) > 0 {
				for _, e := range errs {
					fmt.Fprintf(os.Stderr, "Warning: %v\n", e)
				}
			}
			if len(cfgs) == 0 {
				fmt.Fprintln(os.Stderr, "Error: No valid WireGuard links found in file.")
				os.Exit(1)
			}
			configs = cfgs
			isBatch = true
			fmt.Printf("Loaded %d link(s) from file '%s'.\n", len(configs), rawInput)
		} else {
			// Single link
			cfg, err := ParseWireGuardLink(rawInput)
			if err != nil {
				fmt.Fprintf(os.Stderr, "\nError parsing WireGuard link: %v\n", err)
				os.Exit(1)
			}
			configs = []*Config{cfg}
			isBatch = false
		}
	} else if flagFile != "" {
		content, err := os.ReadFile(flagFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading file '%s': %v\n", flagFile, err)
			os.Exit(1)
		}
		cfgs, errs := ParseBatchLinks(string(content))
		if len(errs) > 0 {
			for _, e := range errs {
				fmt.Fprintf(os.Stderr, "Warning: %v\n", e)
			}
		}
		if len(cfgs) == 0 {
			fmt.Fprintln(os.Stderr, "Error: No valid WireGuard links found in file.")
			os.Exit(1)
		}
		configs = cfgs
		isBatch = len(configs) > 1
	} else {
		// Single link from CLI flag
		cfg, err := ParseWireGuardLink(flagLink)
		if err != nil {
			fmt.Fprintf(os.Stderr, "\nError parsing WireGuard link: %v\n", err)
			os.Exit(1)
		}
		configs = []*Config{cfg}
		isBatch = false
	}

	// If stdout is requested
	if flagStdout {
		for i, cfg := range configs {
			if len(configs) > 1 {
				name := cfg.Name
				if name == "" {
					name = fmt.Sprintf("wg%d", i)
				}
				fmt.Printf("# Configuration: %s.conf\n", name)
			}
			fmt.Print(cfg.ToConf())
			if i < len(configs)-1 {
				fmt.Println("---")
			}
		}
		return
	}

	// Single link custom name prompt
	if !isBatch && len(configs) == 1 {
		if flagName == "" {
			if isInteractive {
				defaultName := configs[0].Name
				if defaultName == "" {
					defaultName = "wg0"
				}
				configs[0].Name = promptUser(reader, "Enter configuration name", defaultName)
			} else {
				if configs[0].Name == "" {
					configs[0].Name = "wg0"
				}
			}
		} else {
			configs[0].Name = flagName
		}
	}

	// Output directory
	outputDir := flagOutDir
	if outputDir == "" {
		defaultDir := getDefaultOutputDir()
		if isInteractive {
			outputDir = promptUser(reader, "Enter output directory", defaultDir)
		} else {
			outputDir = defaultDir
		}
	}

	absOutputDir, err := filepath.Abs(outputDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "\nError resolving directory path: %v\n", err)
		os.Exit(1)
	}

	if err := os.MkdirAll(absOutputDir, 0755); err != nil {
		fmt.Fprintf(os.Stderr, "\nError creating directory '%s': %v\n", absOutputDir, err)
		os.Exit(1)
	}

	// Permission question in interactive mode (POSIX only)
	applyChmod600 := flagChmod600
	if isInteractive && runtime.GOOS != "windows" {
		ans := promptUser(reader, "Set restrictive file permissions (chmod 600 - private key protected)? [y/N]", "n")
		ans = strings.ToLower(ans)
		applyChmod600 = (ans == "y" || ans == "yes")
	}

	usedNames := make(map[string]int)
	successCount := 0

	fmt.Println()
	for i, cfg := range configs {
		rawName := cfg.Name
		if rawName == "" {
			rawName = fmt.Sprintf("wg%d", i)
		}

		sanitizedName, err := SanitizeConfigName(rawName)
		if err != nil {
			sanitizedName = fmt.Sprintf("wg%d", i)
		}

		// Handle duplicate names in batch mode
		finalName := sanitizedName
		if count, exists := usedNames[sanitizedName]; exists {
			usedNames[sanitizedName] = count + 1
			finalName = fmt.Sprintf("%s_%d", sanitizedName, count+1)
		} else {
			usedNames[sanitizedName] = 0
		}

		targetFilePath := filepath.Join(absOutputDir, finalName+".conf")
		saved, err := saveConfigFile(targetFilePath, cfg.ToConf(), applyChmod600, flagYes, reader, isInteractive)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[✘] Error saving '%s': %v\n", finalName, err)
			continue
		}
		if saved {
			successCount++
			if isBatch || len(configs) > 1 {
				fmt.Printf("[✔] Saved: %s.conf -> %s\n", finalName, targetFilePath)
			} else {
				fmt.Println("[✔] Success: WireGuard configuration generated successfully!")
				fmt.Printf("Config Name : %s\n", finalName)
				fmt.Printf("File Path   : %s\n", targetFilePath)
				if cfg.MTU != "" {
					fmt.Printf("MTU         : %s\n", cfg.MTU)
				}
				if runtime.GOOS != "windows" {
					if applyChmod600 {
						fmt.Println("Permissions : 600 (Private)")
					} else {
						fmt.Println("Permissions : Default (Standard)")
					}
				}
			}
		}
	}

	if isBatch || len(configs) > 1 {
		fmt.Printf("\n[✔] Batch conversion complete: %d of %d configuration(s) saved in '%s'\n", successCount, len(configs), absOutputDir)
		if runtime.GOOS != "windows" {
			if applyChmod600 {
				fmt.Println("Permissions : 600 (Private)")
			} else {
				fmt.Println("Permissions : Default (Standard)")
			}
		}
	}
}
