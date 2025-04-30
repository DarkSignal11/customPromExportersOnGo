package main

import (
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/joho/godotenv"
)

func initLogger() {
	execDir, err := os.Getwd()
	if err != nil {
		log.Fatalf("Unable to determine working directory: %v", err)
	}
	logDir := filepath.Join(execDir, "logs")
	_ = os.MkdirAll(logDir, 0755)
	logPath := filepath.Join(logDir, "keystore_monitor.log")
	logFile, err := os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatalf("Unable to open log file: %v", err)
	}
	log.SetOutput(io.MultiWriter(os.Stdout, logFile))
	log.Println("Logger initialized")
}

func loadAllEnvFiles() ([]string, error) {
	execDir, err := os.Getwd()
	if err != nil {
		return nil, fmt.Errorf("Unable to determine working directory: %v", err)
	}
	configDir := filepath.Join(execDir, "config")
	entries, err := os.ReadDir(configDir)
	if err != nil {
		return nil, fmt.Errorf("Unable to read config directory: %v", err)
	}

	var envFiles []string
	for _, entry := range entries {
		if strings.HasSuffix(entry.Name(), ".env") {
			envFiles = append(envFiles, filepath.Join(configDir, entry.Name()))
		}
	}
	sort.Strings(envFiles)
	return envFiles, nil
}

func extractAliases(keystore, password string) ([]string, error) {
	path, err := exec.LookPath("keytool")
	if err != nil {
		log.Println("keytool not found in PATH. Please install Java or set PATH manually.")
		log.Println("You can install it with: sudo apt install openjdk-11-jre-headless")
		log.Println("Or: sudo yum install java-11-openjdk")
		return nil, fmt.Errorf("keytool not found in PATH — Java runtime is required")
	}
	log.Printf("Using keytool at: %s", path)

	cmd := exec.Command("keytool", "-list", "-keystore", keystore, "-storetype", "JCEKS", "-storepass", password)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("failed to list aliases: %v", err)
	}

	aliasRegex := regexp.MustCompile(`Alias name: (\S+)`)
	matches := aliasRegex.FindAllStringSubmatch(string(output), -1)
	var aliases []string

	for _, match := range matches {
		aliases = append(aliases, match[1])
	}

	if len(aliases) == 0 {
		log.Printf("Alias pattern 'Alias name:' not found, trying fallback JCEKS alias parser")
		fallback := regexp.MustCompile(`(?m)^(\S+), \w+ \d{1,2}, \d{4}, (PrivateKeyEntry|trustedCertEntry),`)
		lines := strings.Split(string(output), "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if m := fallback.FindStringSubmatch(line); len(m) == 3 {
				aliases = append(aliases, m[1])
			}
		}
	}

	return aliases, nil
}

func extractCertExpiry(alias, keystore, password string) (int, error) {
	cmd := exec.Command("keytool", "-list", "-v", "-keystore", keystore, "-storetype", "JCEKS", "-storepass", password, "-alias", alias)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return -1, fmt.Errorf("failed to execute keytool: %v", err)
	}

	expiryRegex := regexp.MustCompile(`(?m)until: (.*)`)
	matches := expiryRegex.FindStringSubmatch(string(output))
	if len(matches) < 2 {
		log.Printf("Alias \"%s\" has no expiration date or unparsable format — setting metric value to -1", alias)
		return -9999, nil
	}

	layout := "Mon Jan 2 15:04:05 MST 2006"
	expiryDate, err := time.Parse(layout, matches[1])
	if err != nil {
		return -1, fmt.Errorf("failed to parse expiry date: %v", err)
	}

	daysRemaining := int(expiryDate.Sub(time.Now()).Hours() / 24)
	return daysRemaining, nil
}

func generateMetrics() string {
	serverName := os.Getenv("SERVER_NAME")
	if serverName != "" {
		log.Printf("Server name: %s", serverName)
	}
	keystore := os.Getenv("KEYSTORE_PATH")
	password := os.Getenv("KEYSTORE_PASS")
	metricName := os.Getenv("METRIC_NAME")

	log.Printf("Generating metrics for keystore: %s, metric: %s", keystore, metricName)

	aliases, err := extractAliases(keystore, password)
	if err != nil {
		log.Printf("Error extracting aliases: %v", err)
		return ""
	}

	var minDays int = 99999
	var builder strings.Builder

	for _, alias := range aliases {
		days, err := extractCertExpiry(alias, keystore, password)
		if err != nil {
			log.Printf("Error checking alias %s: %v", alias, err)
			continue
		}
		if days >= 0 && days < minDays {
			minDays = days
		}

		status := "valid"
		expiryLabel := time.Now().AddDate(0, 0, days).Format("2006-01-02")

		if days == -9999 {
			status = "unknown"
			expiryLabel = "permanent"
			days = 0
		} else if days < 0 {
			status = "expired"
			expiryLabel = time.Now().AddDate(0, 0, days).Format("2006-01-02")
		}

		log.Printf("Alias \"%s\" from %s expires on %s (%d days left), metric=%s", alias, keystore, expiryLabel, days, metricName)

		builder.WriteString(fmt.Sprintf("%s{name=\"%s\", keystore=\"%s\", status=\"%s\", expires=\"%s\"} %d\n",
			metricName, alias, keystore, status, expiryLabel, days))
	}

	log.Printf("Total aliases processed in %s: %d", keystore, len(aliases))
	if minDays < 99999 {
		expirySoon := time.Now().AddDate(0, 0, minDays).Format("2006-01-02")
		log.Printf("\033[31mEarliest certificate expiry in %s is on %s (%d days left)\033[0m", keystore, expirySoon, minDays)
	}
	return builder.String()
}
func writeToFile(content string) {
	dir := os.Getenv("PROM_FILE_DIR")
	file := os.Getenv("PROM_FILE_NAME")
	if dir == "" || file == "" {
		log.Println("PROM_FILE_DIR or PROM_FILE_NAME not set, skipping file output")
		return
	}
	path := filepath.Join(dir, file)
	comment := `# File generated by jks-exporter
# Content for PROMETHEUS
`
	contentWithComment := comment + content

	err := ioutil.WriteFile(path, []byte(contentWithComment), 0644)
	if err != nil {
		log.Printf("Error writing to .prom file: %v", err)
	} else {
		log.Printf("Metrics written to %s", path)
	}
}

func metricsHandler(metrics string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, metrics)
	}
}

func writePidFile(pidFile string) error {
	pid := os.Getpid()
	return os.WriteFile(pidFile, []byte(strconv.Itoa(pid)), 0644)
}

func removePidFile(pidFile string) {
	_ = os.Remove(pidFile)
}

func runExporter(pidPath string) {
	defaultLog := log.Default()
	_ = writePidFile(pidPath)
	defer removePidFile(pidPath)

	envFiles, err := loadAllEnvFiles()
	log.Printf("Found %d env file(s) to process", len(envFiles))
	if err != nil {
		log.Fatalf("Failed to discover env files: %v", err)
	}

	allMetrics := strings.Builder{}
	for _, envFile := range envFiles {
		log.SetOutput(defaultLog.Writer())

		base := filepath.Base(envFile)
		baseName := strings.TrimPrefix(base, ".")
		execDir, _ := os.Getwd()
		logDir := filepath.Join(execDir, "logs")
		_ = os.MkdirAll(logDir, 0755)
		logPath := filepath.Join(logDir, baseName+".log")
		f, err := os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err == nil {
			log.SetOutput(f)
			log.Printf("Processing env file: %s", envFile)
		} else {
			log.Printf("Could not create log for %s: %v", envFile, err)
		}

		log.Printf("Loading environment variables from %s", envFile)
		err = godotenv.Overload(envFile)
		if err != nil {
			log.Printf("Skipping env file %s due to error: %v", envFile, err)
			continue
		}
		mode := os.Getenv("EXPORT_MODE")
		metrics := generateMetrics()
		if mode == "file" || mode == "both" {
			writeToFile(metrics)
		}
		if mode == "web" || mode == "both" {
			allMetrics.WriteString(metrics)
		}
	}

	if os.Getenv("EXPORT_MODE") == "web" || os.Getenv("EXPORT_MODE") == "both" {
		port := os.Getenv("PORT")
		if port == "" {
			port = ":9100"
		}
		ln, err := net.Listen("tcp", port)
		if err != nil {
			if strings.Contains(err.Error(), "address already in use") {
				log.Printf("Port %s is already in use, skipping web export.", port)
				return
			}
			log.Printf("Failed to bind to port %s: %v", port, err)
			return
		}
		http.HandleFunc("/metrics", metricsHandler(allMetrics.String()))
		log.Printf("Starting HTTP server on %s — export mode is active", port)
		log.Printf("You can now scrape metrics from http://localhost%s/metrics", port)
		go func() {
			if err := http.Serve(ln, nil); err != nil {
				log.Printf("HTTP server stopped: %v", err)
			}
		}()

		quit := make(chan os.Signal, 1)
		signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
		<-quit
		log.Println("Shutting down exporter")
	}
}

func main() {
	checkAndWarnIfRunning := func(pidPath string) bool {
		data, err := os.ReadFile(pidPath)
		if err == nil {
			pid, _ := strconv.Atoi(strings.TrimSpace(string(data)))
			proc, perr := os.FindProcess(pid)
			if perr == nil {
				err := proc.Signal(syscall.Signal(0))
				if err == nil {
					log.Printf("Exporter already running with PID %d", pid)
					return true
				} else {
					log.Printf("Found stale PID %d, removing .pid file", pid)
					removePidFile(pidPath)
				}
			}
		}
		return false
	}

	initLogger()

	homeDir, _ := os.UserHomeDir()
	pidPath := filepath.Join(homeDir, ".keystore_exporter.pid")

	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "stop":
			data, err := os.ReadFile(pidPath)
			if err != nil {
				log.Fatalf("Cannot read PID file: %v", err)
			}
			pid, _ := strconv.Atoi(strings.TrimSpace(string(data)))
			if err := syscall.Kill(pid, syscall.SIGTERM); err != nil {
				log.Fatalf("Failed to stop process %d: %v", pid, err)
			}
			removePidFile(pidPath)
			log.Printf("Stopped process %d", pid)
			return
		case "start":
			if checkAndWarnIfRunning(pidPath) {
				return
			}
			runExporter(pidPath)
			return
		case "status":
			if data, err := os.ReadFile(pidPath); err == nil {
				pid, _ := strconv.Atoi(strings.TrimSpace(string(data)))
				if err := syscall.Kill(pid, 0); err == nil {
					log.Printf("Exporter is running with PID %d", pid)
				} else {
					log.Println("PID file exists but process is not running")
				}
			} else {
				log.Println("Exporter is not running")
			}
			return
		case "restart":
			data, err := os.ReadFile(pidPath)
			if err == nil {
				pid, _ := strconv.Atoi(strings.TrimSpace(string(data)))
				_ = syscall.Kill(pid, syscall.SIGTERM)
				removePidFile(pidPath)
				log.Printf("Stopped previous process %d", pid)
			}
			runExporter(pidPath)
			return
		default:
			log.Printf("Unknown command: %s", os.Args[1])
			return
		}
	}

	if checkAndWarnIfRunning(pidPath) {
		return
	}
	runExporter(pidPath)
}
