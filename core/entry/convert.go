package entry

import (
	"bufio"
	_ "embed"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strings"

	"wscan/core/output"
	"wscan/core/utils/log"
)

// convertJSONToHTML reads a JSON output file (one JSON object per line) and converts it to HTML.
func convertJSONToHTML(jsonPath, htmlPath string) error {
	jsonFile, err := os.Open(jsonPath)
	if err != nil {
		return fmt.Errorf("failed to open JSON file: %w", err)
	}
	defer jsonFile.Close()

	htmlFile, err := os.Create(htmlPath)
	if err != nil {
		return fmt.Errorf("failed to create HTML file: %w", err)
	}
	defer htmlFile.Close()

	// Write HTML template prefix (reuse embedded template from output package)
	// We reference the template via a function to avoid duplicating it
	templateData := output.GetHTMLTemplate()
	htmlFile.Write(templateData)
	htmlFile.Write([]byte("\n"))

	vulnCount := 0
	scanner := bufio.NewScanner(jsonFile)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		// Validate it's a JSON object (starts with '{')
		if !strings.HasPrefix(line, "{") {
			continue
		}
		htmlFile.Write([]byte("<script class='web-vulns'>webVulns.push("))
		htmlFile.Write([]byte(line))
		htmlFile.Write([]byte(")</script>\n"))
		vulnCount++
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("error reading JSON file: %w", err)
	}

	log.Infof("Converted %d vulns from JSON to HTML: %s -> %s", vulnCount, jsonPath, htmlPath)
	return nil
}

// webVulnsPushPattern matches <script class='web-vulns'>webVulns.push(JSON)</script>
var webVulnsPushPattern = regexp.MustCompile(`<script class='web-vulns'>webVulns\.push\((.*?)\)</script>`)

// convertHTMLToJSON reads an HTML report and extracts the vulnerability data as JSON.
func convertHTMLToJSON(htmlPath, jsonPath string) error {
	htmlFile, err := os.Open(htmlPath)
	if err != nil {
		return fmt.Errorf("failed to open HTML file: %w", err)
	}
	defer htmlFile.Close()

	jsonFile, err := os.Create(jsonPath)
	if err != nil {
		return fmt.Errorf("failed to create JSON file: %w", err)
	}
	defer jsonFile.Close()

	vulnCount := 0
	scanner := bufio.NewScanner(htmlFile)
	for scanner.Scan() {
		line := scanner.Text()
		matches := webVulnsPushPattern.FindStringSubmatch(line)
		if len(matches) < 2 {
			continue
		}
		// Validate the extracted JSON
		if !json.Valid([]byte(matches[1])) {
			continue
		}
		jsonFile.Write([]byte(matches[1]))
		jsonFile.Write([]byte("\n"))
		vulnCount++
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("error reading HTML file: %w", err)
	}

	log.Infof("Converted %d vulns from HTML to JSON: %s -> %s", vulnCount, htmlPath, jsonPath)
	return nil
}
