/**
* @Author: shaochuyu
* @Date: 5/7/2022 11:30
 */
package entry

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"wscan/core/collector"
	"wscan/core/resource"
	"wscan/core/utils/log"

	"github.com/thoas/go-funk"
)

// serviceScanAction implements the service scan entry point
func serviceScanAction(target, targetFile, ports string) error {
	if target == "" && targetFile == "" {
		return fmt.Errorf("target can't be empty")
	}

	// Parse target hosts
	targets := []string{}
	if targetFile != "" {
		log.Infof("Using target file: %s", targetFile)
		f, err := os.Open(targetFile)
		if err != nil {
			return fmt.Errorf("failed to open target file: %v", err)
		}
		defer f.Close()
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line != "" && !funk.ContainsString(targets, line) {
				targets = append(targets, line)
			}
		}
	} else {
		targets = append(targets, target)
	}

	// Parse port range
	portList, err := parsePortRange(ports)
	if err != nil {
		return fmt.Errorf("invalid port range: %v", err)
	}

	// Create service fitter
	fitter := &serviceFitter{
		targets: targets,
		ports:   portList,
	}

	// Create the FitOut channel
	taskChan, err := fitter.FitOut(context.Background(), targets)
	if err != nil {
		return fmt.Errorf("failed to create service scan tasks: %v", err)
	}

	// TODO: Integrate with Dispatcher to run plugins on discovered services
	// This would follow the same pattern as NewApp() in webscan.go:
	//   dispatcher := ctrl.NewDispatcher(&cfg.Config, multiPrinter, reverse.NewReverse(cfg.Reverse))
	//   dispatcher.Init(true) // true = service mode
	//   dispatcher.Run(taskChan, false)
	//   dispatcher.Release()
	_ = taskChan
	log.Infof("Service scan prepared for %d targets, %d ports", len(targets), len(portList))
	return nil
}

// parsePortRange parses a comma-separated port specification (e.g., "80,443,8080-8090")
func parsePortRange(ports string) ([]int, error) {
	if ports == "" {
		// Default common ports
		return []int{21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 993, 995, 1433, 1521, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 9200, 27017}, nil
	}

	var result []int
	seen := make(map[int]bool)
	parts := strings.Split(ports, ",")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if strings.Contains(part, "-") {
			rangeParts := strings.Split(part, "-")
			if len(rangeParts) != 2 {
				return nil, fmt.Errorf("invalid port range: %s", part)
			}
			start, err := strconv.Atoi(strings.TrimSpace(rangeParts[0]))
			if err != nil {
				return nil, fmt.Errorf("invalid port number: %s", rangeParts[0])
			}
			end, err := strconv.Atoi(strings.TrimSpace(rangeParts[1]))
			if err != nil {
				return nil, fmt.Errorf("invalid port number: %s", rangeParts[1])
			}
			if start > end {
				return nil, fmt.Errorf("invalid port range: start %d > end %d", start, end)
			}
			for p := start; p <= end; p++ {
				if !seen[p] {
					result = append(result, p)
					seen[p] = true
				}
			}
		} else {
			p, err := strconv.Atoi(part)
			if err != nil {
				return nil, fmt.Errorf("invalid port number: %s", part)
			}
			if !seen[p] {
				result = append(result, p)
				seen[p] = true
			}
		}
	}
	return result, nil
}

// getServiceFitter creates a service fitter for the given target and ports
func getServiceFitter(target, targetFile string, ports []int) collector.Fitter {
	targets := []string{}
	if targetFile != "" {
		f, err := os.Open(targetFile)
		if err != nil {
			log.Errorf("failed to open target file: %v", err)
			return nil
		}
		defer f.Close()
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line != "" {
				targets = append(targets, line)
			}
		}
	} else if target != "" {
		targets = append(targets, target)
	}

	return &serviceFitter{
		targets: targets,
		ports:   ports,
	}
}

// serviceFitter implements collector.Fitter for service/port scanning
type serviceFitter struct {
	targets []string
	ports   []int
}

func (sf *serviceFitter) FitOut(ctx context.Context, _ []string) (chan resource.Resource, error) {
	ch := make(chan resource.Resource)
	go func() {
		defer close(ch)
		for _, target := range sf.targets {
			// Strip protocol prefix if present
			target = strings.TrimPrefix(target, "http://")
			target = strings.TrimPrefix(target, "https://")
			// Strip port suffix if present (we use our own port list)
			host := target
			if idx := strings.LastIndex(target, ":"); idx != -1 {
				host = target[:idx]
			}

			for _, port := range sf.ports {
				svc := &resource.Service{
					Host:      host,
					Port:      port,
					TimeStamp: 0,
				}
				select {
				case ch <- svc:
				case <-ctx.Done():
					return
				}
			}
		}
	}()
	return ch, nil
}
