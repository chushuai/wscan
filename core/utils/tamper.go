/**
* @Author: shaochuyu
* @Date: 5/7/2022 11:30
 */
package utils

import (
	"net/url"
	"strconv"
	"strings"
)

func TamperURLParam(urlString, paramName, paramValue string) (string, error) {
	// Parse the URL string into a URL struct
	parsedURL, err := url.Parse(urlString)
	if err != nil {
		return "", err
	}

	// Get the query parameters as a map
	queryValues := parsedURL.Query()

	// Set the specified parameter value
	queryValues.Set(paramName, paramValue)

	// Update the URL with the new query parameters
	parsedURL.RawQuery = queryValues.Encode()

	// Return the modified URL string
	return parsedURL.String(), nil
}

func ObscureHost(urlString string) (string, error) {
	// Parse the URL string into a URL struct
	parsedURL, err := url.Parse(urlString)
	if err != nil {
		return "", err
	}

	// Split the host into its subdomains and top-level domain
	hostParts := strings.Split(parsedURL.Hostname(), ".")

	// Obscure the subdomains by replacing them with asterisks
	for i := 0; i < len(hostParts)-1; i++ {
		hostParts[i] = "*"
	}

	// Join the subdomains and top-level domain back together
	obscuredHost := strings.Join(hostParts, ".") + "." + parsedURL.Port()

	// Update the URL struct with the obscured host
	parsedURL.Host = obscuredHost

	// Return the modified URL string
	return parsedURL.String(), nil
}

func MakeSimilarHost(urlString string, num int) (string, error) {
	// Parse the URL string into a URL struct
	parsedURL, err := url.Parse(urlString)
	if err != nil {
		return "", err
	}

	// Get the original host and port
	host := parsedURL.Hostname()
	port := parsedURL.Port()

	// Convert the port to an integer if it is not empty
	var portInt int
	if port != "" {
		portInt, err = strconv.Atoi(port)
		if err != nil {
			return "", err
		}
	}

	// Create a new host by adding the specified number to the port
	newPort := portInt + num
	newHost := host + ":" + strconv.Itoa(newPort)

	// Update the URL struct with the new host
	parsedURL.Host = newHost

	// Return the modified URL string
	return parsedURL.String(), nil
}
