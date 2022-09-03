package main

import (
	"wscan/ext/pocassist/cmd"
)

// @title Pocassist Api
// @version v0.4.0
// @description Pocassist Api

// @securityDefinitions.apikey token
// @in header
// @name Authorization

func main() {
	cmd.RunApp()
}
