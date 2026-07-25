# useragent
A comprehensive and categorized collection of User Agents.

## Installation Instructions

To install the useragent tool, use the following command:

```sh
go install -v github.com/projectdiscovery/useragent/cmd/ua@latest
```

## Usage

To display help for the tool, use the following command:

```sh
ua -h
```

This will display all the flags supported by the tool:

```sh
ua is a straightforward tool to query and filter user agents

Usage:
  ./ua [flags]

Flags:
   -list              list all the categorized tags of user-agent
   -l, -limit int     number of user-agent to list (use -1 to list all) (default 10)
   -t, -tag string[]  list user-agent for given tag
```

The useragent tool is designed to be simple and efficient, making it easy to query and filter user agents based on your specific needs.

## Credits

This tool utilizes user agent data obtained from [WhatIsMyBrowser.com](https://www.whatismybrowser.com).
