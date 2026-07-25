# VNC Library for Go
go-vnc is a VNC client library for Go.

This library implements [RFC 6143][RFC6143] -- The Remote Framebuffer Protocol
-- the protocol used by VNC.

## Project links
* Build Status:  [![Build Status][CIStatus]][CIProject]
* Documentation: [![GoDoc][GoDocStatus]][GoDoc]

## Setup
1. Download software and supporting packages.

    ```
    $ go get github.com/alexsnet/go-vnc
    $ go get golang.org/x/net
    ```

## Usage
Sample code usage is available in the GoDoc.

- Connect and listen to server messages: <https://godoc.org/github.com/alexsnet/go-vnc#example-Connect>

The source code is laid out such that the files match the document sections:

- [7.1] handshake.go
- [7.2] security.go
- [7.3] initialization.go
- [7.4] pixel_format.go
- [7.5] client.go
- [7.6] server.go
- [7.7] encodings.go

There are two additional files that provide everything else:

- vncclient.go -- code for instantiating a VNC client
- common.go -- common stuff not related to the RFB protocol


<!--- Links -->
[RFC6143]: http://tools.ietf.org/html/rfc6143

[CIProject]: https://travis-ci.org/alexsnet/go-vnc
[CIStatus]: https://travis-ci.org/alexsnet/go-vnc.png?branch=master

[GoDoc]: https://godoc.org/github.com/alexsnet/go-vnc
[GoDocStatus]: https://godoc.org/github.com/alexsnet/go-vnc?status.svg
