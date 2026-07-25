/*
Package vnc provides VNC client implementation.

This package implements The Remote Framebuffer Protocol as documented in
[RFC 6143](http://tools.ietf.org/html/rfc6143).

A basic VNC client can be created like this. Replace the IP on the net.Dial line
with something more appropriate for your setup.

  package main

  import (
    "context"
    "log"
    "net"
    "time"

    "github.com/alexsnet/go-vnc"
    "github.com/alexsnet/go-vnc/messages"
    "github.com/alexsnet/go-vnc/rfbflags"
  )

  func main() {
    // Establish TCP connection to VNC server.
    nc, err := net.Dial("tcp", "127.0.0.1:5900")
    if err != nil {
      log.Fatalf("Error connecting to VNC host. %v", err)
    }

    // Negotiate connection with the server.
    vcc := vnc.NewClientConfig("some_password")
    vc, err := vnc.Connect(context.Background(), nc, vcc)
    if err != nil {
      log.Fatalf("Error negotiating connection to VNC host. %v", err)
    }

    // Periodically request framebuffer updates.
    go func() {
      w, h := vc.FramebufferWidth(), vc.FramebufferHeight()
      for {
        if err := vc.FramebufferUpdateRequest(rfbflags.RFBTrue, 0, 0, w, h); err != nil {
          log.Printf("error requesting framebuffer update: %v", err)
        }
        time.Sleep(1 * time.Second)
      }
    }()

    // Listen and handle server messages.
    go vc.ListenAndHandle()

    // Process messages coming in on the ServerMessage channel.
    for {
      msg := <-vcc.ServerMessageCh
      switch msg.Type() {
      case messages.FramebufferUpdate:
        log.Println("Received FramebufferUpdate message.")
      default:
        log.Printf("Received message type:%v msg:%v\n", msg.Type(), msg)
      }
    }
  }

This example will connect to a VNC server running on the localhost. It will
periodically request updates from the server, and listen for and handle
incoming FramebufferUpdate messages coming from the server.
*/
package vnc
