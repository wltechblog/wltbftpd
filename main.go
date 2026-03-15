package main

import (
	"flag"
	"log"
)

var (
	listenAddr = flag.String("addr", ":2121", "FTP server listen address")
	authFile   = flag.String("auth-file", "", "Path to file-based authentication file")
	systemAuth = flag.Bool("system-auth", true, "Enable system authentication")
)

func main() {
	flag.Parse()

	authManager, err := NewAuthManager(*authFile, *systemAuth)
	if err != nil {
		log.Fatalf("Failed to create auth manager: %v", err)
	}

	server := NewFTPServer(*listenAddr, authManager)

	if *authFile != "" {
		log.Printf("Using file-based authentication from: %s", *authFile)
	}
	if *systemAuth {
		log.Printf("System authentication enabled")
	}

	if err := server.Start(); err != nil {
		log.Fatalf("Server error: %v", err)
	}
}
