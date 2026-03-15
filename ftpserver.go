package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
)

type AuthManager struct {
	fileBasedUsers map[string]FileBasedUser
	systemAuth     bool
	mu             sync.RWMutex
}

type FileBasedUser struct {
	Username     string
	HomeDir      string
	LimitRoot    bool
	PasswordHash string
}

func NewAuthManager(authFile string, systemAuth bool) (*AuthManager, error) {
	am := &AuthManager{
		fileBasedUsers: make(map[string]FileBasedUser),
		systemAuth:     systemAuth,
	}

	if authFile != "" {
		if err := am.loadFileBasedUsers(authFile); err != nil {
			return nil, fmt.Errorf("failed to load auth file: %w", err)
		}
	}

	return am, nil
}

func (am *AuthManager) loadFileBasedUsers(authFile string) error {
	file, err := os.Open(authFile)
	if err != nil {
		return err
	}
	defer file.Close()

	am.mu.Lock()
	defer am.mu.Unlock()

	scanner := bufio.NewScanner(file)
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.Split(line, ":")
		if len(parts) != 4 {
			return fmt.Errorf("invalid format at line %d: expected user:homedir:limit_root:password_hash", lineNum)
		}

		username := parts[0]
		homedir := parts[1]
		limitRoot := strings.ToLower(parts[2]) == "true"
		passwordHash := parts[3]

		absPath, err := filepath.Abs(homedir)
		if err != nil {
			return fmt.Errorf("invalid homedir at line %d: %w", lineNum, err)
		}

		if _, err := os.Stat(absPath); os.IsNotExist(err) {
			return fmt.Errorf("homedir does not exist at line %d: %s", lineNum, absPath)
		}

		am.fileBasedUsers[username] = FileBasedUser{
			Username:     username,
			HomeDir:      absPath,
			LimitRoot:    limitRoot,
			PasswordHash: passwordHash,
		}
	}

	return scanner.Err()
}

func (am *AuthManager) Authenticate(username, password string) (string, bool, error) {
	am.mu.RLock()
	defer am.mu.RUnlock()

	fileUser, exists := am.fileBasedUsers[username]
	if exists {
		if fileUser.PasswordHash == "" {
			return fileUser.HomeDir, fileUser.LimitRoot, nil
		}
		hash := sha256.Sum256([]byte(password))
		hashStr := hex.EncodeToString(hash[:])

		if hashStr == fileUser.PasswordHash {
			return fileUser.HomeDir, fileUser.LimitRoot, nil
		}
		return "", false, errors.New("invalid password")
	}

	if am.systemAuth {
		u, err := user.Lookup(username)
		if err != nil {
			return "", false, fmt.Errorf("user not found: %w", err)
		}
		return u.HomeDir, true, nil
	}

	return "", false, errors.New("authentication failed")
}

type FTPServer struct {
	listenAddr    string
	authManager   *AuthManager
	passivePort   int
	passiveHost   string
	passiveListen net.Listener
}

func NewFTPServer(listenAddr string, authManager *AuthManager) *FTPServer {
	return &FTPServer{
		listenAddr:  listenAddr,
		authManager: authManager,
		passivePort: 50000,
	}
}

func (s *FTPServer) Start() error {
	listener, err := net.Listen("tcp", s.listenAddr)
	if err != nil {
		return fmt.Errorf("failed to listen: %w", err)
	}
	defer listener.Close()

	log.Printf("FTP server started on %s", s.listenAddr)

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("Error accepting connection: %v", err)
			continue
		}
		go s.handleConnection(conn)
	}
}

type FTPSession struct {
	conn            net.Conn
	reader          *bufio.Reader
	writer          *bufio.Writer
	username        string
	authenticated   bool
	basePath        string
	limitRoot       bool
	currentDir      string
	dataConn        net.Conn
	passiveMode     bool
	passiveListener net.Listener
	passiveAddr     string
	authManager     *AuthManager
}

func (s *FTPServer) handleConnection(conn net.Conn) {
	defer conn.Close()

	session := &FTPSession{
		conn:        conn,
		reader:      bufio.NewReader(conn),
		writer:      bufio.NewWriter(conn),
		currentDir:  "/",
		authManager: s.authManager,
	}

	session.sendLine("220 Hello")

	for {
		line, err := session.reader.ReadString('\n')
		if err != nil {
			if err != io.EOF {
				log.Printf("Error reading: %v", err)
			}
			break
		}

		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		parts := strings.Fields(line)
		if len(parts) == 0 {
			continue
		}

		cmd := strings.ToUpper(parts[0])
		args := ""
		if len(parts) > 1 {
			args = strings.Join(parts[1:], " ")
		}

		if err := session.handleCommand(cmd, args); err != nil {
			log.Printf("Error handling command %s: %v", cmd, err)
			break
		}
	}
}

func (s *FTPSession) sendLine(line string) error {
	s.writer.WriteString(line + "\r\n")
	return s.writer.Flush()
}

func (s *FTPSession) handleCommand(cmd, args string) error {
	switch cmd {
	case "USER":
		s.username = args
		return s.sendLine("331 User name okay, need password")
	case "PASS":
		homedir, limitRoot, err := s.authManager.Authenticate(s.username, args)
		if err != nil {
			log.Printf("Authentication failed for user %s: %v", s.username, err)
			return s.sendLine("530 Not logged in")
		}
		s.authenticated = true
		s.basePath = homedir
		s.limitRoot = limitRoot
		return s.sendLine("230 User logged in")
	case "SYST":
		return s.sendLine("215 UNIX Type: L8")
	case "FEAT":
		return s.sendLine("211-Features:\r\n211 End")
	case "PWD", "XPWD":
		return s.sendLine("257 \"" + s.currentDir + "\" is current directory")
	case "TYPE":
		return s.sendLine("200 Type set to " + args)
	case "MODE":
		return s.sendLine("200 Mode set to " + args)
	case "STRU":
		return s.sendLine("200 Structure set to " + args)
	case "PASV":
		return s.handlePassive()
	case "EPSV":
		if s.passiveListener == nil {
			listener, err := net.Listen("tcp", "0.0.0.0:0")
			if err != nil {
				return s.sendLine("425 Cannot open data connection")
			}
			addr := listener.Addr().(*net.TCPAddr)
			s.passiveListener = listener
			s.passiveAddr = addr.String()
			s.passiveMode = true
		}
		addr := s.passiveListener.Addr().(*net.TCPAddr)
		return s.sendLine("229 Entering Extended Passive Mode (|||" + strconv.Itoa(addr.Port) + "|)")
	case "CWD", "XCWD":
		return s.handleChangeDir(args)
	case "CDUP", "XCUP":
		return s.handleChangeDir("..")
	case "LIST":
		return s.handleList(args)
	case "NLST":
		return s.handleList(args)
	case "RETR":
		return s.handleRetrieve(args)
	case "STOR":
		return s.handleStore(args)
	case "DELE":
		return s.handleDelete(args)
	case "RMD", "XRMD":
		return s.handleRemoveDir(args)
	case "MKD", "XMKD":
		return s.handleMakeDir(args)
	case "RNFR":
		return s.sendLine("350 Ready for RNTO")
	case "RNTO":
		return s.sendLine("250 Rename successful")
	case "SIZE":
		return s.handleSize(args)
	case "QUIT":
		return s.sendLine("221 Goodbye")
	case "NOOP":
		return s.sendLine("200 OK")
	default:
		return s.sendLine("502 Command not implemented")
	}
}

func (s *FTPSession) handlePassive() error {
	if s.passiveListener != nil {
		s.passiveListener.Close()
	}

	listener, err := net.Listen("tcp", "0.0.0.0:0")
	if err != nil {
		return s.sendLine("425 Cannot open data connection")
	}

	addr := listener.Addr().(*net.TCPAddr)
	s.passiveListener = listener
	s.passiveAddr = addr.String()
	s.passiveMode = true

	p1 := addr.Port / 256
	p2 := addr.Port % 256
	return s.sendLine(fmt.Sprintf("227 Entering Passive Mode (127,0,0,1,%d,%d)", p1, p2))
}

func (s *FTPSession) getDataConnection() (net.Conn, error) {
	if s.passiveListener != nil {
		conn, err := s.passiveListener.Accept()
		if err != nil {
			return nil, err
		}
		return conn, nil
	}
	return nil, errors.New("no data connection available")
}

func (s *FTPSession) resolvePath(path string) (string, error) {
	if path == "" {
		path = s.currentDir
	}

	if !strings.HasPrefix(path, "/") {
		path = filepath.Join(s.currentDir, path)
	}

	absPath := filepath.Join(s.basePath, filepath.Clean(path))

	if s.limitRoot {
		absBase, err := filepath.Abs(s.basePath)
		if err != nil {
			return "", err
		}

		rel, err := filepath.Rel(absBase, absPath)
		if err != nil || strings.HasPrefix(rel, "..") {
			return "", errors.New("permission denied")
		}
	}

	return absPath, nil
}

func (s *FTPSession) handleChangeDir(path string) error {
	if !s.authenticated {
		return s.sendLine("530 Not logged in")
	}

	fullPath, err := s.resolvePath(path)
	if err != nil {
		return s.sendLine("550 Failed to change directory")
	}

	info, err := os.Stat(fullPath)
	if err != nil {
		return s.sendLine("550 Failed to change directory")
	}

	if !info.IsDir() {
		return s.sendLine("550 Not a directory")
	}

	relPath, err := filepath.Rel(s.basePath, fullPath)
	if err != nil {
		return s.sendLine("550 Failed to change directory")
	}

	s.currentDir = "/" + filepath.ToSlash(relPath)
	if s.currentDir != "/" && strings.HasSuffix(s.currentDir, "/") {
		s.currentDir = s.currentDir[:len(s.currentDir)-1]
	}

	return s.sendLine("250 Directory changed to " + s.currentDir)
}

func (s *FTPSession) handleList(args string) error {
	if !s.authenticated {
		return s.sendLine("530 Not logged in")
	}

	path := s.currentDir
	if args != "" {
		path = args
	}

	fullPath, err := s.resolvePath(path)
	if err != nil {
		return s.sendLine("550 Failed to list directory")
	}

	s.sendLine("150 Opening data connection")

	dataConn, err := s.getDataConnection()
	if err != nil {
		return s.sendLine("425 Cannot open data connection")
	}
	defer dataConn.Close()

	entries, err := os.ReadDir(fullPath)
	if err != nil {
		return s.sendLine("550 Failed to list directory")
	}

	for _, entry := range entries {
		info, _ := entry.Info()
		line := fmt.Sprintf("%s %4d %10s %10s %8d %s %s",
			permString(info.Mode()),
			1,
			"ftp",
			"ftp",
			info.Size(),
			info.ModTime().Format("Jan 02 15:04"),
			entry.Name())
		dataConn.Write([]byte(line + "\r\n"))
	}

	return s.sendLine("226 Transfer complete")
}

func (s *FTPSession) handleRetrieve(path string) error {
	if !s.authenticated {
		return s.sendLine("530 Not logged in")
	}

	fullPath, err := s.resolvePath(path)
	if err != nil {
		return s.sendLine("550 File not found")
	}

	file, err := os.Open(fullPath)
	if err != nil {
		return s.sendLine("550 File not found")
	}
	defer file.Close()

	s.sendLine("150 Opening data connection")

	dataConn, err := s.getDataConnection()
	if err != nil {
		return s.sendLine("425 Cannot open data connection")
	}
	defer dataConn.Close()

	_, err = io.Copy(dataConn, file)
	if err != nil {
		return s.sendLine("426 Connection closed; transfer aborted")
	}

	return s.sendLine("226 Transfer complete")
}

func (s *FTPSession) handleStore(path string) error {
	if !s.authenticated {
		return s.sendLine("530 Not logged in")
	}

	fullPath, err := s.resolvePath(path)
	if err != nil {
		return s.sendLine("550 Cannot create file")
	}

	file, err := os.Create(fullPath)
	if err != nil {
		return s.sendLine("550 Cannot create file")
	}
	defer file.Close()

	s.sendLine("150 Opening data connection")

	dataConn, err := s.getDataConnection()
	if err != nil {
		return s.sendLine("425 Cannot open data connection")
	}
	defer dataConn.Close()

	_, err = io.Copy(file, dataConn)
	if err != nil {
		return s.sendLine("426 Connection closed; transfer aborted")
	}

	return s.sendLine("226 Transfer complete")
}

func (s *FTPSession) handleDelete(path string) error {
	if !s.authenticated {
		return s.sendLine("530 Not logged in")
	}

	fullPath, err := s.resolvePath(path)
	if err != nil {
		return s.sendLine("550 File not found")
	}

	err = os.Remove(fullPath)
	if err != nil {
		return s.sendLine("550 Cannot delete file")
	}

	return s.sendLine("250 Delete successful")
}

func (s *FTPSession) handleRemoveDir(path string) error {
	if !s.authenticated {
		return s.sendLine("530 Not logged in")
	}

	fullPath, err := s.resolvePath(path)
	if err != nil {
		return s.sendLine("550 Directory not found")
	}

	err = os.Remove(fullPath)
	if err != nil {
		return s.sendLine("550 Cannot remove directory")
	}

	return s.sendLine("250 Directory removed")
}

func (s *FTPSession) handleMakeDir(path string) error {
	if !s.authenticated {
		return s.sendLine("530 Not logged in")
	}

	fullPath, err := s.resolvePath(path)
	if err != nil {
		return s.sendLine("550 Cannot create directory")
	}

	err = os.MkdirAll(fullPath, 0755)
	if err != nil {
		return s.sendLine("550 Cannot create directory")
	}

	return s.sendLine("257 Directory created")
}

func (s *FTPSession) handleSize(path string) error {
	if !s.authenticated {
		return s.sendLine("530 Not logged in")
	}

	fullPath, err := s.resolvePath(path)
	if err != nil {
		return s.sendLine("550 File not found")
	}

	info, err := os.Stat(fullPath)
	if err != nil {
		return s.sendLine("550 File not found")
	}

	return s.sendLine("213 " + strconv.FormatInt(info.Size(), 10))
}

func permString(mode os.FileMode) string {
	str := ""
	if mode&os.ModeDir != 0 {
		str += "d"
	} else {
		str += "-"
	}
	for i := 0; i < 9; i++ {
		if mode&(1<<uint(8-i)) != 0 {
			switch i % 3 {
			case 0:
				str += "r"
			case 1:
				str += "w"
			case 2:
				str += "x"
			}
		} else {
			str += "-"
		}
	}
	return str
}
