# wltbftpd

A simple, secure FTP server written in Go with support for multiple authentication methods.

## Features

- ✅ **System Authentication** - Authenticate against system users
- ✅ **File-based Authentication** - Custom user database with SHA256 password hashing
- ✅ **Anonymous Access** - Support for password-less logins (empty password hash)
- ✅ **Directory Restrictions** - Lock users to their home directories
- ✅ **Passive FTP Mode** - Default passive mode for better firewall compatibility
- ✅ **Permission-based Access** - Read/write based on OS file permissions
- ✅ **Lightweight** - Pure Go implementation with minimal dependencies

## Installation

### From Source

```bash
git clone https://github.com/wltechblog/wltbftp.git
cd wltbftp
go build -o wltbftp
```

### Binary Download

Download the latest release from the [Releases](https://github.com/wltechblog/wltbftp/releases) page.

## Configuration

### Command Line Options

| Flag | Description | Default |
|------|-------------|---------|
| `-addr` | Listen address | `:2121` |
| `-auth-file` | Path to authentication file | `""` |
| `-system-auth` | Enable system authentication | `true` |

### Authentication File Format

When using file-based authentication, create a file with the following format:

```
# username:homedir:limit_root:sha256_password_hash

alice:/home/ftp/alice:true:5e884898da28047151d0e56f8dc6292773603d0d6aabbdd27a3e5f8e8a8b4c6e
bob:/home/ftp/bob:false:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
```

**Fields:**
- `username` - FTP username (use `anonymous` for anonymous access)
- `homedir` - User's home directory (absolute path)
- `limit_root` - `true` to prevent escaping home directory, `false` to allow full filesystem access
- `sha256_password_hash` - SHA256 hash of the user's password (leave empty for password-less access)

### Generate Password Hash

```bash
echo -n "yourpassword" | sha256sum | awk '{print $1}'
```

### Anonymous Access

To enable anonymous FTP access, create a user with an empty password hash. The standard username for anonymous access is `anonymous`:

```
# Anonymous access - accepts any password
anonymous:/var/ftp/anon:true:
```

Anonymous users can connect with any password (commonly using their email address as a convention).

## Usage

### Start the Server

```bash
# Using only system authentication
./wltbftp -addr ":2121" -system-auth=true

# Using file-based authentication only
./wltbftp -addr ":2121" -auth-file users.txt -system-auth=false

# Using both authentication methods
./wltbftp -addr ":2121" -auth-file users.txt -system-auth=true
```

### Connect with FTP Client

```bash
ftp localhost 2121
```

Example session (authenticated user):
```
Connected to localhost.
220 Welcome to wltbftp FTP Server
Name (localhost:squash): alice
331 User name okay, need password
Password: 
230 User logged in
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> pwd
257 "/" is current directory
ftp> ls
150 Opening data connection
drwxr-xr-x 2 ftp ftp 4096 Jan 01 12:00 uploads
-rw-r--r-- 1 ftp ftp 12345 Jan 01 12:00 file.txt
226 Transfer complete
ftp> quit
221 Goodbye
```

Anonymous access example:
```
Connected to localhost.
220 Welcome to wltbftp FTP Server
Name (localhost:squash): anonymous
331 User name okay, need password
Password: 
230 User logged in
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> pwd
257 "/" is current directory
```
wltbftp/
├── main.go       # Entry point and CLI parsing
├── ftpserver.go  # FTP protocol implementation
└── README.md     # This file
```

### Testing

```bash
go test ./...
```

### Build

```bash
go build -ldflags="-s -w" -o wltbftp
```

## License

[GNU General Public License v2.0 only](LICENSE)

## Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## Support

- Open an issue for bugs or feature requests
- Check existing issues for common problems
