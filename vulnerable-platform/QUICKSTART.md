# 🚀 Quick Start Guide

## Prerequisites
- Docker and Docker Compose
- Web browser
- (Optional) Python 3 for exploitation scripts

## Setup in 3 Steps

### 1. Start the Platform
```bash
cd vulnerable-platform
docker-compose up -d --build
```

Wait for the build to complete (~2-3 minutes)

### 2. Access the Application
Open your browser and navigate to:
```
http://localhost:5000
```

### 3. Start Hacking!

## First Exploit: SQL Injection Login Bypass

1. Go to http://localhost:5000/login
2. Enter these credentials:
   - **Username:** `admin' OR '1'='1' --`
   - **Password:** `anything`
3. Click Login

**You're in!** 🎉

## Second Exploit: Command Injection

1. Navigate to the **Ping Tool** (http://localhost:5000/ping)
2. Enter: `127.0.0.1; whoami`
3. Click Ping

**You just executed a command on the server!**

## Third Exploit: Docker Escape

1. Use command injection to execute: `ls -la /host`
2. You can see the host filesystem!
3. Execute: `cat /host/etc/hostname`

**You escaped the container!** 🏆

## Using Exploitation Scripts

### Automated SQL Injection
```bash
cd exploits
python3 sql_injection.py
```

### Automated Command Injection
```bash
python3 command_injection.py
```

### Docker Escape (from inside container)
```bash
# First, get shell access via command injection
# Then execute:
bash docker_escape.sh
```

## Stopping the Platform
```bash
docker-compose down
```

## Need Help?

- Read the full README.md for detailed exploitation techniques
- Check the vulnerabilities section in the web app home page
- Each page has hints about the vulnerabilities present

## ⚠️ Remember
This is for **educational purposes only**. Never use these techniques on systems you don't own or have explicit permission to test!

---

**Have fun and happy hacking! 🔓**
