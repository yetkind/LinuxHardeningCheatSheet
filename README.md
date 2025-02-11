# Linux System Hardening Cheat Sheet

## 1. **System Updates & Patches**
### Keep OS & Packages Updated
```bash
# Debian/Ubuntu
sudo apt update && sudo apt upgrade -y && sudo apt autoremove

# RHEL/CentOS
sudo yum update -y && sudo yum autoremove

# Fedora
sudo dnf upgrade -y && sudo dnf autoremove
```

### Enable Automatic Updates
```bash
# Debian/Ubuntu (unattended-upgrades)
sudo apt install unattended-upgrades
sudo dpkg-reconfigure unattended-upgrades  # Enable automatic updates

# RHEL/CentOS (dnf-automatic)
sudo dnf install dnf-automatic
sudo systemctl enable --now dnf-automatic.timer
```

---

## 2. **User Account Security**
### Enforce Strong Passwords
- Install `libpam-pwquality` (Debian) or `libpwquality` (RHEL)
```bash
# Edit /etc/security/pwquality.conf
minlen = 12
difok = 5
enforce_for_root
```

### Lock Root Account & Use `sudo`
```bash
sudo passwd -l root  # Lock root account
# Use `visudo` to configure sudo access:
%sudo ALL=(ALL:ALL) ALL  # Allow sudo group to run commands
```

### Manage User Accounts
```bash
sudo useradd -m -s /bin/bash <user>  # Create user with home dir
sudo usermod -aG sudo <user>        # Add to sudo group
sudo userdel -r <user>              # Delete user & home dir
```

---

## 3. **Firewall Configuration**
### UFW (Uncomplicated Firewall)
```bash
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow ssh  # Allow SSH (customize port if changed)
sudo ufw enable
```

### firewalld (RHEL/CentOS)
```bash
sudo firewall-cmd --permanent --remove-service=ssh  # Remove default SSH rule
sudo firewall-cmd --permanent --add-port=2222/tcp    # Custom SSH port
sudo firewall-cmd --reload
```

---

## 4. **SSH Hardening**
Edit `/etc/ssh/sshd_config`:
```bash
Port 2222                         # Change default port
PermitRootLogin no
PasswordAuthentication no        # Enforce key-based auth
AllowUsers <user1> <user2>       # Whitelist users
ClientAliveInterval 300          # Terminate idle sessions
MaxAuthTries 3                   # Limit login attempts
```
```bash
sudo systemctl restart sshd
```

---

## 5. **Filesystem Security**
### Mount Options in `/etc/fstab`
```bash
UUID=... / ext4 defaults,noexec,nodev,nosuid 0 1
/tmp /var/tmp none rw,noexec,nosuid,nodev,bind 0 0
```

### Secure Critical Files
```bash
sudo chmod 600 /etc/shadow        # Restrict shadow file
sudo chattr +i /etc/passwd        # Make immutable (temporary)
```

---

## 6. **Kernel Hardening (sysctl)**
Edit `/etc/sysctl.conf`:
```bash
# Network security
net.ipv4.conf.all.rp_filter = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1

# Memory protection
kernel.exec-shield = 1
kernel.randomize_va_space = 2

# Prevent fork bombs
kernel.pid_max = 65535
```
```bash
sudo sysctl -p  # Apply changes
```

---

## 7. **Audit & Monitoring**
### Install & Configure auditd
```bash
sudo auditctl -e 1                # Enable auditing
sudo auditctl -l                  # List rules
# Monitor file changes:
sudo auditctl -w /etc/passwd -p wa -k passwd_changes
```

### Fail2Ban Setup
```bash
sudo apt install fail2ban  # Debian/Ubuntu
sudo dnf install fail2ban  # RHEL/CentOS

# Configure in /etc/fail2ban/jail.local:
[sshd]
enabled = true
port = 2222
maxretry = 3
```

---

## 8. **Application Sandboxing**
### **Firejail**

Firejail is a lightweight sandboxing tool that uses Linux namespaces and seccomp-bpf to restrict application access.

#### **Basic Usage**

```bash
firejail --noprofile --private --net=none chromium  # Run browser in sandbox
```

- `--noprofile`: Disables default profiles for stricter isolation.
- `--private`: Creates a private temporary filesystem for the application.
- `--net=none`: Disables network access (useful for untrusted applications).

#### **Custom Profiles**

Firejail uses profiles to define restrictions for specific applications. You can create or modify profiles in `/etc/firejail/`.

```bash
# Example: Create a custom profile for Firefox
sudo cp /etc/firejail/firefox.profile /etc/firejail/custom-firefox.profile
sudo nano /etc/firejail/custom-firefox.profile
```

- Add restrictions like:
  
  ```bash
  caps.drop all
  net none
  private-dev
  ```
  

#### **Run Applications with Firejail**

```bash
firejail --profile=/etc/firejail/custom-firefox.profile firefox
```

#### **List Active Sandboxes**

```bash
firejail --list
```

#### **Remove Firejail**

```bash
sudo apt remove firejail  # Debian/Ubuntu
sudo dnf remove firejail  # RHEL/CentOS
```

---

### **Docker Hardening**

Docker containers can be hardened by reducing their privileges and limiting their access to the host system.

#### **Run Containers with Limited Privileges**

```bash
docker run --read-only --cap-drop=ALL alpine
```

- `--read-only`: Mounts the container's root filesystem as read-only.
- `--cap-drop=ALL`: Drops all Linux capabilities (e.g., `CAP_SYS_ADMIN`, `CAP_NET_RAW`).

#### **Additional Hardening Options**

- **Limit CPU and Memory Usage:**
  
  ```bash
  docker run --cpus="1" --memory="512m" alpine
  ```
  
- **Disable Inter-Container Communication:**
  
  ```bash
  docker run --network none alpine
  ```
  
- **Use User Namespaces:**
  
  ```bash
  docker run --userns-remap=default alpine
  ```
  
- **Enable AppArmor/SELinux Profiles:**
  
  ```bash
  docker run --security-opt apparmor=docker-default alpine
  docker run --security-opt label=type:container_t alpine
  ```
  

#### **Scan Docker Images for Vulnerabilities**

Use tools like `Trivy` or `Clair` to scan Docker images for known vulnerabilities.

```bash
trivy image <image-name>
```

---

### **Bubblewrap (Alternative to Firejail)**

Bubblewrap is a lightweight sandboxing tool used by Flatpak and other applications.

#### **Basic Usage**

```bash
bwrap --ro-bind / / --dev /dev --proc /proc --unshare-pid --die-with-parent bash
```

- `--ro-bind`: Mounts directories as read-only.
- `--unshare-pid`: Isolates the process namespace.
- `--die-with-parent`: Ensures the sandbox is terminated when the parent process exits.

---

### **Flatpak (Sandboxed Applications)**

Flatpak is a package manager that runs applications in isolated sandboxes.

#### **Install Flatpak**

```bash
sudo apt install flatpak  # Debian/Ubuntu
sudo dnf install flatpak  # RHEL/CentOS
```

#### **Run Applications in Sandbox**

```bash
flatpak run org.mozilla.firefox
```

#### **View Sandbox Permissions**

```bash
flatpak info org.mozilla.firefox
```

---

### **Seccomp (Secure Computing Mode)**

Seccomp is a Linux kernel feature that restricts system calls.

#### **Example: Restrict System Calls in Docker**

```bash
docker run --security-opt seccomp=/path/to/seccomp-profile.json alpine
```

- Create a custom seccomp profile to allow only specific system calls.

---

## 9. **Advanced Security Modules**
### SELinux (Enforcing Mode)
```bash
sudo setenforce 1
sudo semanage boolean -l          # List policies
```

### AppArmor
```bash
sudo aa-enforce /etc/apparmor.d/*  # Enforce all profiles
```

---

## 10. **Miscellaneous**
### Disable USB Storage
```bash
echo "blacklist usb-storage" | sudo tee /etc/modprobe.d/disable-usb.conf
```

### Check for Open Ports
```bash
sudo netstat -tulpn | grep LISTEN
sudo ss -tulpn
```

---

## **Full Checklist**
1. [ ] Update OS & packages
2. [ ] Configure firewall
3. [ ] Harden SSH
4. [ ] Audit user accounts
5. [ ] Enable SELinux/AppArmor
6. [ ] Set filesystem permissions
7. [ ] Install fail2ban/auditd
8. [ ] Test configurations

---
### **Resources**

*   **CIS Benchmarks:**  The Center for Internet Security (CIS) provides hardening benchmarks for various operating systems and software. These are highly regarded industry best practices.
    *   [CIS Benchmarks](https://www.cisecurity.org/cis-benchmarks/)
    *   [CIS Controls](https://www.cisecurity.org/cis-controls/)
*   **Lynis:** A powerful security auditing tool that performs a comprehensive scan of your Linux system.
    *   [Lynis Website](https://cisofy.com/lynis/)
    *   [Lynis GitHub](https://github.com/CISOfy/lynis)
*   **OpenSCAP:** A suite of tools for implementing and verifying compliance with security baselines.
    *   [OpenSCAP Website](https://www.open-scap.org/)
*   **Security-Enhanced Linux (SELinux):**  Documentation and resources for SELinux.
    *   [SELinux Wiki](https://github.com/SELinuxProject/selinux/wiki)
    *   [NSA SELinux](https://www.nsa.gov/resources/everyone/support/selinux/)
*   **National Vulnerability Database (NVD):** A database of known vulnerabilities.
    *   [NVD Website](https://nvd.nist.gov/)
*   **OWASP (Open Web Application Security Project):** A non-profit foundation dedicated to improving the security of software.  While focused on web applications, many principles apply to system hardening.
    *   [OWASP Website](https://owasp.org/)
*   **SANS Institute:**  Provides security training and certifications.
    *   [SANS Institute Website](https://www.sans.org/)
*   **Linux Security Hardening Guides:** (Search for distro-specific guides, e.g., "Ubuntu Linux Security Hardening Guide")

This cheat sheet covers essential baseline hardening steps with actionable commands, it is basic so there are many things can be added for different purposes,
Contributions welcome on GitHub! 
Enjoy! - Yetkin
