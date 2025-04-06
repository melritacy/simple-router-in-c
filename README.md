[![Review Assignment Due Date](https://classroom.github.com/assets/deadline-readme-button-22041afd0340ce965d47ae6ef1cefeee28c7c493a6346c4f15d667ab976d596c.svg)](https://classroom.github.com/a/WWT44ius)

# ---------------------------------------------
# Name : Melrita Cyriac
# SID  : 1772366
# CCID : melritac
# ---------------------------------------------

## Assignment: Software Router Implementation

### Important Design Decisions

In addition to implementing the core routing logic, I made several adjustments to the VM and Mininet environment to facilitate testing, including enabling SSH access and DNS resolution.

#### 🛠️ Mininet Network Configuration

To ensure a realistic network testing setup, I configured the Mininet VM environment as follows:

1. **Dual Network Adapter Setup**  
   - **Adapter 1 (NAT Network):** Provided internet connectivity to the VM.
   - **Adapter 2 (Host-only Adapter):** Allowed SSH access to the VM from the host machine.

2. **SSH Access for Debugging**  
   - Installed and started the SSH server on the Mininet VM:
     ```bash
     sudo apt install openssh-server
     sudo systemctl enable ssh
     sudo systemctl start ssh
     ```
   - Connected to the VM using:
     ```bash
     ssh mininet@192.168.170.4
     ```

3. **DNS Resolution Fix**  
   - DNS lookups failed initially inside Mininet hosts.
   - I manually configured `/etc/resolv.conf` in the Mininet host to use Google's public DNS:
     ```bash
     echo "nameserver 8.8.8.8" | sudo tee /etc/resolv.conf
     ```
   - This enabled services like `ping google.com` and ensured proper testing of DNS and external connectivity.

### Sources Cited

- Class-provided starter code and documentation.
- Man pages for `ssh`, `resolv.conf`, `systemctl`.
- StackOverflow for common Mininet and VM networking setups.

### Testing Strategy

- Used `ping` and `traceroute` to test ICMP Echo and TTL expiry.
- Used `nmap` and `netcat` to simulate TCP/UDP port probing and confirm ICMP port unreachable replies.
- Captured packets using:
  ```bash
  ./sr -l log.pcap


