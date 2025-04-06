[![Review Assignment Due Date](https://classroom.github.com/assets/deadline-readme-button-22041afd0340ce965d47ae6ef1cefeee28c7c493a6346c4f15d667ab976d596c.svg)](https://classroom.github.com/a/WWT44ius)

# ---------------------------------------------
# Name : Melrita Cyriac
# SID  : 1772366
# CCID : melritac
# ---------------------------------------------

## Assignment: Software Router Implementation

### Important Design Decisions

In addition to implementing core router functionality, I had to adapt the Mininet environment to support realistic networking capabilities such as SSH access and DNS resolution. These setup changes were essential for testing packet forwarding, ARP resolution, and ICMP handling end-to-end:

#### Mininet Network Configuration

To enable external SSH access and support internet-based services from within Mininet, I modified the network settings as follows:

1. **Dual Network Adapter Setup**  
   - **Adapter 1 (NAT Network):** Provides internet connectivity to the VM.  
   - **Adapter 2 (Host-only Adapter):** Allows SSH access to the VM from the host machine.

2. **Internet Access Inside Mininet**  
   - I created a NAT node in the Mininet topology and configured it to:
     - Use IP forwarding.
     - Masquerade packets going out to the NAT interface using `iptables`:
       ```bash
       sudo iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
       sudo sysctl -w net.ipv4.ip_forward=1
       ```

3. **DNS Resolution Fix**  
   - DNS queries from within Mininet initially failed.
   - I added Google’s public DNS to `/etc/resolv.conf` inside Mininet hosts:
     ```bash
     echo "nameserver 8.8.8.8" | sudo tee /etc/resolv.conf
     ```
   - This allowed resolution of domain names during pings and traceroutes.

4. **SSH Access for Debugging**  
   - Installed and enabled OpenSSH server in the VM:
     ```bash
     sudo apt install openssh-server
     sudo systemctl enable ssh
     sudo systemctl start ssh
     ```
   - Connected using:
     ```bash
     ssh mininet@192.168.170.4
     ```

### Sources Cited

- Class-provided starter code and documentation.
- Man pages for `iptables`, `sysctl`, and `resolv.conf`.
- StackOverflow for specific Valgrind memory debugging tips.

### Testing Strategy

- Used `ping` and `traceroute` to test ICMP Echo and TTL expiration handling.
- Verified TCP/UDP port unreachable responses with `nc` and `nmap`.
- Used Wireshark and `sr -l log.pcap` to capture and inspect forwarded packets.
- Validated ARP caching, timeouts, and retries using ARP requests and monitoring logs.
- Ran `valgrind` to ensure minimal memory leaks; addressed all but unavoidable `calloc`-related TLS thread allocations.

