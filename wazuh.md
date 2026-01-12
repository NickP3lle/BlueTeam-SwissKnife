# Wazuh Introduction

## What is Wazuh?

Wazuh is a free, open-source security monitoring platform that provides unified SIEM (Security Information and Event Management) and XDR (Extended Detection and Response) capabilities. It helps organizations detect threats, monitor integrity, ensure compliance, and respond to security incidents across their infrastructure.

## Key Features

-   **Intrusion Detection**: Real-time log analysis and file integrity monitoring
-   **Threat Intelligence**: Integration with threat intelligence feeds
-   **Cloud Security**: Multi-cloud security monitoring (AWS, Azure, GCP)
-   **Vulnerability Detection**: Automated vulnerability scanning

## Architecture

Wazuh consists of three main components:

1. **Wazuh Agent**: Lightweight software installed on monitored endpoints
2. **Wazuh Server**: Central component that analyzes data from agents
3. **Wazuh Dashboard**: Web interface for visualization and management

## Deployment

### Installation Steps

**1. Install Wazuh Indexer (OpenSearch)**

```bash
# Install Wazuh indexer
apt-get install wazuh-indexer

# Configure and start the service
systemctl daemon-reload
systemctl enable wazuh-indexer
systemctl start wazuh-indexer
```

**2. Install Wazuh Server (Manager)**

```bash
# Install Wazuh manager
apt-get install wazuh-manager

# Enable and start the service
systemctl daemon-reload
systemctl enable wazuh-manager
systemctl start wazuh-manager
```

**3. Install Wazuh Dashboard**

```bash
# Install Wazuh dashboard
apt-get install wazuh-dashboard

# Enable and start the dashboard
systemctl daemon-reload
systemctl enable wazuh-dashboard
systemctl start wazuh-dashboard
```

#### Installing Wazuh Agent

**Linux:**

```bash
# Install with manager IP (repository should already be configured)
WAZUH_MANAGER="wazuh-manager.example.com" apt-get install wazuh-agent

# Start the agent
systemctl daemon-reload
systemctl enable wazuh-agent
systemctl start wazuh-agent
```

**Windows:**

```powershell
# Download the Windows agent installer
Invoke-WebRequest -Uri https://packages.wazuh.com/4.x/windows/wazuh-agent-4.7.0-1.msi -OutFile wazuh-agent.msi

# Install with manager IP
msiexec.exe /i wazuh-agent.msi /q WAZUH_MANAGER="wazuh-manager.example.com"

# Start the agent
NET START WazuhSvc
```

## Useful Wazuh Commands

```bash
# View manager logs
tail -f /var/ossec/logs/ossec.log

# List connected agents
/var/ossec/bin/agent_control -lc

# Test rules and decoders
/var/ossec/bin/wazuh-logtest
```

## Wazuh Tips

-   Always restart the **Wazuh agent** after editing `ossec.conf`
-   Check agent connectivity from the dashboard before debugging rules
-   Custom rules and decoders are added under:

    -   `/var/ossec/etc/rules/`
    -   `/var/ossec/etc/decoders/`

-   Start troubleshooting from `ossec.log`

## Wazuh Log Configuration

```xml
<localfile>
  <log_format>syslog</log_format>
  <location>/var/log/auth.log</location>
</localfile>
```

## Wazuh Detection Rules

### SSH Brute Force (Linux)

```xml
<group name="authentication,ssh,">
  <rule id="100010" level="10">
    <if_matched_sid>5710</if_matched_sid>
    <frequency>5</frequency>
    <timeframe>60</timeframe>
    <description>Possible SSH brute force attack</description>
  </rule>
</group>
```

### File Integrity Monitoring (FIM)

```xml
<syscheck>
  <directories check_all="yes" realtime="yes" report_changes="yes">/etc</directories>
  <directories check_all="yes" realtime="yes" report_changes="yes">/bin</directories>
  <directories check_all="yes" realtime="yes" report_changes="yes">/sbin</directories>

  <ignore>/etc/mtab</ignore>
  <ignore>/etc/hosts.deny</ignore>
  <ignore>/etc/resolv.conf</ignore>

  <frequency>43200</frequency>
</syscheck>
```

## Suricata Installation

Suricata was installed on **LinuxHost** and integrated with Wazuh through the agent.

```bash
sudo add-apt-repository ppa:oisf/suricata-stable
sudo apt update
sudo apt install suricata -y
```

### Install Emerging Threats Rules

```bash
cd /tmp/
curl -LO https://rules.emergingthreats.net/open/suricata-6.0.8/emerging.rules.tar.gz
sudo tar -xvzf emerging.rules.tar.gz
sudo mkdir /etc/suricata/rules
sudo mv rules/*.rules /etc/suricata/rules/
sudo chmod 640 /etc/suricata/rules/*.rules
```

### Configuration

File: `/etc/suricata/suricata.yaml`

```yaml
HOME_NET: "10.10.10.2"
EXTERNAL_NET: "any"

default-rule-path: /etc/suricata/rules
rule-files:
    - "*.rules"

stats:
    enabled: yes

af-packet:
    - interface: enp0s8
```

Restart Suricata:

```bash
sudo systemctl restart suricata
```

### Suricata Log on Wazuh

```xml
<localfile>
  <log_format>json</log_format>
  <location>/var/log/suricata/eve.json</location>
</localfile>
```

```bash
sudo systemctl restart wazuh-agent
```

### Custom Suricata Rules

#### Detect GET /pass.html

```conf
alert http any any -> any 80 (
  msg:"HTTP Attack Detected";
  content:"GET /pass.html";
  sid:1000001;
  rev:1;
)
```

#### Detect pass.html with Offset

```conf
alert http any any -> any 80 (
  msg:"Attempt to Access pass.html File Detected";
  content:"pass.html";
  offset:5;
  depth:261;
  sid:1000002;
  rev:1;
)
```

## Atomic Red Team (ART)

```powershell
Invoke-AtomicTest T1048 -ShowDetailsBrief
Invoke-AtomicTest T1048 -TestNumbers 4
```

**Analysis Flow**

1. Execute atomic test
2. Identify Wazuh alert
3. Check rule group triggered
4. Inspect original log source

## Response to Attacks

### Blocking Malicious IPs (Apache)

```xml
<active-response>
  <command>firewall-drop</command>
  <location>local</location>
  <rules_id>100100</rules_id>
  <timeout>60</timeout>
</active-response>
```

### Malware Removal with VirusTotal

Detect and remove the **EICAR test file**.

```powershell
Invoke-WebRequest https://secure.eicar.org/eicar.com.txt -OutFile eicar.txt
```

Flow:

-   File detected by FIM
-   VirusTotal scan
-   Active Response removes file
