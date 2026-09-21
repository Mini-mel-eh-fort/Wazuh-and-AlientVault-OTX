# Wazuh with Alien Vault OTX on Ubuntu

**Objective:** This project covers the deployment of a Wazuh SIEM environment integrated with AlienVault Open Threat Exchange (OTX). By utilizing a custom Python script, this lab automates threat intelligence lookups for network events, enriching alerts with real-time data to significantly reduce manual analysis time and accelerate incident response.

**Prerequisites:** To deploy this environment, you will need:
* An Ubuntu virtual machine with root or sudo privileges.
* An active AlienVault OTX account and API key (it's free thankfully).
* Basic familiarity with Linux command-line administration.

---

## Step 1: Set Static IP Address

Once Ubuntu is installed, run updates:

```bash
sudo apt update -y && sudo apt upgrade -y
```

Modify the file at `/etc/netplan/00-installer-config.yaml` with `sudo` or `root` access to set the static IP address to **YOUR IP ADDRESS** (Make sure to update `YOURSTATICIP`, `CIDR`, `YOURDEFAULTGATEWAYIP`, and `YOURMACADDRESS` to your situation's information.).

```yaml
netog@wazuhserver:/etc/netplan$ sudo cat 00-installer-config.yaml
# This is the network config written by 'subiquity'
network:
  version: 2
  renderer: networkd
  ethernets:
    ens18:
      dhcp4: false
      dhcp6: false
      addresses:
        - (YOURSTATICIP/CIDR)
      routes:
         - to: default
           via: (YOURDEFAULTGATEWAYIP)
      nameservers:
        addresses:
         - (YOURDEFAULTGATEWAYIP)
         - 1.1.1.1
         - 8.8.8.8
      match:
        macaddress: (YOURMACADDRESS)
      set-name: ens18
```
Then apply with :
```BASH
sudo netplan apply
```
---

## Step 2: Install Wazuh

Documentation found here: [Wazuh Quickstart](https://documentation.wazuh.com/current/quickstart.html)

I created a folder at `~/wazuhinstallfiles` to keep my files together and `cd` to this directory:

```bash
cd ~
mkdir wazuhinstallfiles
cd wazuhinstallfiles
```

With `curl`, download the install script and run it with this command:

```bash
curl -sO https://packages.wazuh.com/4.14/wazuh-install.sh && sudo bash ./wazuh-install.sh -a
```

Output format for accessing the console:

```text
11/09/2026 02:50:51 INFO: You can access the web interface https://<wazuh-dashboard-ip>:443
    User: admin
    Password: (your password will be displayed here)
```

**Test Login:**
From a different PC within the same network as the Wazuh server, navigate to `https://(YOURSTATICIP):443` and sign in with the credentials provided.

### Secure the default login credentials

Updating the password through the UI will cause sync issues between the different components of Wazuh, so a tool is used to make sure they are all synced with the right credentials. Download the Wazuh passwords tool:

```bash
curl -sO https://packages.wazuh.com/4.14/wazuh-passwords-tool.sh
```

Make the file executable and run it:

```bash
sudo chmod +x wazuh-passwords-tool.sh
sudo bash ./wazuh-passwords-tool.sh -u admin -p 'YourNewPassword'
```

---

## Step 3: Add AlienVault OTX and pull with a Python script

### Install OTX

```bash
sudo apt update
sudo apt install python3-pip -y
sudo /var/ossec/framework/python/bin/python3 -m pip install OTXv2 
```

Test that Wazuh’s python binary can import the module:

```bash
sudo /var/ossec/framework/python/bin/python3 -c "import OTXv2; print('OTXv2 successfully loaded in Wazuh environment')"
```

### Create the Integration Python Script

Create the Python script to be triggered when an alert fires to query AlienVault for threat intelligence:

```bash
sudo nano /var/ossec/integrations/custom-alienvault.py
```

Paste the following script into the file:

```python
#!/var/ossec/framework/python/bin/python3
import sys
import json
import os
from OTXv2 import OTXv2, IndicatorTypes

# Wazuh passes arguments dynamically:
# sys.argv[1] = Alert file path, sys.argv[2] = API Key
alert_file = sys.argv[1]
api_key = sys.argv[2]

# Load the triggered alert data
try:
    with open(alert_file, 'r') as f:
        alert_json = json.load(f)
except Exception:
    sys.exit(0)

# Extract IP indicators from standard Wazuh schema fields
data = alert_json.get('data', {})
ip_address = data.get('srcip') or data.get('dstip') or alert_json.get('srcip') or alert_json.get('dstip')

# Exit if no IP address exists in the alert context
if not ip_address:
    sys.exit(0)

try:
    # Query AlienVault OTX API using your key
    otx = OTXv2(api_key)
    result = otx.get_indicator_details_by_section(IndicatorTypes.IPv4, ip_address, "general")
    
    # Check for pulse data indicating known malicious infrastructure
    pulse_info = result.get('pulse_info', {})
    pulse_count = pulse_info.get('count', 0)
    
    if pulse_count > 0:
        # Construct data payload for the Wazuh manager event loop
        msg = {
            "integration": "alienvault-otx",
            "alienvault_otx": {
                "ip": ip_address,
                "pulse_count": pulse_count,
                "pulses": [pulse.get('name') for pulse in pulse_info.get('pulses', [])[:3]],
                "source_alert_id": alert_json.get('id')
            }
        }
        # Write the threat intelligence match to the integrations log
        with open('/var/ossec/logs/integrations.log', 'a') as log_f:
            log_f.write(json.dumps(msg) + '
')
except Exception as e:
    with open('/var/ossec/logs/integrations.log', 'a') as log_f:
        log_f.write(json.dumps({"integration": "alienvault-otx", "error": str(e)}) + '
')

sys.exit(0)
```

Set strict ownership so only `root` and `wazuh` group can run the script:

```bash
sudo chown root:wazuh /var/ossec/integrations/custom-alienvault.py
sudo chmod 750 /var/ossec/integrations/custom-alienvault.py
```

To verify permissions, run: `ls -l /var/ossec/integrations/custom-alienvault.py`. You should see: `-rwxr-x--- 1 root wazuh`.

### Configure Wazuh Manager Configuration

Open Wazuh manager configuration:

```bash
sudo nano /var/ossec/etc/ossec.conf
```

Add this code block to the `<ossec_config>` section, replacing `YOUR_OTX_API_KEY` with your OTX API key (if you do not have an OTX API key, create an account at [otx.alienvault.com](https://otx.alienvault.com)):

```xml
  <!-- AlienVault OTX Threat Intelligence Integration -->
  <integration>
    <name>custom-alienvault</name>
    <api_key>YOUR_OTX_API_KEY</api_key>
    <!-- Triggers lookup on any alert level 5 or higher -->
    <level>5</level>
    <alert_format>json</alert_format>
  </integration>
```
It should look something like this:

![ossec config with script added](https://github.com/Mini-mel-eh-fort/Wazuh-and-AlientVault-OTX/blob/main/screenshot.png)


### Add Custom Wazuh Rules

When the Python script writes a JSON match to `/var/ossec/logs/integrations.log`, Wazuh needs custom rules to turn that log line into a dashboard alert.

```bash
sudo nano /var/ossec/etc/rules/local_rules.xml
```

Paste the following XML block:

```xml
<group name="alienvault,threat_intel,">
  <rule id="100100" level="10">
    <decoded_as>json</decoded_as>
    <field name="integration">alienvault-otx</field>
    <description>AlienVault OTX: Malicious IP detected ($(alienvault_otx.ip))</description>
    <mitre>
      <id>T1071</id>
    </mitre>
  </rule>
</group>
```

Verify if the XML block works without error (no output from the command means there are no syntax errors):

```bash
sudo /var/ossec/bin/wazuh-analysisd -t
```

Now restart the Wazuh service:

```bash
sudo systemctl restart wazuh-manager 
```

### Confirm Health of Installation

Confirm the Wazuh service is running and active:

```bash
sudo systemctl status wazuh-manager
```

Ensure the output displays `active (running)` in green text.

---

## Testing & Validation

Trigger the custom script manually with a mock alert containing a known malicious or flagged test IP (e.g., `77.83.39.94`, a known exit node for the Tor network) to confirm communication with AlienVault OTX.

1. **Create a dummy alert file:**

```bash
echo '{"id":"99999","data":{"srcip":"77.83.39.94"}}' | sudo tee /tmp/test_alert.json
```

2. **Run your python script directly passing the test alert path and your API key:**

```bash
sudo /var/ossec/integrations/custom-alienvault.py /tmp/test_alert.json YOUR_OTX_API_KEY
```

3. **Check for log entry:**

```bash
sudo grep "77.83.39.94" /var/ossec/logs/alerts/alerts.json | tail -n 1 
```

You should receive a result. If not, try checking AlienVault to swap the IP address with another currently known active threat.

4. **Clean up the test file:**

```bash
sudo rm /tmp/test_alert.json
```
