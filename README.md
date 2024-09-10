# scanner

Tool for machine discovery and fleet monitoring

## Install

```
git clone git@github.com:NoHackMe05/scanner.git

cd scanner
```

### Sniffer

```
sudo dpkg -i sniffer/nhm-sniffer_1.0_amd64.deb
```

### Agents

- agent_linux
- agent_mac
- agent_raspberry_pi
- agent_raspberry_pi2
- agent_raspberry_pi3
- agent_windows.exe

### Scanner

Requires Nmap installation:

```
sudo apt update
sudo apt install nmap
```

Installing Python packages (root) :

```
python3 -m venv mon_env
source mon_env/bin/activate
pip install -r requirements.txt
deactivate
```

## Usage

### Sniffer

The sniffer runs as a service. Here are the useful paths and files:

- /opt/nohackme/nhm-sniffer : main C program
- /etc/nohackme/nhm_sniffer.conf : configuration file
- /tmp/nohackme_sniffer.ipc : zmq communication
- /tmp/nohackme_sniffer_pub.ipc : zmq communication
- /var/log/nhm_sniffer.log : log file

### Agents

Copy the agent adapted to the platform onto client machines. Then launch the client manually (or install it via an Ansible or Saltstack script).

#### The configuration file

```
cp config.json.example config.json
```

The configuration file allows you to:

- Set interfaces and subnets to be scanned
- Configure sniffer (zmq files and filter to be applied)
- Enable debug mode
- Define Nmap mode (basic, advanced, aggressive)
- Name of json output file
- Scan interval
- Number of threads

### Scanner

You'll need to run the program in root mode (because of the ARP scan). Go to root then :

```
source mon_env/bin/activate
python network-scanner.py -c config.json
deactivate
```

To stop the scan: Ctrl + C

If no argument is passed, the default config.json file is used. The argument allows different configurations depending on the infrastructure.

## TODO

This tool is currently under development

- Securing ZMQ communications
- Replace Nmap with an unlicensed port scanner
- Enhance existing scanners (LDAP, SSH, etc.)
- Add exploit tests

## DISCLAIMER

This tool is to be used on your own infrastructure or with the agreement of a customer. Make sure you are aware of the legal requirements before using it. This tool has been created for educational purposes.
