# MiHome - MQTT bridge 

A lot of the codes come from https://github.com/illxi/mihome

Requirements: Turn on developer mode on Xiaomi Aqara Gateway. (from the Android Mi Home app)

## Modications

* Log file with all messages can be specified in INI file.
* Additional MQTT parameters for published data (QoS, Retain).
* Python 3 compatibility.
* System daemon script.

## How to install on Raspberry Pi or Banana Pi

```bash
$ sudo su
$ pip3 freeze --local | grep -v '^\-e' | cut -d = -f 1  | xargs -n1 pip3 install -U
$ pip3 install ConfigParser
$ pip3 install paho-mqtt
$ pip3 install pycrypto
$ chmod 0755 mihome.sh
$ cp mihome.sh /etc/init.d
$ update-rc.d mihome.sh defaults
$ service mihome start
```

## How to start/stop the daemon

$ sudo service mihome start

Special thanks go to http://pvto.info.
