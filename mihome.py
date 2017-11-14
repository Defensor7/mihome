__author__ = 'lxl'
#!/usr/bin/python
# -*- coding: utf-8 -*-

from connector import *
import os
import paho.mqtt.client as mqtt
import json
import sys
import datetime
from Crypto.Cipher import AES
import binascii
import logging

if sys.version_info >= (3,0):
    import configparser as ConfigParser  # Python 3+
    import _thread as thread
else:
    import ConfigParser  # Python 2.7
    import thread

try:
    reload(sys)  # Python 2.7
    sys.setdefaultencoding('UTF8')
except NameError:
    try:
        from importlib import reload  # Python 3.4+
    except ImportError:
        from imp import reload  # Python 3.0 - 3.3

debug_mode = 0
logger = None
MQTT_QOS = 0
MQTT_RETAIN = False
subscribed_channels = set()
published_channels = set()

IV = bytearray([0x17, 0x99, 0x6d, 0x09, 0x3d, 0x28, 0xdd, 0xb3, 0xba, 0x69, 0x5a, 0x2e, 0x6f, 0x58, 0x56, 0x2e])

def printf(*args):
    together = ' '.join(map(str, args))    # avoid the arg is not str
    return together

def log(*args):
    if logger is not None:
        logger.info(printf(*args))
    else:
        d = datetime.datetime.now()
        print(d.strftime("%Y-%m-%d %H:%M:%S"), *args)
    return

# The callback for when the client receives a CONNACK response from the server.
def on_connect(client, userdata, flags, rc):
    log("Connected with result code "+str(rc))
    # Subscribing in on_connect() means that if we lose the connection and
    # reconnect then subscriptions will be renewed.
    #client.subscribe("xiaomi/test")

# The callback for when a PUBLISH message is received from the server.
def on_message(client, userdata, msg):
    log("Topic: ", msg.topic+'\nMessage: '+str(msg.payload))
    items = msg.topic.split('/')
    device_model = items[1]
    device_name = items[2]
    sid = items[3]
    device_channel = items[4]
    gateway_address = userdata[1][sid]['gateway_address']
    token = userdata[0][userdata[1][sid]['gateway_sid']]

    log(userdata[2])
    log(type(userdata[2]))
    user_key = userdata[2][str(gateway_address)]

    log("User key:", user_key)

    aes = AES.new(user_key, AES.MODE_CBC, str(IV))

    ciphertext = aes.encrypt(token)

    write_key = binascii.hexlify(ciphertext)
    if msg.payload == "1":
        command = "on"
    elif msg.payload == "0":
        command = "off"
    else:
        command = "unknown"

    write_command = {"cmd":"write",
                     "model":device_model,
                     "sid":sid,
                     "short_id":4343,
                     "data":{device_channel:command,"key":write_key}}
    userdata[3].send_command(write_command, gateway_address, 9898)
    if debug_mode > 0:
        log(write_command)


def prepare_mqtt(MQTT_SERVER, MQTT_PORT=1883):
    client = mqtt.Client()
    client.on_connect = on_connect
    client.on_message = on_message
    client.connect(MQTT_SERVER, MQTT_PORT, 60)
    return client

def push_data(client, model, sid, cmd, data, id2name, PATH_FMT):
    for key, value in data.items():
        if sid in id2name:
            dname = id2name[sid]
            if sys.version_info < (3,0):
                dname = dname.decode('utf8')
        else:
            dname = sid
        path = PATH_FMT.format(model=model,
                             name=dname,
                             sid=sid,
                             cmd=cmd,
                             prop=key)

        client.publish(path, payload=str(value).upper(), qos=MQTT_QOS, retain=MQTT_RETAIN)
        if path not in published_channels:
            log("Published to:", path)
            published_channels.add(path)
        elif debug_mode > 0:
            log("Updated:", path)

        if model in ['plug', 'ctrl_neutral2', 'ctrl_neutral1']:
            if path in subscribed_channels:
                pass
            else:
                log("Subscribed to:", path + "/command")
                client.subscribe(path + "/command")
                subscribed_channels.add(path)

def ConfigSectionMap(Config, section):
    dict1 = {}
    options = Config.options(section)
    for option in options:
        try:
            dict1[option] = Config.get(section, option)
            if dict1[option] == -1:
                log("skip: %s" % option)
        except:
            log("Exception on %s!" % option)
            dict1[option] = None
    return dict1

if __name__ == "__main__":
    id2name = dict()
    Config = ConfigParser.ConfigParser()

    script_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), '')
    script_name = os.path.basename(__file__)
    script_ini = script_path + os.path.splitext(script_name)[0]+'.ini'

    log('Read settings from:', script_ini)
    Config.read(script_ini)

    mqtt_cfg = ConfigSectionMap(Config, "MQTT")
    log_file = mqtt_cfg.get('log', '')
    if log_file != '':
        logger = logging.getLogger('mihome')
        hdlr = logging.FileHandler(log_file)
        formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
        hdlr.setFormatter(formatter)
        logger.addHandler(hdlr) 
        logger.setLevel(logging.INFO)

    debug_mode = int(mqtt_cfg.get('debug', 0))
    MQTT_QOS = int(mqtt_cfg.get('qos', 0))
    tmp = int(mqtt_cfg.get('retain', 0))
    if tmp > 0:
        MQTT_RETAIN = True
    else:
        MQTT_RETAIN = False
    MQTT_SERVER = mqtt_cfg['server']
    MQTT_PORT = int(mqtt_cfg['port'])
    PATH_FMT =  mqtt_cfg['mqtt_path']
    devices = ConfigSectionMap(Config, "devices")['sub_devices']
    if not sys.version_info >= (3,0):
        devices = devices.decode('utf-8')
    user_key = Config._sections['user_key']
    data = json.loads(devices)
    for i in data:
        id2name[i['did'].split('.')[1]] = i['name']
    client = prepare_mqtt(MQTT_SERVER, MQTT_PORT)
    #model, sid, cmd, data, gateway
    cb = lambda m, s, c, d: push_data(client, m, s, c, d, id2name, PATH_FMT)

    connector = XiaomiConnector(data_callback=cb, debug_mode=debug_mode, log_callback=log)
    node_list = connector.get_nodes()
    #log(node_list)
    #p = connector.send_whois()

    for node in node_list:
        if node_list[node]["model"] == "gateway":
            pass
        else:
            connector.request_current_status(node, node_list[node]['gateway_address'])
    try:
        thread.start_new_thread(client.loop_forever, ())

    except:
        log("Exception: Unable to start thread")
    log("Start listenning")
    while True:
        connector.check_incoming()

        client.user_data_set((connector.get_token(),node_list,user_key,connector))
        #log(connector.get_token())