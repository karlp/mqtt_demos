'''
Example for verifying HMAC-SHA1 signed messages on MQTT topics.

By calculating the HMAC over the entire message body, we can be sure that the message has not been 
tampered with, and was produced by someone who knows the shared secret.

Anyone can still read the message of course, and messages can be replayed at will and still 
appear genuine.  Timestamps and only accepting messages from the "recent" past can help with that

@author: karlp@remake.is
'''

import hashlib
import hmac
import logging
logging.basicConfig(level=logging.DEBUG, format="%(asctime)s %(levelname)s %(name)s - %(message)s")
log = logging.getLogger("main")

import mosquitto

def on_connect(rc):
    log.info("Connected")

def on_message(msg):
    """
    Looks for messages on topics like blahblah/signed/>hex_hmac_key_here<
    """
    log.info("Received message on topic %s, length: %d bytes", msg.topic, msg.payloadlen)

    if "/signed/" in msg.topic:
        log.debug("message is signed! will attempt to verify, msg is: <%s>", msg.payload_str)
        topic_remainder, sig = msg.topic.rsplit('/', 1)
        log.debug("sig is: <%s>", sig)
        key = "karl_loves_you"
        rsig = hmac.new(key, msg.payload_str, hashlib.sha1).hexdigest()
        if rsig == sig:
            log.info("Signatures match, message appears genuine")
        else:
            log.warn("rsig != sig! message was tampered: %s != %s", rsig, sig)

    else:
        log.info("Message is: <%s>", msg.payload_str)

#create a client object
mqttc = mosquitto.Mosquitto("python_sub_karl_1234")

#define the callbacks
mqttc.on_message = on_message
mqttc.on_connect = on_connect

#connect
mqttc.connect("localhost", 1883, 60, True)

#subscribe to topic test
mqttc.subscribe("#", 2)

#keep connected to broker
while mqttc.loop() == 0:
    pass
