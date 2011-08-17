'''
Example for encrypted, signed messages on MQTT topics.

First, the HMAC-SHA1 is verified to match, and if so, the message is decrypted using our private key

@author: karlp@remake.is
'''

import hashlib
import hmac
import logging
import M2Crypto.RSA
import mosquitto

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s - %(message)s")
log = logging.getLogger("main")

# Shared key is used for signing, say, one key per client
shared_key = "karl_loves_you"
# private key is used so that only we can decrypt, all clients encrypt with our public key
private_key = M2Crypto.RSA.load_key("/home/karlp/karl.test.private.nopf.key")
log.info("Ok, key loaded ok: %d bits", len(private_key))

def on_connect(rc):
    log.info("Connected")

def on_message(msg):
    """
    Looks for messages on topics like blahblah/signed/<hex_hmac_key_here>
    or, blablah/encrypted/signed/<hex_hmac_key_here>
    """
    log.info("Received message on topic %s, length: %d bytes", msg.topic, msg.payloadlen)

    # Ugly. See http://stackoverflow.com/questions/7082788/efficiently-turning-a-ctypes-lp-c-ubyte-into-a-pyhon-str
    payload_bytes = ''.join(chr(msg.payload[i]) for i in xrange(msg.payloadlen)) 
    if "/signed/" in msg.topic:
        log.debug("message is signed! will attempt to verify, msg is: <%s>", payload_bytes)
        topic_remainder, sig = msg.topic.rsplit('/', 1)
        log.debug("sig is: <%s>", sig)
        rsig = hmac.new(shared_key, payload_bytes, hashlib.sha1).hexdigest()
        if rsig == sig:
            log.info("Signatures match, message appears genuine")
        else:
            log.warn("rsig != sig! message was tampered: %s != %s", rsig, sig)
            return

    if "/encrypted/" in msg.topic:
        log.debug("received encrypted message, attempting to decode with private shared_key")
        clear_text = private_key.private_decrypt(payload_bytes, M2Crypto.RSA.pkcs1_oaep_padding)
        log.info("Decrypted message: <%s>", clear_text)
    else:
        log.info("Message is: <%s>", payload_bytes)

def doit():
    #create a client object
    mqttc = mosquitto.Mosquitto("python_sub_karl_1234")
    
    #define the callbacks
    mqttc.on_message = on_message
    mqttc.on_connect = on_connect
    mqttc.connect("localhost", 1883, 60, True)
    mqttc.subscribe("#", 2)
    
    #keep connected to broker
    while mqttc.loop() == 0:
        pass
    
    
if __name__ == "__main__":
    doit()
