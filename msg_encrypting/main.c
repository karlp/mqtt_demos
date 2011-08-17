/* 
 * Basic demo of public key encrypting messages, then signing using a shared key,
 * then finally publishing to an MQTT server.
 * 
 * three messages are sent every second or so...
 * * demo/insecure   - plain text of message
 * * demo/insecure/signed/<hmac_signature> - signed, but clear text
 * * demo/encrypted/signed/<hmac_signature> - encrypted, then signed
 * 
 * Karl Palsson <karlp@remake.is>
 * 
 * Takes two optional arguments, the MQTT server host, and the shared key
 * Default MQTT host is localhost
 * Default shared key is "karl_loves_you"
 * the public key is embedded in the code below...
 * 
 * Released into the public domain as demonstration code
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>

#include <mosquitto.h>
#include <openssl/err.h>
#include <openssl/hmac.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>

#include "uglylogging.h"

#define LOG_TAG __FILE__
#define DLOG(format, args...)         ugly_log(UDEBUG, LOG_TAG, format, ## args)
#define ILOG(format, args...)         ugly_log(UINFO, LOG_TAG, format, ## args)
#define fatal(format, args...)        ugly_log(UFATAL, LOG_TAG, format, ## args)

// Just a sample public key
#define PUBLIC_KEY_PEM \
"-----BEGIN PUBLIC KEY-----\n" \
"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxKMFS0eoDxn6YltlCM4P\n" \
"uIHK1bp3+7Lt0aWZ9rimjd4uvx49ZYT1DKrUZi96rUkzdJuCqtYbFtUVAy0V5AtZ\n" \
"EtQGRoZBN5JQ9u80I8NNS4jhtHZU2i6CY9Aeb6KHY790ceD+lMCbXCgrtl1yPUVE\n" \
"s8pFwEwO2Vqjim2pO0iVsAzUJAyppjn/7FjxyqOHZHL+OPi7vNule1V9OdVrb9m3\n" \
"mHVy3u9LWdA+3Ch/YJe8FgenRncQEVrDbA/0wHlRE5fH+nQ9OwPTDYP6A6pphAbk\n" \
"ZUhc9VjIDKrTCQP2o4RDLz0OKyBs5xZc7vjGXpHG+kL3OVpHxpSrK9EVGIX65ofN\n" \
"9QIDAQAB\n"  \
"-----END PUBLIC KEY-----"

/**
 * Load in a public key, remember to call RSA_free when you're done!
 * @return 
 */
RSA *rsa_get_public_key() {
    BIO *bp = BIO_new_mem_buf(PUBLIC_KEY_PEM, -1); // Create a new memory buffer BIO
    RSA *key = PEM_read_bio_RSA_PUBKEY(bp, 0, 0, 0); // And read the RSA key from it
    if (!key) {
        fatal("failed to read pubkey: %s", ERR_error_string(ERR_get_error(), NULL));
    }
    BIO_free(bp);
    return key;
}

struct mosquitto* mosq;
char *key;
long int last_message_time;

int setup_mq(const char* host) {
    int mq_maj, mq_min, mq_rev;
    mosquitto_lib_version(&mq_maj, &mq_min, &mq_rev);
    DLOG("You've got mosquitto version major:%d, minor:%d, rev:%d\n", mq_maj, mq_min, mq_rev);
    mosquitto_lib_init();
    pid_t pid = getpid();
    char clientid[40];

    snprintf(clientid, sizeof (clientid), "rme_signed_demo_%d", pid);
    mosq = mosquitto_new(clientid, NULL);

    ILOG("Connecting to %s\n", host);
    mosquitto_connect(mosq, host, 1883, 15, true);
    return 0;
}

/**
 * Demonstrate sending a signed (HMAC) and then encrypted message to MQTT
 * @param tt just something that varies between messages, so we can see it when decrypted
 * @return 
 */
int send_signed_message(char *topic_base, const unsigned char *msg_to_sign, uint32_t msg_len, char *shared_key) {

    //DLOG("pub SIGNED: %s\n", msg_to_sign);
    unsigned char* hmac;
    unsigned int result_len;

    // printf "%s" "message to be signed..." | openssl sha1 -hmac "karl_hmac_key"
    hmac = HMAC(EVP_sha1(), shared_key, strlen(shared_key), msg_to_sign, msg_len, NULL, &result_len);
    if (hmac == NULL) {
        fatal("Couldn't sign the message: %s\n", ERR_error_string(ERR_get_error(), NULL));
    }

    // Add signature to message
    char topic[100];
    assert(sizeof topic > strlen(topic_base) + result_len * 2);
    char *tmp = &topic[0];
    tmp += sprintf(topic, "%s", topic_base);
    int i;
    for (i = 0; i < result_len; i++) {
        sprintf(tmp + (i*2), "%02x", hmac[i]);
    }
    i = mosquitto_publish(mosq, NULL, topic, msg_len, msg_to_sign, 0, false);
    if (i != MOSQ_ERR_SUCCESS) {
        fatal("Failed to publish message: %d\n", i);
    }
    return 0;
}

int send_insecure_message(void *msg, uint32_t msg_len) {
    mosquitto_publish(mosq, NULL, "demo/insecure", msg_len, msg, 0, false);
    DLOG("pub unsigned: %s\n", msg);
    return 0;
}

int encrypt_message(unsigned char **encrypted, unsigned char *clear, uint32_t clear_len) {

    RSA *pubkey = rsa_get_public_key();
    int rsa_size = RSA_size(pubkey);
    assert(clear_len < rsa_size - 41);  // 41 is the padding size for RSA_PKCS1_OAEP_PADDING
    ILOG("rsa size = %d\n", rsa_size);
    *encrypted = malloc(RSA_size(pubkey));
    uint32_t encrypted_len = RSA_public_encrypt(clear_len, clear, *encrypted, pubkey, RSA_PKCS1_OAEP_PADDING);
    RSA_free(pubkey);
    if (encrypted_len == -1) {
        fatal("Failed to encrypt data. %s", ERR_error_string(ERR_get_error(), NULL));
    }
#if 0 
    // base64 encode the encrypted text to stdout....
    // might be nice to have this as an option 
    BIO *bio, *b64;
    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new_fp(stdout, BIO_NOCLOSE);
    bio = BIO_push(b64, bio);
    BIO_write(bio, *encrypted, encrypted_len);
    BIO_flush(bio);
    BIO_free_all(bio);
#endif
    
    return encrypted_len;
}

void run_tasks() {
    mosquitto_loop(mosq, -1);
    // anything else we like here....

    time_t tt = time(NULL);
    if ((long int) tt > last_message_time + 2) {
        last_message_time = tt;
        char msg_orig[400];
        sprintf(msg_orig, "This is a plain message: %ld", tt);
        send_insecure_message(msg_orig, strlen(msg_orig));
        send_signed_message("demo/insecure/signed/", (unsigned char*)msg_orig, strlen(msg_orig), key);
        
        unsigned char *msg_encrypted;
        uint32_t msg_encrypted_len = encrypt_message(&msg_encrypted, (unsigned char*)msg_orig, strlen(msg_orig));
        send_signed_message("demo/encrypted/signed/", msg_encrypted, msg_encrypted_len, key);
        free(msg_encrypted);
    }
    sleep(1);
}

/*
 * Do mad wild shit that makes us metric boatloads of cash money
 */
int main(int argc, char** argv) {
    ugly_init(99);

    if (argc < 2) {
        DLOG("(pass a mq host as argument, otherwise we use localhost)\n");
        setup_mq("localhost");
    } else {
        DLOG("Connecting to %s\n", argv[1]);
        setup_mq(argv[1]);
    }
    if (argc < 3) {
        key = "karl_loves_you";
        DLOG("using default shared key of %s\n", key);
    } else {
        key = argv[2];
        DLOG("using supplied shared key of %s\n", key);
    }

    while (1) {
        run_tasks();
    }

    return (EXIT_SUCCESS);
}

