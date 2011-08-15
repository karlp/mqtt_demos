/* 
 * Basic demo of sending HMAC signed messages to an MQTT server
 * 
 * The message HMAC is calculated, and put in the topic, like so
 * /demo/signed/<hmac_signature_here>
 * 
 * Karl Palsson <karlp@remake.is>
 * 
 * Takes two optional arguments, the MQTT server host, and the shared key
 * Default MQTT host is localhost
 * Default shared key is "karl_loves_you"
 * 
 * Released into the public domain as demonstration code
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>

#include <mosquitto.h>
#include <openssl/err.h>
#include <openssl/hmac.h>

#include "uglylogging.h"

#define LOG_TAG __FILE__
#define DLOG(format, args...)         ugly_log(UDEBUG, LOG_TAG, format, ## args)
#define ILOG(format, args...)         ugly_log(UINFO, LOG_TAG, format, ## args)
#define fatal(format, args...)        ugly_log(UFATAL, LOG_TAG, format, ## args)

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
int send_signed_message(time_t tt, char *shared_key) {

    // Make message...
    char data[200];
    sprintf(data, "Signed Message with sequence: %ld", tt);

    DLOG("pub SIGNED: %s\n", data);
    unsigned char* hmac;
    unsigned int result_len;

    // printf "%s" "message to be signed..." | openssl sha1 -hmac "karl_hmac_key"
    hmac = HMAC(EVP_sha1(), shared_key, strlen(shared_key), (unsigned char*)data, strlen(data), NULL, &result_len);
    if (hmac == NULL) {
        fatal("Couldn't sign the message: %s\n", ERR_error_string(ERR_get_error(), NULL));
    }
    
    // Add signature to message
    char topic[60];
    char *tmp = &topic[0];
    tmp += sprintf(topic, "demo/signed/");
    int i;
    for (i = 0; i < result_len; i++) {
        sprintf(tmp + (i*2), "%02x", hmac[i]);
    }
    i = mosquitto_publish(mosq, NULL, topic, strlen(data), (unsigned char*)data, 0, false);
    if (i != MOSQ_ERR_SUCCESS) {
        fatal("Failed to publish message: %d\n", i);
    }
    return 0;
}

int send_insecure_message(time_t tt) {
    char msg[128];
    sprintf(msg, "Insecure Message with sequence: %ld", tt);
    mosquitto_publish(mosq, NULL, "demo/insecure", strlen(msg), (unsigned char*)msg, 0, false);
    DLOG("pub unsigned: %s\n", msg);
    return 0;
}

void run_tasks() {
    mosquitto_loop(mosq, -1);
    // anything else we like here....

    time_t tt = time(NULL);
    if ((long int) tt > last_message_time + 2) {
        last_message_time = tt;
        send_insecure_message(tt);
        send_signed_message(tt, key);
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

