
/**
 * @file
 * A simple program to that publishes the current time whenever ENTER is pressed. 
 */
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <openssl/sha.h>
#include <openssl/rsa.h>
#include <cjson/cJSON.h>

#include <mqtt.h>
#include "templates/posix_sockets.h"


/**
 * @brief The function that would be called whenever a PUBLISH is received.
 * 
 * @note This function is not used in this example. 
 */
void publish_callback(void** unused, struct mqtt_response_publish *published);

/**
 * @brief The client's refresher. This function triggers back-end routines to 
 *        handle ingress/egress traffic to the broker.
 * 
 * @note All this function needs to do is call \ref __mqtt_recv and 
 *       \ref __mqtt_send every so often. I've picked 100 ms meaning that 
 *       client ingress/egress traffic will be handled every 100 ms.
 */
void* client_refresher(void* client);

/**
 * @brief Safelty closes the \p sockfd and cancels the \p client_daemon before \c exit. 
 */
void exit_example(int status, int sockfd, pthread_t *client_daemon);

/**
 * A simple program to that publishes the current time whenever ENTER is pressed. 
 */
int main(int argc, const char *argv[]) 
{
    const char* addr;
    const char* port;
    const char* topic;

    /* get address (argv[1] if present) */
    if (argc > 1) {
        addr = argv[1];
    } else {
        addr = "192.168.31.185";
    }

    /* get port number (argv[2] if present) */
    if (argc > 2) {
        port = argv[2];
    } else {
        port = "1883";
    }

    /* get the topic name to publish */
    if (argc > 3) {
        topic = argv[3];
    } else {
        topic = "devices/TC/measurement";
    }

    /* open the non-blocking TCP socket (connecting to the broker) */
    int sockfd = open_nb_socket(addr, port);

    if (sockfd == -1) {
        perror("Failed to open socket: ");
        exit_example(EXIT_FAILURE, sockfd, NULL);
    }

    /* setup a client */
    struct mqtt_client client;
    uint8_t sendbuf[2048]; /* sendbuf should be large enough to hold multiple whole mqtt messages */
    uint8_t recvbuf[1024]; /* recvbuf should be large enough any whole mqtt message expected to be received */
    mqtt_init(&client, sockfd, sendbuf, sizeof(sendbuf), recvbuf, sizeof(recvbuf), publish_callback);
    mqtt_connect(&client, "publishing_client", NULL, NULL, 0, "jane@mens.de", "jolie", 0, 400);

    /* check that we don't have any errors */
    if (client.error != MQTT_OK) {
        fprintf(stderr, "error: %s\n", mqtt_error_str(client.error));
        exit_example(EXIT_FAILURE, sockfd, NULL);
    }

    /* start a thread to refresh the client (handle egress and ingree client traffic) */
    pthread_t client_daemon;
    if(pthread_create(&client_daemon, NULL, client_refresher, &client)) {
        fprintf(stderr, "Failed to start client daemon.\n");
        exit_example(EXIT_FAILURE, sockfd, NULL);

    }

    /* start publishing the time */
    printf("%s is ready to run.\n", argv[0]);
    printf("Press ENTER to publish the current time.\n");
    printf("Press CTRL-D (or any other key) to exit.\n\n");

    FILE *fp1,*fp2;
    char buff1[1024];
    char buff2[1024];
    while(fgetc(stdin) == '\n') {
        /* INPUT bios_image*/
        fp1=fopen("/home/zwl/桌面/bios_image.txt","rb");
        if(fp1==NULL)
        {
            printf("Can't open file\n");
            return 0;
        }
        fread(buff1,1,1024,fp1);
        fclose(fp1);
        fp1=NULL;
        printf("\033[1m\033[45;33m[1] Calculating bios_image hash from:\n/home/zwl/桌面/bios.img\033[0m\n\n");
        usleep(2000000U);
        /* SHA bios_image*/
        unsigned char digest[SHA_DIGEST_LENGTH];
        SHA_CTX ctx;
        SHA1_Init(&ctx);
        SHA1_Update(&ctx, buff1, strlen(buff1));
        SHA1_Final(digest, &ctx);
        char mdString[SHA_DIGEST_LENGTH*2+1];
        for (int i = 0; i < SHA_DIGEST_LENGTH; i++)
        sprintf(&mdString[i*2], "%02x", (unsigned int)digest[i]);
        printf("\033[1m\033[45;33m[2] SHA1 digest of bios_image :\n%s\033[0m\n\n",mdString);
        usleep(2000000U);
        /* INPUT os_image*/
        fp2=fopen("/home/zwl/桌面/os_image.txt","rb");
        if(fp2==NULL)
        {
            printf("Can't open file\n");
            return 0;
        }
        fread(buff2,1,1024,fp2);
        fclose(fp2);
        fp2=NULL;
        printf("\033[1m\033[45;33m[3] Calculating os_image hash from:\n/home/zwl/桌面/os.img\033[0m\n\n");
        usleep(2000000U);
        /* SHA os_image*/
        unsigned char digest2[SHA_DIGEST_LENGTH];
        SHA_CTX ctx2;
        SHA1_Init(&ctx2);
        SHA1_Update(&ctx2, buff2, strlen(buff2));
        SHA1_Final(digest2, &ctx2);
        char mdString2[SHA_DIGEST_LENGTH*2+1];
        for (int i = 0; i < SHA_DIGEST_LENGTH; i++)
        sprintf(&mdString2[i*2], "%02x", (unsigned int)digest2[i]);
        printf("\033[1m\033[45;33m[4] SHA1 digest of os_image :\n%s\033[0m\n\n",mdString2);
        usleep(2000000U);
        /* SHA digest*/
        unsigned char digest3[SHA_DIGEST_LENGTH];
        SHA_CTX ctx3;
        SHA1_Init(&ctx3);
        SHA1_Update(&ctx3, strcat((char *)digest,(char *)digest2), strlen((char *)digest));
        SHA1_Final(digest3, &ctx3);
        char mdString3[SHA_DIGEST_LENGTH*2+1];
        for (int i = 0; i < SHA_DIGEST_LENGTH; i++)
        sprintf(&mdString3[i*2], "%02x", (unsigned int)digest3[i]);
        printf("\033[1m\033[45;33m[5] SHA1 digest of bios&os image :\n%s\033[0m\n\n",mdString3);
        usleep(2000000U);

        /*create publish json data*/
        cJSON *root,*ml,*pcrs,*file1,*file2;   
        root=cJSON_CreateObject();     
 //       cJSON_AddItemToObject(root, "name", cJSON_CreateString("Jack (\"Bee\") Nimble"));   
        cJSON_AddItemToObject(root, "ML", ml=cJSON_CreateObject());  
 //       cJSON_AddStringToObject(fmt,"type",     "rect");   
        cJSON_AddNumberToObject(ml,"length", 2);
        cJSON_AddItemToObject(root, "1", file1=cJSON_CreateObject()); 
        cJSON_AddItemToObject(root, "2", file2=cJSON_CreateObject());

        cJSON_AddStringToObject(file1,"name","BIOS");
        cJSON_AddStringToObject(file1,"sha1",mdString);
        cJSON_AddNumberToObject(file1,"PCR", 1);

        cJSON_AddStringToObject(file2,"name","BIOS");
        cJSON_AddStringToObject(file2,"sha1",mdString2);
        cJSON_AddNumberToObject(file2,"PCR", 1);

        cJSON_AddItemToObject(root, "PCRs", pcrs=cJSON_CreateObject());
        cJSON_AddStringToObject(pcrs,"1",mdString3);
        char* out1 = cJSON_Print(root);//生成json经私钥加密后发布
        //printf("%s\n  %ld",out1,strlen(out1));
        unsigned char digest4[SHA_DIGEST_LENGTH];
        SHA_CTX ctx4;
        SHA1_Init(&ctx4);
        SHA1_Update(&ctx4, out1, strlen(out1));
        SHA1_Final(digest4, &ctx4);

        /*RSA encrypto*/
        printf("\033[1m\033[45;33m[6] Generating RSA key......\033[0m\n\n");
        //usleep(2000000U);
        RSA *rsa = RSA_new();
        BIGNUM *bne=BN_new();
        BN_set_word(bne,RSA_F4);
        RSA_generate_key_ex(rsa,512,bne,NULL);
        //RSA* pub = RSAPublicKey_dup(rsa);
        //RSA* pri = RSAPrivateKey_dup(rsa);
        //RSA_print_fp(stdout, pri, 5);
        //printf("\n");
        usleep(2000000U);
        //RSA_print(stdout, pri, 5);
        unsigned char cipper[1024]={0};
        unsigned char newplain[512]={0};
        size_t outl=512;
        size_t outl2;
        // printf("----------------------------------\n");  
        outl=RSA_private_encrypt(SHA_DIGEST_LENGTH,(const unsigned char*)digest4,cipper,rsa, RSA_PKCS1_PADDING);
        printf("\033[1m\033[45;33m[7] Encrypt publish message with RSA_private_key:\033[0m\n");
        char shString[512*2+1];
        for (unsigned int i = 0; i < outl; i++)
        sprintf(&shString[i*2], "%02x", (unsigned int)cipper[i]);
        printf("\033[1m\033[45;33m%s\033[0m\n\n",shString);
        usleep(2000000U);
        //outl2=RSA_private_decrypt(outl,cipper,newplain,rsa,RSA_PKCS1_OAEP_PADDING);
        //printf("-----------------\n");
        //for(unsigned int i =0;i<outl2;i++) {
        //    printf("%02x",newplain[i]);
        //}
        //printf("\n");

        cJSON_AddStringToObject(root,"sign",shString); 

        char* out = cJSON_Print(root);
        //printf("%s\n",out); 

        printf("\033[1m\033[45;33m[8] Terminal published :\n%s\033[0m\n",out);
        /* publish the time */        
        mqtt_publish(&client, topic, out, strlen((const char *)out) + 1, MQTT_PUBLISH_QOS_0);
        cJSON_Delete(root);
        free(out);
        /* check for errors */
        if (client.error != MQTT_OK) {
            fprintf(stderr, "error: %s\n", mqtt_error_str(client.error));
            exit_example(EXIT_FAILURE, sockfd, &client_daemon);
        }
    }   

    /* disconnect */
    printf("\n%s disconnecting from %s\n", argv[0], addr);
    sleep(1);

    /* exit */ 
    exit_example(EXIT_SUCCESS, sockfd, &client_daemon);
}

void exit_example(int status, int sockfd, pthread_t *client_daemon)
{
    if (sockfd != -1) close(sockfd);
    if (client_daemon != NULL) pthread_cancel(*client_daemon);
    exit(status);
}



void publish_callback(void** unused, struct mqtt_response_publish *published) 
{
    /* not used in this example */
}

void* client_refresher(void* client)
{
    while(1) 
    {
        mqtt_sync((struct mqtt_client*) client);
        usleep(100000U);
    }
    return NULL;
}