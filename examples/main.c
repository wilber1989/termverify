#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <openssl/sha.h>
#include <openssl/rsa.h>
#include <cjson/cJSON.h>

#include <mqtt.h>
#include <base64.h>
#include "templates/posix_sockets.h"

/*获取订阅消息变量*/
char rev_msg[512];

/*创建pem文件*/
int createkeyfile()
{
    RSA *rsa= RSA_new();
    BIGNUM *bne=BN_new();
    BN_set_word(bne,RSA_F4);
    RSA_generate_key_ex(rsa,512,bne,NULL);
    RSA* pub = RSAPublicKey_dup(rsa);
    RSA* pri = RSAPrivateKey_dup(rsa);  
   	FILE *pub_file,*pri_file;
    if (NULL == rsa)
    {
        printf("RSA not initial.\n");
        return 0;
    }
    //RSA_print_fp(stdout, rsa,5);
    pub_file = fopen("/home/zwl/桌面/terminal verification/examples/dpubkey.key","w");
	pri_file = fopen("/home/zwl/桌面/terminal verification/examples/dprikey.key","w");
    if (NULL == pub_file||NULL == pri_file)
    {
        printf("create file 'key' failed!\n");
        return 0;
    }
    PEM_write_RSAPublicKey(pub_file, pub, NULL, NULL, 512, NULL, NULL);
  	PEM_write_RSAPrivateKey(pri_file, pri, NULL, NULL, 512, NULL, NULL);
    fclose(pub_file);
    fclose(pri_file);
    RSA_free(rsa);
    return 1;
 }

/*读取pem文件*/
int getdpubkey()
{
    //RSA *rsa2;
    FILE *file;
    char buffer[512];
    file = fopen("/home/zwl/桌面/terminal verification/examples/dpubkey.key", "r");
    if (NULL == file)
    {
        printf("open file 'pubkey.key' failed!\n");
    }
    //PEM_read_RSAPrivateKey(file,&rsa, NULL, NULL);
    //RSA_print_fp(stdout, rsa, 5);
    //printf("\n\n");
    fseek(file, 0, SEEK_END);
	int length = ftell(file);
	fseek(file, 0, SEEK_SET);
    fread(buffer, sizeof(char), length, file);
    printf("%s\n\n", buffer);
    fclose(file);
    file=NULL;
    return 0;
}

void exit_example(int status, int sockfd, pthread_t *client_daemon)
{
    if (sockfd != -1) close(sockfd);
    if (client_daemon != NULL) pthread_cancel(*client_daemon);
    exit(status);
}

void publish_callback(void** unused, struct mqtt_response_publish *published) 
{
  
}

void publish_callback2(void** unused, struct mqtt_response_publish *published) 
{
    /* note that published->topic_name is NOT null-terminated (here we'll change it to a c-string) */
    char* topic_name = (char*) malloc(published->topic_name_size + 1);
    memcpy(topic_name, published->topic_name, published->topic_name_size);
    topic_name[published->topic_name_size] = '\0';
    usleep(2000000U);
    //printf("-------------------------------\n");
    //printf("Listening for messages.\n");
    //printf("-------------------------------\n");
    //usleep(2000000U);
    printf("\033[1m\033[45;32主题('%s')最新消息:\n %s\033[0m\n", topic_name, (const char*) published->application_message);
    strcpy(rev_msg,(const char*) published->application_message);
    free(topic_name);
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
int main(int argc, const char *argv[]) 
{
    printf("----------------------------------------\n");
    printf("\033[1m\033[45;33m终端设备认证、度量演示程序\033[0m\n");
    printf("----------------------------------------\n");
    printf("\033[1m\033[45;33mPress ENTER to start.\033[0m\n");
    printf("----------------------------------------\n");
    printf("\033[1m\033[45;33mPress CTRL+D to exit.\033[0m\n");
	printf("----------------------------------------\n");
    
    
	if(fgetc(stdin) == '\n') 
	{
		printf("\033[1m\033[45;33m[1] 创建设备密钥对,展示设备公钥:\033[0m\n\n");
		usleep(2000000U);
		//createkeyfile();
		getdpubkey();
		usleep(2000000U);
	}

    /*读取产品私钥*/
    FILE *ppri_file;
    RSA *ppri= RSA_new();
    ppri_file = fopen("/home/zwl/桌面/terminal verification/examples/pprikey.key", "r");
    if (NULL == ppri_file)
    {
        printf("open file 'pprikey.key' failed!\n");
        return -1;
    }
    PEM_read_RSAPrivateKey(ppri_file,&ppri, NULL, NULL);
    fclose(ppri_file);
    ppri_file=NULL;

    /*读取设备公钥*/
    FILE *dpub_file;
    RSA *dpub= RSA_new();
    dpub_file = fopen("/home/zwl/桌面/terminal verification/examples/dpubkey.key", "r");
    if (NULL == dpub_file)
    {
        printf("open file 'dpubkey.key' failed!\n");
        return -1;
    }
    PEM_read_RSAPublicKey(dpub_file,&dpub, NULL, NULL);
    //RSA_print_fp(stdout, dpub, 5);
    fclose(dpub_file);
    dpub_file=NULL;

    /*提取设备公钥n和e*/
    BIGNUM *bne=BN_new();
	BIGNUM *bnn=BN_new();
	char *dpub_n = BN_bn2hex(dpub->n);
	char *dpub_e = BN_bn2hex(dpub->e);
	//printf("%s\n",dpub_n);
	//printf("%s\n",dpub_e);
    RSA_free(dpub);//删除公钥结构体

	/*创建json并摘要*/
    cJSON *root;   
    root=cJSON_CreateObject();
	cJSON_AddStringToObject(root,"flag","register");
	cJSON_AddStringToObject(root,"deviceid","chislab1"); 
	cJSON_AddStringToObject(root,"pub_e",dpub_e);
	cJSON_AddStringToObject(root,"pub_n",dpub_n);
	char* json1 = cJSON_Print(root);

	unsigned char digest1[SHA_DIGEST_LENGTH];
    SHA_CTX ctx1;
    SHA1_Init(&ctx1);
    SHA1_Update(&ctx1, json1, strlen(json1));
    SHA1_Final(digest1, &ctx1);
	
	/*加密设备ID及设备公钥n和e*/
	unsigned char cipper[512]={0};
    size_t outl=512;
    outl=RSA_private_encrypt(SHA_DIGEST_LENGTH,(const unsigned char*)digest1,cipper,ppri, RSA_PKCS1_PADDING);
	RSA_free(ppri);//删除私钥结构体
    char shString[512*2+1];
    for (unsigned int i = 0; i < outl; i++)
    sprintf(&shString[i*2], "%02x", (unsigned int)cipper[i]);
    //printf("\033[1m\033[45;33m%s\033[0m\n\n",shString);
	cJSON_AddStringToObject(root,"sign",shString);
    //printf("shString:%s\n",shString);
    //printf("shString(length):%ld\n",strlen(shString));
	char* json1_1 = cJSON_Print(root);
	printf("\033[1m\033[45;33m[2] 产品私钥对设备ID及设备公钥签名sign:\033[0m\n\n");
	usleep(2000000U);
	printf("%s\n\n",shString);
	usleep(2000000U);

	/*建立socket并发布*/
    const char* addr;
    const char* port;
    const char* topic;
    /* get address (argv[1] if present) */
    if (argc > 1) {
        addr = argv[1];
    } else {
        //addr = "218.89.239.8";
        addr = "127.0.0.1";
        //addr = "192.168.31.246";
        //addr = "192.168.31.185";
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
        //topic = "devices/TC/measurement";
        topic = "devices/measurement/register";
    }

    /* open the non-blocking TCP socket (connecting to the broker) */
    int sockfd = open_nb_socket(addr, port);
    if (sockfd == -1) {
        perror("Failed to open socket: ");
        exit_example(EXIT_FAILURE, sockfd, NULL);
    }
    fcntl(sockfd, F_SETFL, fcntl(sockfd, F_GETFL) | O_NONBLOCK);

    /* setup a client */
    struct mqtt_client client;
    uint8_t sendbuf[2048]; /* sendbuf should be large enough to hold multiple whole mqtt messages */
    uint8_t recvbuf[1024]; /* recvbuf should be large enough any whole mqtt message expected to be received */
    mqtt_init(&client, sockfd, sendbuf, sizeof(sendbuf), recvbuf, sizeof(recvbuf), publish_callback2);
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
     /* publish the register */       
    //while(fgetc(stdin) == '\n') {
        mqtt_publish(&client, topic, json1_1, strlen((const char *)json1_1), MQTT_PUBLISH_QOS_0);   
        printf("\033[1m\033[45;33m[3]终端发布消息:\033[0m\n\n");
        usleep(2000000U);
	    printf("%s\n\n",json1_1);
    //}
    //while(fgetc(stdin) != EOF); 
    cJSON_Delete(root);
    free(json1_1);
    //usleep(2000000U);
    /*等待获取消息*/
    //while(fgetc(stdin) != '\n') ;
	    if (client.error != MQTT_OK) {
        fprintf(stderr, "error: %s\n", mqtt_error_str(client.error));
        exit_example(EXIT_FAILURE, sockfd, &client_daemon);
        }   
    /* exit */ 
    //exit_example(EXIT_SUCCESS, sockfd, &client_daemon);
    
    /* 订阅通道 */
    sockfd = open_nb_socket(addr, port);
    if (sockfd == -1) {
        perror("Failed to open socket: ");
        exit_example(EXIT_FAILURE, sockfd, NULL);
    }
    fcntl(sockfd, F_SETFL, fcntl(sockfd, F_GETFL) | O_NONBLOCK);

    struct mqtt_client client2;
    uint8_t sendbuf2[2048]; 
    uint8_t recvbuf2[1024]; 
    mqtt_init(&client2, sockfd, sendbuf2, sizeof(sendbuf2), recvbuf2, sizeof(recvbuf2), publish_callback2);
    mqtt_connect(&client2, "subscribing_client", NULL, NULL, 0, NULL, NULL, 0, 400);

    if (client2.error != MQTT_OK) {
        fprintf(stderr, "error: %s\n", mqtt_error_str(client2.error));
        exit_example(EXIT_FAILURE, sockfd, NULL);
    }

    pthread_t client_daemon2;
    if(pthread_create(&client_daemon2, NULL, client_refresher, &client2)) {
        fprintf(stderr, "Failed to start client daemon.\n");
        exit_example(EXIT_FAILURE, sockfd, NULL);

    }
    //mqtt_subscribe(&client2, topic, 0);
    //usleep(2000000U);
    //printf("\033[1m\033[45;33m[4]终端订阅消息:\033[0m\n\n");
    /* start publishing the time */
    printf("\033[1m\033[45;33m[4]监听订阅消息:\033[0m\n\n");
    //usleep(5000000U);
    //printf("%s\n", rev_msg);
    while(fgetc(stdin) != EOF); 
    //while(fgetc(stdin) != '\n') ;
    /*判断返回数据*/
    //while(rev_msg==NULL);

    /*获取返回数据，验证hash，用平台公钥解密比对是否一致*/
    //memset(rev_msg,0,512); 
    //strcpy(rev_msg,"{\"flag\":\"register_res\",\"status\":\"success\",\"sign\":\"xxxx\"}");
    cJSON *root_rev,*root_revsign;   
    root_rev = cJSON_CreateObject();
    root_revsign = cJSON_CreateObject();
    root_rev = cJSON_Parse((const char *)rev_msg);
    root_revsign = cJSON_GetObjectItem(root_rev,"sign");
    char* sign_rev =cJSON_Print(root_revsign );
    cJSON_DeleteItemFromObject(root_rev,"sign");
    char* veri_rev = cJSON_Print(root_rev);
    printf("sign_rev:%s\n", sign_rev);
    printf("sign_rev(length):%ld\n", strlen(sign_rev)-2);
    //printf("veri_rev:%s\n", veri_rev);
    unsigned char digest_veri[SHA_DIGEST_LENGTH];
    SHA_CTX ctx_veri;
    SHA1_Init(&ctx_veri);
    SHA1_Update(&ctx_veri, veri_rev, strlen(veri_rev));
    SHA1_Final(digest_veri, &ctx_veri);
    //printf("digest_veri:%s\n", digest_veri);

    /*读取平台公钥*/
    FILE *platpub_file;
    RSA *platpub= RSA_new();
    platpub_file = fopen("/home/zwl/桌面/terminal verification/examples/ppubkey.key", "r");
    if (NULL == platpub_file)
    {
        printf("open file 'platpubkey.key' failed!\n");
        return -1;
    }
    PEM_read_RSAPublicKey(platpub_file,&platpub, NULL, NULL);
    RSA_print_fp(stdout, platpub, 5);
    fclose(platpub_file);
    platpub_file=NULL;
    const char * a ="62dd908de8044f9fed88ee700213f5229ae62b88856e3c27fbac4c4508bb53f0";
    unsigned char newplain[512]={0};
    size_t outl2 = RSA_public_decrypt(strlen(sign_rev)-2,(const unsigned char *)sign_rev, newplain, platpub, RSA_NO_PADDING);
    char newplain_String[512*2+1];
    for (unsigned int i = 0; i < outl2; i++)
    sprintf(&newplain_String[i*2], "%02x", (unsigned int)newplain[i]);
    printf("newplain_String:%s\n", newplain_String);

    usleep(2000000U);
    //printf("%s\n", rev_msg);
    if (strstr(rev_msg,"BIOS")!=0)
        printf("\033[1m\033[45;33m[5]设备验证成功success!\033[0m\n");
    else{
        printf("\033[1m\033[45;33m[5]设备验证失败failed!\033[0m\n");
        return 0;
        }    
    /* block */
    while(fgetc(stdin) != EOF);
    //usleep(2000000U);
    //mqtt_publish(&client, topic, "1111111111111111111", 25, MQTT_PUBLISH_QOS_0);
    //usleep(8000000U);
    //mqtt_subscribe(&client, topic, 0);
   	/* check for errors */

    return 0;
}

