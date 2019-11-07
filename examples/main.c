#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include<sys/time.h>

#include <openssl/sha.h>
#include <openssl/rsa.h>
#include <openssl/ssl.h>
#include <cjson/cJSON.h>
#include <mqtt.h>
#include "templates/posix_sockets.h"

/*获取订阅消息变量*/
char rev_msg[512]={0};

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
    PEM_write_RSAPublicKey(pub_file, pub);
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
    /*去掉转换以后的\n\t*/
    unsigned char i=0,j=0;
    while(json1[i] != '\0')
    {
        if(json1[i] != '\n'&&json1[i] != '\t' )  //只有在不是空格的情况下目标才会移动赋值
        {
            json1[j++] = json1[i];
        }
        i++;  //源一直移动
    }
    json1[j] = '\0';
    printf("%s\n",json1);

	unsigned char digest1[SHA_DIGEST_LENGTH];
    SHA_CTX ctx1;
    SHA1_Init(&ctx1);
    //SHA1_Update(&ctx1, json1, strlen(json1));
    //SHA1_Final(digest1, &ctx1);
	SHA1_Update(&ctx1,"12345", strlen("12345"));
    SHA1_Final(digest1, &ctx1);
    for (unsigned int i = 0; i < SHA_DIGEST_LENGTH; i++)
    printf("\033[1m\033[45;33m%02x\033[0m",digest1[i]);
    printf("\033[1m\033[45;33m\n------------\n\033[0m");

	/*加密设备ID及设备公钥n和e*/
	unsigned char cipper[512]={0};
    size_t outl=512;
    unsigned int signlen;
    //outl=RSA_private_encrypt(SHA_DIGEST_LENGTH,(const unsigned char*)digest1,cipper,ppri, RSA_PKCS1_PADDING);
    RSA_sign(NID_sha1, (unsigned char *)digest1,SHA_DIGEST_LENGTH, cipper, (unsigned int *)&signlen,ppri);
    RSA_free(ppri);//删除私钥结构体

    char shString[512*2+1];
    for (unsigned int i = 0; i < signlen; i++)
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
        //addr = "127.0.0.1";
        addr = "192.168.31.246";
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
    mqtt_connect(&client, "terminal_device_publish", NULL, NULL, 0, "jane@mens.de", "jolie", 0, 400);

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
        printf("\033[1m\033[45;33m[3] 终端发布消息:\033[0m\n\n");
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
    mqtt_connect(&client2, "terminal_device_subscribe", NULL, NULL, 0, NULL, NULL, 0, 400);

    if (client2.error != MQTT_OK) {
        fprintf(stderr, "error: %s\n", mqtt_error_str(client2.error));
        exit_example(EXIT_FAILURE, sockfd, NULL);
    }

    pthread_t client_daemon2;
    if(pthread_create(&client_daemon2, NULL, client_refresher, &client2)) {
        fprintf(stderr, "Failed to start client daemon.\n");
        exit_example(EXIT_FAILURE, sockfd, NULL);

    }
    printf("\033[1m\033[45;33m[4] 订阅消息并等待响应.....\033[0m\n\n");
    mqtt_subscribe(&client, topic, 0);
     
    /*判断执行时间，超时10秒未受到消息结束*/ 
    float time_use=0;
    struct timeval start;   
    struct timeval end;
    gettimeofday(&start,NULL);  
    while(1)
    {
    if(rev_msg[0]!=0) break;//获得消息中断循环        
    gettimeofday(&end,NULL);  
    time_use=(end.tv_sec-start.tv_sec)*1000000+(end.tv_usec-start.tv_usec);//微秒         
    if(time_use>=10000000)       
        {           
            printf("\033[1m\033[45;33m[5]等待超时......\033[0m\n\n");
            exit_example(EXIT_SUCCESS, sockfd, &client_daemon);
            exit_example(EXIT_SUCCESS, sockfd, &client_daemon2);
            return 0;        
        }
    }
    //usleep(2000000U);
    //printf("\033[1m\033[45;33m[4]终端订阅消息:\033[0m\n\n");  
    /* start publishing the time */
    printf("\033[1m\033[45;33m[5] 服务器返回消息:\033[0m\n\n");
    usleep(2000000U);
    printf("rev_msg:%s\n\n", rev_msg);
    usleep(2000000U);
    printf("\033[1m\033[45;33m[6]返回数据校验.....\033[0m\n\n");
    usleep(2000000U);
    //while(fgetc(stdin) != EOF); 
    //while(fgetc(stdin) != '\n') ;

    /*获取返回数据，验证hash，用平台公钥解密比对是否一致*/
    //memset(rev_msg,0,512); 
    //strcpy(rev_msg,"{\"flag\":\"register_res\",\"status\":\"success\",\"sign\":\"xxxx\"}");
    //strcpy(rev_msg,json1_1);
    //printf("rev_msg:%s\n", rev_msg);
    cJSON *root_rev,*root_revsign; 
    root_rev = cJSON_CreateObject();
    root_revsign = cJSON_CreateObject();
    root_rev = cJSON_Parse((const char *)rev_msg);
    root_revsign = cJSON_GetObjectItem(root_rev,"sign");
    char sign_rev[128];
    strcpy(sign_rev,root_revsign->valuestring);
    cJSON_DeleteItemFromObject(root_rev,"sign");  
    char* veri_rev = cJSON_Print(root_rev);
    //printf("sign_rev:%s\n", sign_rev);  
    //printf("sign_rev(length):%ld\n", strlen(sign_rev));
    //printf("veri_rev:%s\n", veri_rev);

    /*将签名的16进制字符串转化为普通字符串*/
    //char sign_rev_String[strlen(sign_rev)/2+1];
    //for (unsigned int i = 0; sign_rev[i]!='\0'; i++)
    //sprintf(&sign_rev_String[i*2], "%s", (char *)((sign_rev[2*i]-'0')*16+(sign_rev[2*i]-'0'));
    unsigned int sign_rev_int[128];
    unsigned char sign_rev_char[64];
    for (unsigned int i = 0; sign_rev[i]!='\0'; i++)
    {
    if(sign_rev[i]>='0'&&sign_rev[i]<='9')  
        sign_rev_int[i] = (unsigned int)(sign_rev[i]-'0');
    else if(sign_rev[i]>='a'&&sign_rev[i]<='f')  
        sign_rev_int[i] = (unsigned int)(sign_rev[i]-'a'+10);
    else if(sign_rev[i]>='A'&&sign_rev[i]<='F')  
        sign_rev_int[i] = (unsigned int)(sign_rev[i]-'A'+10);
    else {
        printf("received msg error!\n");
        exit_example(EXIT_SUCCESS, sockfd, &client_daemon);
        exit_example(EXIT_SUCCESS, sockfd, &client_daemon2); 
        return 0;
        }
    }
    for (unsigned int i = 0; i < 64; i++)
        sign_rev_char[i]=(unsigned char)(sign_rev_int[2*i]*16 + sign_rev_int[2*i+1]);
        //printf("%02x",sign_rev_char[i]);
   
    unsigned char digest_veri[SHA_DIGEST_LENGTH];
    SHA_CTX ctx_veri;
    SHA1_Init(&ctx_veri);
    SHA1_Update(&ctx_veri, veri_rev, strlen(veri_rev));
    SHA1_Final(digest_veri, &ctx_veri);
    printf("返回数据摘要：");
    for(unsigned int i =0;i<SHA_DIGEST_LENGTH;i++) 
    printf("%02x",digest_veri[i]);
    printf("\n\n");
    usleep(2000000U);

    /*读取平台公钥*/
    FILE *platpub_file;
    RSA *platpub= RSA_new();
    platpub_file = fopen("/home/zwl/桌面/terminal verification/examples/ppubkey.key", "r");
    if (NULL == platpub_file)
    {
        printf("open file 'platpubkey.key' failed!\n");
        exit_example(EXIT_SUCCESS, sockfd, &client_daemon);
        exit_example(EXIT_SUCCESS, sockfd, &client_daemon2);
        return -1;
    }
    PEM_read_RSAPublicKey(platpub_file,&platpub, NULL, NULL);
    //RSA_print_fp(stdout, platpub, 5);
    fclose(platpub_file);
    platpub_file=NULL;

    unsigned char rev_decrypt[SHA_DIGEST_LENGTH]={0};
    size_t outl2 = RSA_public_decrypt(sizeof(sign_rev_char),(const unsigned char *)sign_rev_char, rev_decrypt, platpub, RSA_PKCS1_PADDING);
    printf("平台公钥验签结果：");
    for(unsigned int i =0;i<SHA_DIGEST_LENGTH;i++) 
    printf("%02x",rev_decrypt[i]);
    printf("\n\n");
    usleep(2000000U);
    //char rev_decrypt_String[512*2+1];
    //for (unsigned int i = 0; i < outl2; i++)
    //sprintf(&rev_decrypt_String[i*2], "%02x", (unsigned int)rev_decrypt[i]);
    //printf("rev_decrypt_String:%s\n", rev_decrypt_String);
    if(strcmp((const char *)digest_veri,(const char *)rev_decrypt)==0)
        {
            printf("\033[1m\033[45;33m[7]返回数据验签成功success!\033[0m\n\n");
            usleep(2000000U);
            if (strstr(rev_msg,"chislab1")!=0)
                printf("\033[1m\033[45;33m[8]设备注册认证成功success!\033[0m\n\n");   
            else
            {
                printf("\033[1m\033[45;33m[8]设备注册认证失败failed!\033[0m\n\n");
                exit_example(EXIT_SUCCESS, sockfd, &client_daemon);
                exit_example(EXIT_SUCCESS, sockfd, &client_daemon2);
                return 0;
            } 
        }  
    else
        {
            printf("\033[1m\033[45;33m[7]返回数据验签失败failed!\033[0m\n\n");
            exit_example(EXIT_SUCCESS, sockfd, &client_daemon);
            exit_example(EXIT_SUCCESS, sockfd, &client_daemon2); 
            return 0;
        }
  
    /* block */
    while(fgetc(stdin) != EOF);
    //usleep(2000000U);
    //mqtt_publish(&client, topic, "1111111111111111111", 25, MQTT_PUBLISH_QOS_0);
    //usleep(8000000U);
    //mqtt_subscribe(&client, topic, 0);
   	/* check for errors */
  /* exit */ 
    exit_example(EXIT_SUCCESS, sockfd, &client_daemon);
    exit_example(EXIT_SUCCESS, sockfd, &client_daemon2);

    return 0;
}

