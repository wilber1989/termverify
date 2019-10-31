#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <openssl/sha.h>
#include <openssl/rsa.h>
#include <cjson/cJSON.h>

#include <mqtt.h>
#include <base64.h>
#include "templates/posix_sockets.h"

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
	char shString[512*2+1];
    for (unsigned int i = 0; i < outl; i++)
    sprintf(&shString[i*2], "%02x", (unsigned int)cipper[i]);
    //printf("\033[1m\033[45;33m%s\033[0m\n\n",shString);
	cJSON_AddStringToObject(root,"sign",shString);
	char* json1_1 = cJSON_Print(root);
	printf("\033[1m\033[45;33m[2] 产品私钥对设备ID及设备公钥签名:\033[0m\n\n");
	usleep(2000000U);
	printf("%s\n",json1_1 );
	usleep(2000000U);
	return 0;
}