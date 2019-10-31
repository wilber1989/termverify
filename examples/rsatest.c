#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <openssl/sha.h>
#include <openssl/rsa.h>

/*********************************************
 * 函数功能：保存私钥到文件
 * 传入参数：RSA结构体
 * 传出参数：无
 * 返 回 值：成功返回1否则0
 ********************************************/
int saveprikey(RSA *rsa)
{
    FILE *file;
    if (NULL == rsa)
    {
        printf("RSA not initial.\n");
        return 0;
    }
    //RSA_print_fp(stdout, rsa,5);
    file = fopen("/home/zwl/桌面/terminal verification/examples/prikey.key","wb");

    if (NULL == file)
    {
        printf("create file 'prikey.key' failed!\n");
        return 0;
    }
    PEM_write_RSAPrivateKey(file, rsa, NULL, NULL, 512, NULL, NULL);
    fclose(file);
    return 1;
}

/****************************************
*函数功能：读取密钥存储文件，获取私钥
*传入参数：rsa RSA结构体指针
*传出参数：无
*返回值  ：rsa RSA结构体指针,失败为NULL
****************************************/
RSA* getprikey(RSA *rsa)
{
    //RSA *rsa2;
    FILE *file;
    if (NULL == rsa)
    {
        printf("RSA not initial!\n");
        return NULL;
    }
    file = fopen("/home/zwl/桌面/terminal verification/examples/prikey.key", "rb");
    if (NULL == file)
    {
        printf("open file 'prikey.key' failed!\n");
        return NULL;
    }
    PEM_read_RSAPrivateKey(file,&rsa, NULL, NULL);
    RSA_print_fp(stdout, rsa, 5);
    printf("\n\n");
    fclose(file);
    return rsa;
}


RSA* createkey(RSA *rsa)
    {
        BIGNUM *bne=BN_new();
        BN_set_word(bne,RSA_F4);
        RSA_generate_key_ex(rsa,512,bne,NULL);
        return rsa;
    }

int main(int argc, const char *argv[]) 
{
    RSA *rsa= RSA_new();
    rsa = createkey(rsa);
    saveprikey(rsa);
    RSA *rsa1= RSA_new();
    rsa1 = getprikey(rsa1);
    //RSA_print_fp(stdout, rsa1, 5);
    RSA* pub = RSAPublicKey_dup(rsa1);
    RSA* pri = RSAPrivateKey_dup(rsa1);
    RSA_print_fp(stdout, pub, 5);
    //getprikey(rsa);  
    while(fgetc(stdin) != EOF);
}