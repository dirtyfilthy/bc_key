#include <sys/types.h>
#include <limits.h>
#include <stdlib.h>
#include <stdio.h>
#include <db.h>
#include <string.h> 
#include <unistd.h>
#include <gmp.h>
#include <openssl/buffer.h>
#include <openssl/ecdsa.h>
#include <openssl/sha.h>
#include <openssl/ripemd.h>
#include <openssl/evp.h>
#define DATABASE "/home/alhazred/.bitcoin/wallet.dat"
static const char* base58chars = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

DB *open_wallet(char *path){

    DB *dbp;
    int ret;

    if ((ret = db_create(&dbp, NULL, 0)) != 0) {
        fprintf(stderr, "db_create: %s\n", db_strerror(ret));
        exit (1);
    }
    if ((ret = dbp->open(
                    dbp, NULL, path, "main", DB_BTREE, DB_RDONLY, 0664)) != 0) {
        dbp->err(dbp, ret, "%s", path);
        printf("fail open\n");
        exit (1);
    }
    return dbp;
}

unsigned int get_size(FILE *f){
    int magic;
    unsigned char byte1=0;
    unsigned char byte2=0;
    unsigned char byte3=0;
    unsigned char byte4=0;
    unsigned int size;
    magic=fgetc(f);
    if(magic<253){
        byte1=magic;
    }
    else if(magic==253){
        byte1=fgetc(f);
        byte2=fgetc(f);
    }
    else if(magic==254){
                
        byte1=fgetc(f);
        byte2=fgetc(f);
        byte3=fgetc(f);
        byte4=fgetc(f);
    }
    else{
        exit(1);
    }
    size=((unsigned int) byte4 << 24) + ((unsigned int) byte3 << 16) |  ((unsigned int) byte2 << 8) | (unsigned int) byte1;
    return size;
}


char *get_string(FILE *f){
    unsigned int size=get_size(f);
    char *buffer=(char *) malloc(size+1);
    fread(buffer,size,1,f);
    buffer[size]=0;
    return buffer;
}

char* reverse_string(char* str)
{
    int end= strlen(str)-1;
    int start = 0;

    while( start<end )
    {
        str[start] ^= str[end];
        str[end] ^=  str[start];
        str[start]^= str[end];

        ++start;
        --end;
    }

    return str;
}

char *sha256(char *string,int length)
{
    unsigned char *digest=(unsigned char *) malloc(SHA256_DIGEST_LENGTH);
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, string, length);
    SHA256_Final(digest, &sha256);
    return digest;
}

char *double_sha256(char *string, int length){
    unsigned char *digest1=sha256(string,length);
    unsigned char *digest2=sha256(digest1,SHA256_DIGEST_LENGTH);
    free(digest1);
    return digest2;
}



char *ripemd160(char *string,int length)
{
    unsigned char *digest=(unsigned char *) malloc(RIPEMD160_DIGEST_LENGTH);
    RIPEMD160_CTX ripe;
    RIPEMD160_Init(&ripe);
    RIPEMD160_Update(&ripe, string, length);
    RIPEMD160_Final(digest, &ripe);
    return digest;
}

char *base58_encode(char *buffer, int length){
    mpz_t bn;
    mpz_t bn2;
    mpz_t r;
    char digit;
    size_t result_size;
    char *result;
    FILE *result_stream=open_memstream(&result,&result_size);
    int i;
    mpz_init(bn);
    mpz_init(bn2);
    mpz_init(r);    
    mpz_import(bn,length,1,1,0,0,buffer);
    while(mpz_cmp_ui(bn,58)>=0){
        mpz_fdiv_qr_ui(bn2,r,bn,58);
        mpz_set(bn,bn2);
        digit=base58chars[(int) mpz_get_ui(r)];
        fputc(digit,result_stream);
    }
    digit=base58chars[(int) mpz_get_ui(bn)];
    fputc(digit,result_stream);
    for(i=0;i<length && !buffer[i];i++){
        fputc(base58chars[0],result_stream);
    }
    fclose(result_stream);
    reverse_string(result);
    return result;

}

char *public_key_to_bc_address(char *key, int length){
    char *digest1=sha256(key,length);
    char *digest2=ripemd160(digest1,SHA256_DIGEST_LENGTH);
    size_t result_size;
    char *result;
    char *b58;
    char *checksum;
    char *final=malloc(RIPEMD160_DIGEST_LENGTH+5); /* +1 byte for version, +4 bytes for checksum) */
    final[0]=0x00; /* version 0 */
    memcpy(final+1,digest2,RIPEMD160_DIGEST_LENGTH);
    checksum=double_sha256(final,RIPEMD160_DIGEST_LENGTH+1);
    memcpy(&final[RIPEMD160_DIGEST_LENGTH+1],checksum,4);
    free(digest1);
    free(digest2);
    free(checksum);
    b58=base58_encode(final,RIPEMD160_DIGEST_LENGTH+5);
    free(final);
    return b58;
    
}

void export_key(const unsigned char *key, int length){
    EC_KEY* pkey=EC_KEY_new();
    EC_GROUP *group = EC_GROUP_new_by_curve_name(NID_secp256k1);
    EC_GROUP_set_asn1_flag(group, OPENSSL_EC_NAMED_CURVE);
    EC_GROUP_set_point_conversion_form(group, POINT_CONVERSION_UNCOMPRESSED);
    EC_KEY_set_group(pkey,group);
    BIO *out=BIO_new(BIO_s_file());
    BIO_set_fp(out,stdout,BIO_NOCLOSE);
    if(!d2i_ECPrivateKey(&pkey, &key, length)){
        printf("failed to make key\n");
        exit(1);
    }
    PEM_write_bio_ECPKParameters(out, group);
    PEM_write_bio_ECPrivateKey(out,pkey,NULL,NULL,0,NULL,NULL);
}


void find_key(DBT *key, DBT *value, void *data){
    char *address=(char *) data;
    FILE *key_stream=fmemopen(key->data,key->size,"r");
    FILE *value_stream=fmemopen(value->data,value->size,"r");
    char *type;
    char *b58;
    char *public_key;
    int public_key_length;

    char *private_key;
    int private_key_length;
    int found_key=0;
    type=get_string(key_stream);
    if(strcmp("key",type)==0){
        public_key_length=get_size(key_stream);
        public_key=(char *) malloc(public_key_length);
        private_key_length=get_size(value_stream);
        private_key=(char *) malloc(private_key_length);
        fread(public_key,1,public_key_length,key_stream);
        fread(private_key,1,private_key_length,value_stream);
        found_key=1;
    }
    if(found_key){
        b58=public_key_to_bc_address(public_key,public_key_length);
        if(strcmp(b58,address)==0){
            export_key(private_key,private_key_length);
            exit(0);
        }
        free(public_key);
        free(private_key);
        free(b58);
    }
    free(type);
    fclose(key_stream);
    fclose(value_stream);
}

void foreach_item(DB *db, void func(DBT *, DBT *,void *), void *data){
    DBC *cursor;
    DBT key, value;
    int ret;
    if ((ret = db->cursor(db, NULL, &cursor, 0)) != 0) {
        db->err(db, ret, "DB->cursor");
        exit(1);
    }
    memset(&key, 0, sizeof(key));
    memset(&value, 0, sizeof(value));
    while ((ret = cursor->get(cursor, &key, &value, DB_NEXT)) == 0){
        func(&key,&value,data);
    }
    if (ret != DB_NOTFOUND) {
        db->err(db, ret, "DBcursor->get");
        exit(1);
    }
}

void print_usage(char *here){
    printf("Usage:\n");
    printf("%s BITCOIN_ADDRESS /path/to/wallet.dat\n",here);
    printf("%s 1qZGQG5Ls66oBbtLt3wPMa6zfq7CJ7f12 /home/dirtyfilthy/.bitcoin/wallet.dat\n",here);
}

int main(int argc, char *argv[]){
    DB *wallet;
    ENGINE_load_builtin_engines();
    CRYPTO_malloc_init();
    if(argc!=3){
        print_usage(argv[0]);
        exit(1);
    }
    wallet=open_wallet(argv[2]);
    foreach_item(wallet,find_key,argv[1]);
}


