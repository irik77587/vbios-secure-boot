#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <efi.h>
#include <regex.h>

#define SHA256_DIGEST_SIZE  (32)
#define HASH_SIZE           (SHA256_DIGEST_SIZE)
#define HASH_LENGTH         (HASH_SIZE*2)
#define UUID_PATTERN        "^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"

EFI_GUID EFI_CERT_SHA256_GUID = { 0xc1c41626, 0x504c, 0x4092, { 0xac, 0xa9, 0x41, 0xf9, 0x36, 0x93, 0x43, 0x28 } };
//EFI_GUID MOK_OWNER = { 0x605dab50, 0xe046, 0x4300, {0xab, 0xb6, 0x3d, 0xd8, 0x10, 0xdd, 0x8b, 0x23} };

#pragma pack(1)
typedef struct {
  EFI_GUID          SignatureOwner;
  UINT8             SignatureData[1];
} EFI_SIGNATURE_DATA;

typedef struct {
  EFI_GUID            SignatureType;
  UINT32              SignatureListSize;
  UINT32              SignatureHeaderSize;
  UINT32              SignatureSize;
} EFI_SIGNATURE_LIST;
#pragma pack()

EFI_GUID Parse_UUID(char *str) {
    unsigned int data_1, data_2, data_3, data_4a, data_4b, data_4m, data_4n, data_4o, data_4x, data_4y, data_4z;
    sscanf(str, "%8x-%4x-%4x-%2x%2x-%2x%2x%2x%2x%2x%2x", &data_1, &data_2, &data_3, &data_4a, &data_4b, &data_4m, &data_4n, &data_4o, &data_4x, &data_4y, &data_4z);
    EFI_GUID guid;// = { data_1, data_2, data_3, {data_4a, data_4b, data_4m, data_4n, data_4o, data_4x, data_4y, data_4z} };
    guid.Data1 = data_1;
    guid.Data2 = data_2;
    guid.Data3 = data_3;
    guid.Data4[0] = data_4a;
    guid.Data4[1] = data_4b;
    guid.Data4[2] = data_4m;
    guid.Data4[3] = data_4n;
    guid.Data4[4] = data_4o;
    guid.Data4[5] = data_4x;
    guid.Data4[6] = data_4y;
    guid.Data4[7] = data_4z;
    return guid;
}

int check_invalid_uuid(char *uuidstr)
{
    regex_t engine;
    char errbuf[128];
    int status = regcomp(&engine, UUID_PATTERN, REG_EXTENDED);
    if (status != 0) {
        regerror(status, &engine, errbuf, sizeof(errbuf));
        fprintf(stderr, "Regex compile error: %s\n", errbuf);
        return status;
    }
    int result = regexec(&engine, uuidstr, 0, NULL, 0);
    regfree(&engine);
    return result;
}

void usage(const char *str) {
    fprintf(stderr, "Usage: %s SHA256SUM SIGN_OWNER_GUID OUT_FILE\n", str);
    exit(1);
}

int main(int argc, char *argv[]) {
    if (argc < 3) {
        usage(argv[0]);
    }

    if (strlen(argv[1]) != HASH_LENGTH) {
        fprintf(stderr, "First argument should be an sha256 hash");
        exit(1);
    }

    if (check_invalid_uuid(argv[2])) {
        fprintf(stderr, "Second argument should be GUID of signature owner");
        exit(1);
    }

    /* Read GUID of signature owner */
    EFI_GUID MOK_OWNER = Parse_UUID(argv[2]);

    /* Read digest */
    unsigned char digest[HASH_SIZE];
    char buffer[3] = {0, 0, '\0'};
    char *ptr;

    for (size_t i = 0; i < HASH_SIZE; ++i) {
        buffer[0] = argv[1][i*2];
        buffer[1] = argv[1][(i*2) + 1];
        digest[i] = (unsigned char)strtoul(buffer, &ptr, 16);
    }

    /* Convert to signature list */
    unsigned char sig[sizeof(EFI_SIGNATURE_LIST) + (sizeof(EFI_SIGNATURE_DATA) - 1 + SHA256_DIGEST_SIZE)];
    EFI_SIGNATURE_LIST *l = (void *)sig;

    memset(sig, 0, sizeof(sig));
    l->SignatureType = EFI_CERT_SHA256_GUID;
    l->SignatureListSize = sizeof(sig);
    l->SignatureSize = 16 + 32; /* UEFI defined */
    EFI_SIGNATURE_DATA *d = (void *)sig + sizeof(EFI_SIGNATURE_LIST);
    d->SignatureOwner = MOK_OWNER;
    memcpy(&d->SignatureData, digest, sizeof(digest));

    /* Write file */
    int fdoutfile = open(argv[3], O_CREAT|O_WRONLY|O_TRUNC, S_IWUSR|S_IRUSR);
    if (fdoutfile == -1) {
        fprintf(stderr, "Failed to open %s: ", argv[3]);
        perror("");
        exit(1);
    }
    write(fdoutfile, sig, sizeof(sig));
    close(fdoutfile);

    return 0;
}
