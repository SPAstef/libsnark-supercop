#include <openssl/evp.h>
#include "crypto_core_aes128encrypt.h"

int crypto_core_aes128encrypt_openssl(
        unsigned char *out,
  const unsigned char *in,
  const unsigned char *k,
  const unsigned char *c
)
{
  EVP_CIPHER_CTX *ctx;
  int outlen;

  ctx = EVP_CIPHER_CTX_new();
  if (!ctx) return -1;

  if (EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, k, NULL) != 1) {
    EVP_CIPHER_CTX_free(ctx);
    return -1;
  }

  EVP_CIPHER_CTX_set_padding(ctx, 0);

  if (EVP_EncryptUpdate(ctx, out, &outlen, in, 16) != 1) {
    EVP_CIPHER_CTX_free(ctx);
    return -1;
  }

  EVP_CIPHER_CTX_free(ctx);
  return 0;
}
