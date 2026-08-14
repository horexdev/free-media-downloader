#include <curl/curl.h>
#include <stddef.h>

#define FMD_STATIC_ASSERT(name, condition) typedef char name[(condition) ? 1 : -1]

FMD_STATIC_ASSERT(fmd_public_key_auth_mask_is_stable,
                  CURLSSH_AUTH_PUBLICKEY == (1L << 0));
FMD_STATIC_ASSERT(fmd_password_auth_mask_is_stable,
                  CURLSSH_AUTH_PASSWORD == (1L << 1));
FMD_STATIC_ASSERT(fmd_no_auth_mask_is_stable, CURLSSH_AUTH_NONE == 0L);

typedef int (*fmd_hostkey_callback)(void *context, int key_type,
                                    const unsigned char *key, size_t key_len);
typedef struct {
  fmd_hostkey_callback callback;
  void *context;
} fmd_hostkey_state;

static CURLHcode fmd_curl_hostkey_bridge(void *clientp, int keymatch,
                                         const struct curl_khkey *match,
                                         const struct curl_khkey *foundkey) {
  (void)keymatch;
  (void)match;
  fmd_hostkey_state *state = (fmd_hostkey_state *)clientp;
  int decision = state->callback(state->context, (int)foundkey->keytype,
                          (const unsigned char *)foundkey->key,
                          foundkey->len);
  return decision == 1 ? CURLKHSTAT_FINE : CURLKHSTAT_REJECT;
}

CURLcode fmd_curl_set_hostkey_callback(CURL *easy, fmd_hostkey_state *state) {
  CURLcode result = curl_easy_setopt(easy, CURLOPT_SSH_HOSTKEYDATA, state);
  if (result != CURLE_OK) return result;
  return curl_easy_setopt(easy, CURLOPT_SSH_HOSTKEYFUNCTION,
                          fmd_curl_hostkey_bridge);
}

CURLcode fmd_curl_set_ssh_auth(CURL *easy, long auth_types,
                               const char *private_key,
                               const char *passphrase) {
  CURLcode result = curl_easy_setopt(easy, CURLOPT_SSH_AUTH_TYPES, auth_types);
  if (result != CURLE_OK) return result;
  if (private_key != NULL) {
    result = curl_easy_setopt(easy, CURLOPT_SSH_PRIVATE_KEYFILE, private_key);
    if (result != CURLE_OK) return result;
  }
  if (passphrase != NULL) {
    result = curl_easy_setopt(easy, CURLOPT_KEYPASSWD, passphrase);
  }
  return result;
}
