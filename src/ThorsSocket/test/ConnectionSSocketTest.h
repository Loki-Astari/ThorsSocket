#ifndef THORSANVIL_TEST_CONNECTION_SSOCKET_H
#define THORSANVIL_TEST_CONNECTION_SSOCKET_H

#include "test/ConnectionSocketTest.h"

class MockConnectionSSocket: public MockConnectionSocket
{
    MOCK_MEMBER(TLS_client_method);
    MOCK_MEMBER(TLS_server_method);
    MOCK_MEMBER(SSL_CTX_new);
    MOCK_MEMBER(SSL_CTX_free);
    MOCK_MEMBER(SSL_new);
    MOCK_MEMBER(SSL_free);
    MOCK_MEMBER(SSL_set_fd);
    MOCK_MEMBER(SSL_connect);
    MOCK_MEMBER(SSL_get_error);
    MOCK_MEMBER(SSL_get1_peer_certificate);
    MOCK_MEMBER(X509_free);
    MOCK_MEMBER(SSL_read);
    MOCK_MEMBER(SSL_write);
    MOCK_MEMBER(SSL_shutdown);

    public:
        MockConnectionSSocket()
            : MOCK_PARAM(TLS_client_method,             [&]()                        {checkExpected("TLS_client_method");return (SSL_METHOD*)1;})
            , MOCK_PARAM(TLS_server_method,             [&]()                        {checkExpected("TLS_server_method");return (SSL_METHOD*)2;})
            , MOCK_PARAM(SSL_CTX_new,                   [&](SSL_METHOD const*)       {checkExpected("SSL_CTX_new");return (SSL_CTX*)2;})
            , MOCK_PARAM(SSL_CTX_free,                  [&](SSL_CTX*)                {checkExpected("SSL_CTX_free");return 1;})
            , MOCK_PARAM(SSL_new,                       [&](SSL_CTX*)                {checkExpected("SSL_new");return (SSL*)3;})
            , MOCK_PARAM(SSL_free,                      [&](SSL*)                    {checkExpected("SSL_free");return 1;})
            , MOCK_PARAM(SSL_set_fd,                    [&](SSL*, int)               {checkExpected("SSL_set_fd");return 1;})
            , MOCK_PARAM(SSL_connect,                   [&](SSL*)                    {checkExpected("SSL_connect");return 1;})
            , MOCK_PARAM(SSL_get_error,                 [&](SSL const*, int)         {checkExpected("SSL_get_error");return 1;})
            , MOCK_PARAM(SSL_get1_peer_certificate,     [&](SSL const*)              {checkExpected("SSL_get1_peer_certificate");return reinterpret_cast<X509*>(0x08);})
            , MOCK_PARAM(X509_free,                     [&](X509*)                   {checkExpected("X509_free");})
            , MOCK_PARAM(SSL_read,                      [&](SSL*, void*, int)        {checkExpected("SSL_read");return 1;})
            , MOCK_PARAM(SSL_write,                     [&](SSL*, void const*, int)  {checkExpected("SSL_write");return 1;})
            , MOCK_PARAM(SSL_shutdown,                  [&](SSL*)                    {checkExpected("SSL_shutdown");return 1;})
        {}
        static MockAction getActionSSLctxClient()
        {
            return  {
                        "SSLctx",
                        {"TLS_client_method", "SSL_CTX_new"},
                        {"SSL_CTX_free"},
                        {"SSL_CTX_ctrl", "SSL_CTX_set_cipher_list", "SSL_CTX_set_ciphersuites", "SSL_CTX_set_default_passwd_cb", "SSL_CTX_set_default_passwd_cb_userdata", "SSL_CTX_use_certificate_file", "SSL_CTX_use_PrivateKey_file", "SSL_CTX_check_private_key", "SSL_CTX_set_default_verify_file", "SSL_CTX_set_default_verify_dir", "SSL_CTX_set_default_verify_store", "SSL_CTX_load_verify_file", "SSL_CTX_load_verify_dir", "SSL_CTX_load_verify_store", "sk_X509_NAME_new_null_wrapper", "sk_X509_NAME_free_wrapper", "sk_X509_NAME_pop_free_wrapper", "SSL_CTX_set_verify", "SSL_CTX_set_client_CA_list", "ERR_get_error"}
                    };
        }
        static MockAction getActionSSLctxServer()
        {
            return  {
                        "SSLctx",
                        {"TLS_server_method", "SSL_CTX_new"},
                        {"SSL_CTX_free"},
                        {"SSL_CTX_ctrl", "SSL_CTX_set_cipher_list", "SSL_CTX_set_ciphersuites", "SSL_CTX_set_default_passwd_cb", "SSL_CTX_set_default_passwd_cb_userdata", "SSL_CTX_use_certificate_file", "SSL_CTX_use_PrivateKey_file", "SSL_CTX_check_private_key", "SSL_CTX_set_default_verify_file", "SSL_CTX_set_default_verify_dir", "SSL_CTX_set_default_verify_store", "SSL_CTX_load_verify_file", "SSL_CTX_load_verify_dir", "SSL_CTX_load_verify_store", "sk_X509_NAME_new_null_wrapper", "sk_X509_NAME_free_wrapper", "sk_X509_NAME_pop_free_wrapper", "SSL_CTX_set_verify", "SSL_CTX_set_client_CA_list", "ERR_get_error"}
                    };
        }
        static MockAction getActionSSocket()
        {
            return {
                        "SSocket",
                        {"SSL_new", "SSL_set_fd", "SSL_connect", "SSL_get1_peer_certificate", "X509_free"},
                        {"SSL_shutdown", "SSL_free"},
                        {"SSL_ctrl", "SSL_set_cipher_list", "SSL_set_ciphersuites", "SSL_set_default_passwd_cb", "SSL_set_default_passwd_cb_userdata", "SSL_use_certificate_file", "SSL_use_PrivateKey_file", "SSL_check_private_key", "SSL_add_file_cert_subjects_to_stack", "SSL_add_dir_cert_subjects_to_stack", "SSL_add_store_cert_subjects_to_stack", "sk_X509_NAME_ne    w_null_wrapper", "sk_X509_NAME_free_wrapper", "sk_X509_NAME_pop_free_wrapper", "SSL_set_verify", "SSL_set_client_CA_list", "ERR_get_error"}
                   };
        }
};

#endif
