#ifndef THORSANVIL_TEST_CONNECTION_SSOCKET_UTIL_H
#define THORSANVIL_TEST_CONNECTION_SSOCKET_UTIL_H

#include "test/ConnectionSSocketTest.h"

typedef int (*CB)(char*, int, int, void*);
typedef int (*VCB)(int, X509_STORE_CTX*);

class MockConnectionSSocketUtil: public MockConnectionSSocket
{
    MOCK_MEMBER(SSL_CTX_ctrl);
    MOCK_MEMBER(SSL_CTX_set_cipher_list);
    MOCK_MEMBER(SSL_CTX_set_ciphersuites);
    MOCK_MEMBER(SSL_CTX_set_default_passwd_cb);
    MOCK_MEMBER(SSL_CTX_set_default_passwd_cb_userdata);
    MOCK_MEMBER(SSL_CTX_use_certificate_file);
    MOCK_MEMBER(SSL_CTX_use_PrivateKey_file);
    MOCK_MEMBER(SSL_CTX_check_private_key);
    MOCK_MEMBER(SSL_CTX_set_default_verify_file);
    MOCK_MEMBER(SSL_CTX_set_default_verify_dir);
    MOCK_MEMBER(SSL_CTX_set_default_verify_store);
    MOCK_MEMBER(SSL_CTX_load_verify_file);
    MOCK_MEMBER(SSL_CTX_load_verify_dir);
    MOCK_MEMBER(SSL_CTX_load_verify_store);
    MOCK_MEMBER(SSL_CTX_set_verify);
    MOCK_MEMBER(SSL_CTX_set_client_CA_list);
    MOCK_MEMBER(SSL_ctrl);
    MOCK_MEMBER(SSL_set_cipher_list);
    MOCK_MEMBER(SSL_set_ciphersuites);
    MOCK_MEMBER(SSL_set_default_passwd_cb);
    MOCK_MEMBER(SSL_set_default_passwd_cb_userdata);
    MOCK_MEMBER(SSL_use_certificate_file);
    MOCK_MEMBER(SSL_use_PrivateKey_file);
    MOCK_MEMBER(SSL_check_private_key);
    MOCK_MEMBER(SSL_add_file_cert_subjects_to_stack);
    MOCK_MEMBER(SSL_add_dir_cert_subjects_to_stack);
    MOCK_MEMBER(SSL_add_store_cert_subjects_to_stack);
    MOCK_MEMBER(SSL_set_verify);
    MOCK_MEMBER(SSL_set_client_CA_list);
    MOCK_MEMBER(sk_X509_NAME_new_null_wrapper);
    MOCK_MEMBER(sk_X509_NAME_free_wrapper);
    MOCK_MEMBER(sk_X509_NAME_pop_free_wrapper);

    public:
        MockConnectionSSocketUtil()
            : MOCK_PARAM(SSL_CTX_ctrl,                          [&](SSL_CTX*, int, int, void*)          {checkExpected("SSL_CTX_ctrl");return 1;})
            , MOCK_PARAM(SSL_CTX_set_cipher_list,               [&](SSL_CTX*, char const*)              {checkExpected("SSL_CTX_set_cipher_list");return 1;})
            , MOCK_PARAM(SSL_CTX_set_ciphersuites,              [&](SSL_CTX*, char const*)              {checkExpected("SSL_CTX_set_ciphersuites");return 1;})
            , MOCK_PARAM(SSL_CTX_set_default_passwd_cb,         [&](SSL_CTX*, CB)                       {checkExpected("SSL_CTX_set_default_passwd_cb");return 1;})
            , MOCK_PARAM(SSL_CTX_set_default_passwd_cb_userdata,[&](SSL_CTX*, void*)                    {checkExpected("SSL_CTX_set_default_passwd_cb_userdata");return 1;})
            , MOCK_PARAM(SSL_CTX_use_certificate_file,          [&](SSL_CTX*, char const*, int)         {checkExpected("SSL_CTX_use_certificate_file");return 1;})
            , MOCK_PARAM(SSL_CTX_use_PrivateKey_file,           [&](SSL_CTX*, char const*, int)         {checkExpected("SSL_CTX_use_PrivateKey_file");return 1;})
            , MOCK_PARAM(SSL_CTX_check_private_key,             [&](SSL_CTX const*)                     {checkExpected("SSL_CTX_check_private_key");return 1;})
            , MOCK_PARAM(SSL_CTX_set_default_verify_file,       [&](SSL_CTX*)                           {checkExpected("SSL_CTX_set_default_verify_file");return 1;})
            , MOCK_PARAM(SSL_CTX_set_default_verify_dir,        [&](SSL_CTX*)                           {checkExpected("SSL_CTX_set_default_verify_dir");return 1;})
            , MOCK_PARAM(SSL_CTX_set_default_verify_store,      [&](SSL_CTX*)                           {checkExpected("SSL_CTX_set_default_verify_store");return 1;})
            , MOCK_PARAM(SSL_CTX_load_verify_file,              [&](SSL_CTX*, char const*)              {checkExpected("SSL_CTX_load_verify_file");return 1;})
            , MOCK_PARAM(SSL_CTX_load_verify_dir,               [&](SSL_CTX*, char const*)              {checkExpected("SSL_CTX_load_verify_dir");return 1;})
            , MOCK_PARAM(SSL_CTX_load_verify_store,             [&](SSL_CTX*, char const*)              {checkExpected("SSL_CTX_load_verify_store");return 1;})
            , MOCK_PARAM(SSL_CTX_set_verify,                    [&](SSL_CTX*, int, VCB)                 {checkExpected("SSL_CTX_set_verify");return 1;})
            , MOCK_PARAM(SSL_CTX_set_client_CA_list,            [&](SSL_CTX*, STACK_OF(X509_NAME)*)     {checkExpected("SSL_CTX_set_client_CA_list");return 1;})
            , MOCK_PARAM(SSL_ctrl,                              [&](SSL*, int, long, void*)             {checkExpected("SSL_ctrl");return 1;})
            , MOCK_PARAM(SSL_set_cipher_list,                   [&](SSL*, char const*)                  {checkExpected("SSL_set_cipher_list");return 1;})
            , MOCK_PARAM(SSL_set_ciphersuites,                  [&](SSL*, char const*)                  {checkExpected("SSL_set_ciphersuites");return 1;})
            , MOCK_PARAM(SSL_set_default_passwd_cb,             [&](SSL*, int(*)(char*, int, int, void*)){checkExpected("SSL_set_default_passwd_cb");return 1;})
            , MOCK_PARAM(SSL_set_default_passwd_cb_userdata,    [&](SSL*, void*)                        {checkExpected("SSL_set_default_passwd_cb_userdata");return 1;})
            , MOCK_PARAM(SSL_use_certificate_file,              [&](SSL*, char const*, int)             {checkExpected("SSL_use_certificate_file");return 1;})
            , MOCK_PARAM(SSL_use_PrivateKey_file,               [&](SSL*, char const*, int)             {checkExpected("SSL_use_PrivateKey_file");return 1;})
            , MOCK_PARAM(SSL_check_private_key,                 [&](SSL const*)                         {checkExpected("SSL_check_private_key");return 1;})
            , MOCK_PARAM(SSL_add_file_cert_subjects_to_stack,   [&](STACK_OF(X509_NAME)*, char const*)  {checkExpected("SSL_add_file_cert_subjects_to_stack");return 1;})
            , MOCK_PARAM(SSL_add_dir_cert_subjects_to_stack,    [&](STACK_OF(X509_NAME)*, char const*)  {checkExpected("SSL_add_dir_cert_subjects_to_stack");return 1;})
            , MOCK_PARAM(SSL_add_store_cert_subjects_to_stack,  [&](STACK_OF(X509_NAME)*, char const*)  {checkExpected("SSL_add_store_cert_subjects_to_stack");return 1;})
            , MOCK_PARAM(SSL_set_verify,                        [&](SSL*, int, VCB)                     {checkExpected("SSL_set_verify");return 1;})
            , MOCK_PARAM(SSL_set_client_CA_list,                [&](SSL*, STACK_OF(X509_NAME)*)         {checkExpected("SSL_set_client_CA_list");return 1;})
            , MOCK_PARAM(sk_X509_NAME_new_null_wrapper,         [&]()                                   {checkExpected("sk_X509_NAME_new_null_wrapper");return reinterpret_cast<STACK_OF(X509_NAME)*>(0x08);})
            , MOCK_PARAM(sk_X509_NAME_free_wrapper,             [&](STACK_OF(X509_NAME)*)               {checkExpected("sk_X509_NAME_free_wrapper");})
            , MOCK_PARAM(sk_X509_NAME_pop_free_wrapper,         [&](STACK_OF(X509_NAME)*)               {checkExpected("sk_X509_NAME_pop_free_wrapper");})
        {}
};

#endif
