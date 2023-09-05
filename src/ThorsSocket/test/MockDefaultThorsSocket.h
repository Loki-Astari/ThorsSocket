#ifndef THORSANVIL_TEST_MOCK_DEFAULT_THORS_SOCKET_H
#define THORSANVIL_TEST_MOCK_DEFAULT_THORS_SOCKET_H

#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>
#include "ConnectionSocket.h"

typedef int (*CB)(char*, int, int, void*);
typedef int (*VCB)(int, X509_STORE_CTX*);

class MockDefaultThorsSocket: public ThorsAnvil::BuildTools::Mock::MockOverride
{
    std::function<ThorsAnvil::ThorsSocket::ConnectionType::HostEnt*(const char*)> getHostByNameMock =[]  (char const*) {
        static char* addrList[] = {""};
        static ThorsAnvil::ThorsSocket::ConnectionType::HostEnt result {.h_length=1, .h_addr_list=addrList};
        return &result;
    };

    MOCK_MEMBER(read);
    MOCK_MEMBER(write);
    MOCK_TMEMBER(OpenType, open);
    MOCK_MEMBER(close);
    MOCK_TMEMBER(FctlType, fcntl);
    MOCK_MEMBER(pipe);
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
    MOCK_MEMBER(ERR_get_error);
    MOCK_MEMBER(socket);
    MOCK_MEMBER(gethostbyname);
    MOCK_MEMBER(connect);
    MOCK_MEMBER(shutdown);

    public:
        MockDefaultThorsSocket()
            : MOCK_PARAM(read,                                  [ ](int, void*, ssize_t size)           {return size;})
            , MOCK_PARAM(write,                                 [ ](int, void const*, ssize_t size)     {return size;})
            , MOCK_PARAM(open,                                  [ ](char const*, int, int)              {return 12;})
            , MOCK_PARAM(close,                                 [ ](int)                                {return 0;})
            , MOCK_PARAM(fcntl,                                 [ ](int, int, int)                      {return 0;})
            , MOCK_PARAM(pipe,                                  [ ](int* p)                             {p[0] = 12; p[1] =13;return 0;})
            , MOCK_PARAM(TLS_client_method,                     [ ]()                                   {return (SSL_METHOD*)1;})
            , MOCK_PARAM(TLS_server_method,                     [ ]()                                   {return (SSL_METHOD*)2;})
            , MOCK_PARAM(SSL_CTX_new,                           [ ](SSL_METHOD const*)                  {return (SSL_CTX*)2;})
            , MOCK_PARAM(SSL_CTX_free,                          [ ](SSL_CTX*)                           {return 1;})
            , MOCK_PARAM(SSL_new,                               [ ](SSL_CTX*)                           {return (SSL*)3;})
            , MOCK_PARAM(SSL_free,                              [ ](SSL*)                               {return 1;})
            , MOCK_PARAM(SSL_set_fd,                            [ ](SSL*, int)                          {return 1;})
            , MOCK_PARAM(SSL_connect,                           [ ](SSL*)                               {return 1;})
            , MOCK_PARAM(SSL_get_error,                         [ ](SSL const*, int)                    {return SSL_ERROR_NONE;})
            , MOCK_PARAM(SSL_get1_peer_certificate,             [ ](SSL const*)                         {return reinterpret_cast<X509*>(0x08);})
            , MOCK_PARAM(X509_free,                             [ ](X509*)                              {})
            , MOCK_PARAM(SSL_read,                              [ ](SSL*, void*, int)                   {return 1;})
            , MOCK_PARAM(SSL_write,                             [ ](SSL*, void const*, int)             {return 1;})
            , MOCK_PARAM(SSL_shutdown,                          [ ](SSL*)                               {return 1;})
            , MOCK_PARAM(SSL_CTX_ctrl,                          [ ](SSL_CTX*, int, int, void*)          {return 1;})
            , MOCK_PARAM(SSL_CTX_set_cipher_list,               [ ](SSL_CTX*, char const*)              {return 1;})
            , MOCK_PARAM(SSL_CTX_set_ciphersuites,              [ ](SSL_CTX*, char const*)              {return 1;})
            , MOCK_PARAM(SSL_CTX_set_default_passwd_cb,         [ ](SSL_CTX*, CB)                       {return 1;})
            , MOCK_PARAM(SSL_CTX_set_default_passwd_cb_userdata,[ ](SSL_CTX*, void*)                    {return 1;})
            , MOCK_PARAM(SSL_CTX_use_certificate_file,          [ ](SSL_CTX*, char const*, int)         {return 1;})
            , MOCK_PARAM(SSL_CTX_use_PrivateKey_file,           [ ](SSL_CTX*, char const*, int)         {return 1;})
            , MOCK_PARAM(SSL_CTX_check_private_key,             [ ](SSL_CTX const*)                     {return 1;})
            , MOCK_PARAM(SSL_CTX_set_default_verify_file,       [ ](SSL_CTX*)                           {return 1;})
            , MOCK_PARAM(SSL_CTX_set_default_verify_dir,        [ ](SSL_CTX*)                           {return 1;})
            , MOCK_PARAM(SSL_CTX_set_default_verify_store,      [ ](SSL_CTX*)                           {return 1;})
            , MOCK_PARAM(SSL_CTX_load_verify_file,              [ ](SSL_CTX*, char const*)              {return 1;})
            , MOCK_PARAM(SSL_CTX_load_verify_dir,               [ ](SSL_CTX*, char const*)              {return 1;})
            , MOCK_PARAM(SSL_CTX_load_verify_store,             [ ](SSL_CTX*, char const*)              {return 1;})
            , MOCK_PARAM(SSL_CTX_set_verify,                    [ ](SSL_CTX*, int, VCB)                 {return 1;})
            , MOCK_PARAM(SSL_CTX_set_client_CA_list,            [ ](SSL_CTX*, STACK_OF(X509_NAME)*)     {return 1;})
            , MOCK_PARAM(SSL_ctrl,                              [ ](SSL*, int, long, void*)             {return 1;})
            , MOCK_PARAM(SSL_set_cipher_list,                   [ ](SSL*, char const*)                  {return 1;})
            , MOCK_PARAM(SSL_set_ciphersuites,                  [ ](SSL*, char const*)                  {return 1;})
            , MOCK_PARAM(SSL_set_default_passwd_cb,             [ ](SSL*, int(*)(char*, int, int, void*)){return 1;})
            , MOCK_PARAM(SSL_set_default_passwd_cb_userdata,    [ ](SSL*, void*)                        {return 1;})
            , MOCK_PARAM(SSL_use_certificate_file,              [ ](SSL*, char const*, int)             {return 1;})
            , MOCK_PARAM(SSL_use_PrivateKey_file,               [ ](SSL*, char const*, int)             {return 1;})
            , MOCK_PARAM(SSL_check_private_key,                 [ ](SSL const*)                         {return 1;})
            , MOCK_PARAM(SSL_add_file_cert_subjects_to_stack,   [ ](STACK_OF(X509_NAME)*, char const*)  {return 1;})
            , MOCK_PARAM(SSL_add_dir_cert_subjects_to_stack,    [ ](STACK_OF(X509_NAME)*, char const*)  {return 1;})
            , MOCK_PARAM(SSL_add_store_cert_subjects_to_stack,  [ ](STACK_OF(X509_NAME)*, char const*)  {return 1;})
            , MOCK_PARAM(SSL_set_verify,                        [ ](SSL*, int, VCB)                     {return 1;})
            , MOCK_PARAM(SSL_set_client_CA_list,                [ ](SSL*, STACK_OF(X509_NAME)*)         {return 1;})
            , MOCK_PARAM(sk_X509_NAME_new_null_wrapper,         [ ]()                                   {return reinterpret_cast<STACK_OF(X509_NAME)*>(0x08);})
            , MOCK_PARAM(sk_X509_NAME_free_wrapper,             [ ](STACK_OF(X509_NAME)*)               {})
            , MOCK_PARAM(sk_X509_NAME_pop_free_wrapper,         [ ](STACK_OF(X509_NAME)*)               {})
            , MOCK_PARAM(ERR_get_error,                         [ ]()                                   {return 0;})
            , MOCK_PARAM(socket,                                [ ](int, int, int)                      {return 12;})
            , MOCK_PARAM(gethostbyname,                         std::move(getHostByNameMock))
            , MOCK_PARAM(connect,                               [ ](int, ThorsAnvil::ThorsSocket::ConnectionType::SocketAddr const*, unsigned int) {return 0;})
            , MOCK_PARAM(shutdown,                              [ ](int, int)                           {return 0;})
        {}
        static ThorsAnvil::BuildTools::Mock::MockAction getActionFile()
        {
            return {
                        "File",
                        {"open"},
                        {"close"},
                        {},
                        {}
                   };
        }
        static ThorsAnvil::BuildTools::Mock::MockAction getActionPipeBlocking()
        {
            return {
                        "Pipe",
                        {"pipe"},
                        {"close", "close"},
                        {},
                        {}
                   };
        }
        static ThorsAnvil::BuildTools::Mock::MockAction getActionPipeNonBlocking()
        {
            return {
                        "Pipe",
                        {"pipe", "fcntl", "fcntl"},
                        {"close", "close"},
                        {},
                        {}
                   };
        }
        static ThorsAnvil::BuildTools::Mock::MockAction getActionSSLctxClient()
        {
            return  {
                        "SSLctx",
                        {"TLS_client_method", "SSL_CTX_new"},
                        {"SSL_CTX_free"},
                        {"SSL_CTX_ctrl", "SSL_CTX_set_cipher_list", "SSL_CTX_set_ciphersuites", "SSL_CTX_set_default_passwd_cb", "SSL_CTX_set_default_passwd_cb_userdata", "SSL_CTX_use_certificate_file", "SSL_CTX_use_PrivateKey_file", "SSL_CTX_check_private_key", "SSL_CTX_set_default_verify_file", "SSL_CTX_set_default_verify_dir", "SSL_CTX_set_default_verify_store", "SSL_CTX_load_verify_file", "SSL_CTX_load_verify_dir", "SSL_CTX_load_verify_store", "sk_X509_NAME_new_null_wrapper", "sk_X509_NAME_free_wrapper", "sk_X509_NAME_pop_free_wrapper", "SSL_CTX_set_verify", "SSL_CTX_set_client_CA_list", "ERR_get_error"}
                    };
        }
        static ThorsAnvil::BuildTools::Mock::MockAction getActionSSLctxServer()
        {
            return  {
                        "SSLctx",
                        {"TLS_server_method", "SSL_CTX_new"},
                        {"SSL_CTX_free"},
                        {"SSL_CTX_ctrl", "SSL_CTX_set_cipher_list", "SSL_CTX_set_ciphersuites", "SSL_CTX_set_default_passwd_cb", "SSL_CTX_set_default_passwd_cb_userdata", "SSL_CTX_use_certificate_file", "SSL_CTX_use_PrivateKey_file", "SSL_CTX_check_private_key", "SSL_CTX_set_default_verify_file", "SSL_CTX_set_default_verify_dir", "SSL_CTX_set_default_verify_store", "SSL_CTX_load_verify_file", "SSL_CTX_load_verify_dir", "SSL_CTX_load_verify_store", "sk_X509_NAME_new_null_wrapper", "sk_X509_NAME_free_wrapper", "sk_X509_NAME_pop_free_wrapper", "SSL_CTX_set_verify", "SSL_CTX_set_client_CA_list", "ERR_get_error"}
                    };
        }
        static ThorsAnvil::BuildTools::Mock::MockAction getActionSSocket()
        {
            return {
                        "SSocket",
                        {"SSL_new", "SSL_set_fd", "SSL_connect", "SSL_get1_peer_certificate", "X509_free"},
                        {"SSL_shutdown", "SSL_free"},
                        {"SSL_ctrl", "SSL_set_cipher_list", "SSL_set_ciphersuites", "SSL_set_default_passwd_cb", "SSL_set_default_passwd_cb_userdata", "SSL_use_certificate_file", "SSL_use_PrivateKey_file", "SSL_check_private_key", "SSL_add_file_cert_subjects_to_stack", "SSL_add_dir_cert_subjects_to_stack", "SSL_add_store_cert_subjects_to_stack", "sk_X509_NAME_ne    w_null_wrapper", "sk_X509_NAME_free_wrapper", "sk_X509_NAME_pop_free_wrapper", "SSL_set_verify", "SSL_set_client_CA_list", "ERR_get_error"}
                   };
        }

        static ThorsAnvil::BuildTools::Mock::MockAction getActionSocketBlocking()
        {
            return {
                        "Socket",
                        {"socket", "gethostbyname", "connect"},
                        {"close"},
                        {}
                   };
        }
        static ThorsAnvil::BuildTools::Mock::MockAction getActionSocketNonBlocking()
        {
            return {
                        "Socket",
                        {"socket", "gethostbyname", "connect", "fcntl"},
                        {"close"},
                        {}
                   };
        }
};

#endif
