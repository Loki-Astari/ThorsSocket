#ifndef THORSANVIL_TEST_MOCK2_DEFAULT_THORS_SOCKET_H
#define THORSANVIL_TEST_MOCK2_DEFAULT_THORS_SOCKET_H

#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>
#include "ConnectionSocket.h"
#include "coverage/MockHeaders2.h"

typedef int (*CB)(char*, int, int, void*);
typedef int (*VCB)(int, X509_STORE_CTX*);

class Mock2DefaultThorsSocket: public ThorsAnvil::BuildTools::Mock2::MockFunctionGroupDefault
{
    std::function<ThorsAnvil::ThorsSocket::ConnectionType::HostEnt*(const char*)> getHostByNameMock =[]  (char const*) {
        static char* addrList[] = {""};
        static ThorsAnvil::ThorsSocket::ConnectionType::HostEnt result {.h_length=1, .h_addr_list=addrList};
        return &result;
    };

    MOCK2_MEMBER(read);
    MOCK2_MEMBER(write);
    MOCK2_TMEMBER(OpenType, open);
    MOCK2_MEMBER(close);
    MOCK2_TMEMBER(FctlType, fcntl);
    MOCK2_MEMBER(pipe);
    MOCK2_MEMBER(TLS_client_method);
    MOCK2_MEMBER(TLS_server_method);
    MOCK2_MEMBER(SSL_CTX_new);
    MOCK2_MEMBER(SSL_CTX_free);
    MOCK2_MEMBER(SSL_new);
    MOCK2_MEMBER(SSL_free);
    MOCK2_MEMBER(SSL_set_fd);
    MOCK2_MEMBER(SSL_connect);
    MOCK2_MEMBER(SSL_get_error);
    MOCK2_MEMBER(SSL_get1_peer_certificate);
    MOCK2_MEMBER(X509_free);
    MOCK2_MEMBER(SSL_read);
    MOCK2_MEMBER(SSL_write);
    MOCK2_MEMBER(SSL_shutdown);
    MOCK2_MEMBER(SSL_CTX_ctrl);
    MOCK2_MEMBER(SSL_CTX_set_cipher_list);
    MOCK2_MEMBER(SSL_CTX_set_ciphersuites);
    MOCK2_MEMBER(SSL_CTX_set_default_passwd_cb);
    MOCK2_MEMBER(SSL_CTX_set_default_passwd_cb_userdata);
    MOCK2_MEMBER(SSL_CTX_use_certificate_file);
    MOCK2_MEMBER(SSL_CTX_use_PrivateKey_file);
    MOCK2_MEMBER(SSL_CTX_check_private_key);
    MOCK2_MEMBER(SSL_CTX_set_default_verify_file);
    MOCK2_MEMBER(SSL_CTX_set_default_verify_dir);
    MOCK2_MEMBER(SSL_CTX_set_default_verify_store);
    MOCK2_MEMBER(SSL_CTX_load_verify_file);
    MOCK2_MEMBER(SSL_CTX_load_verify_dir);
    MOCK2_MEMBER(SSL_CTX_load_verify_store);
    MOCK2_MEMBER(SSL_CTX_set_verify);
    MOCK2_MEMBER(SSL_CTX_set_client_CA_list);
    MOCK2_MEMBER(SSL_ctrl);
    MOCK2_MEMBER(SSL_set_cipher_list);
    MOCK2_MEMBER(SSL_set_ciphersuites);
    MOCK2_MEMBER(SSL_set_default_passwd_cb);
    MOCK2_MEMBER(SSL_set_default_passwd_cb_userdata);
    MOCK2_MEMBER(SSL_use_certificate_file);
    MOCK2_MEMBER(SSL_use_PrivateKey_file);
    MOCK2_MEMBER(SSL_check_private_key);
    MOCK2_MEMBER(SSL_add_file_cert_subjects_to_stack);
    MOCK2_MEMBER(SSL_add_dir_cert_subjects_to_stack);
    MOCK2_MEMBER(SSL_add_store_cert_subjects_to_stack);
    MOCK2_MEMBER(SSL_set_verify);
    MOCK2_MEMBER(SSL_set_client_CA_list);
    MOCK2_MEMBER(sk_X509_NAME_new_null_wrapper);
    MOCK2_MEMBER(sk_X509_NAME_free_wrapper);
    MOCK2_MEMBER(sk_X509_NAME_pop_free_wrapper);
    MOCK2_MEMBER(ERR_get_error);
    MOCK2_MEMBER(socket);
    MOCK2_MEMBER(gethostbyname);
    MOCK2_MEMBER(connect);
    MOCK2_MEMBER(shutdown);

    public:
        Mock2DefaultThorsSocket()
            : MOCK2_PARAM(read)
            , MOCK2_PARAM(write)
            , MOCK2_PARAM(open)
            , MOCK2_PARAM(close)
            , MOCK2_PARAM(fcntl)
            , MOCK2_PARAM(pipe)
            , MOCK2_PARAM(TLS_client_method)
            , MOCK2_PARAM(TLS_server_method)
            , MOCK2_PARAM(SSL_CTX_new)
            , MOCK2_PARAM(SSL_CTX_free)
            , MOCK2_PARAM(SSL_new)
            , MOCK2_PARAM(SSL_free)
            , MOCK2_PARAM(SSL_set_fd)
            , MOCK2_PARAM(SSL_connect)
            , MOCK2_PARAM(SSL_get_error)
            , MOCK2_PARAM(SSL_get1_peer_certificate)
            , MOCK2_PARAM(X509_free)
            , MOCK2_PARAM(SSL_read)
            , MOCK2_PARAM(SSL_write)
            , MOCK2_PARAM(SSL_shutdown)
            , MOCK2_PARAM(SSL_CTX_ctrl)
            , MOCK2_PARAM(SSL_CTX_set_cipher_list)
            , MOCK2_PARAM(SSL_CTX_set_ciphersuites)
            , MOCK2_PARAM(SSL_CTX_set_default_passwd_cb)
            , MOCK2_PARAM(SSL_CTX_set_default_passwd_cb_userdata)
            , MOCK2_PARAM(SSL_CTX_use_certificate_file)
            , MOCK2_PARAM(SSL_CTX_use_PrivateKey_file)
            , MOCK2_PARAM(SSL_CTX_check_private_key)
            , MOCK2_PARAM(SSL_CTX_set_default_verify_file)
            , MOCK2_PARAM(SSL_CTX_set_default_verify_dir)
            , MOCK2_PARAM(SSL_CTX_set_default_verify_store)
            , MOCK2_PARAM(SSL_CTX_load_verify_file)
            , MOCK2_PARAM(SSL_CTX_load_verify_dir)
            , MOCK2_PARAM(SSL_CTX_load_verify_store)
            , MOCK2_PARAM(SSL_CTX_set_verify)
            , MOCK2_PARAM(SSL_CTX_set_client_CA_list)
            , MOCK2_PARAM(SSL_ctrl)
            , MOCK2_PARAM(SSL_set_cipher_list)
            , MOCK2_PARAM(SSL_set_ciphersuites)
            , MOCK2_PARAM(SSL_set_default_passwd_cb)
            , MOCK2_PARAM(SSL_set_default_passwd_cb_userdata)
            , MOCK2_PARAM(SSL_use_certificate_file)
            , MOCK2_PARAM(SSL_use_PrivateKey_file)
            , MOCK2_PARAM(SSL_check_private_key)
            , MOCK2_PARAM(SSL_add_file_cert_subjects_to_stack)
            , MOCK2_PARAM(SSL_add_dir_cert_subjects_to_stack)
            , MOCK2_PARAM(SSL_add_store_cert_subjects_to_stack)
            , MOCK2_PARAM(SSL_set_verify)
            , MOCK2_PARAM(SSL_set_client_CA_list)
            , MOCK2_PARAM(sk_X509_NAME_new_null_wrapper)
            , MOCK2_PARAM(sk_X509_NAME_free_wrapper)
            , MOCK2_PARAM(sk_X509_NAME_pop_free_wrapper)
            , MOCK2_PARAM(ERR_get_error)
            , MOCK2_PARAM(socket)
            , MOCK2_PARAM(gethostbyname)
            , MOCK2_PARAM(connect)
            , MOCK2_PARAM(shutdown)
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
