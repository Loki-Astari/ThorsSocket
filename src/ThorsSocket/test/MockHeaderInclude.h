#ifndef THORSANVIl_THORS_SOCKET_MOCK_HEADER_INCLUDE
#define THORSANVIl_THORS_SOCKET_MOCK_HEADER_INCLUDE

#include <functional>

// Please add includes for all mocked libraries here.
// PART-1-Start

#include <utility>

#include "ConnectionSSocket.h"

#include <fcntl.h>
#include <netdb.h>
#include <sys/socket.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

// PART-1-End
namespace ThorsAnvil::BuildTools::Mock
{

// Please define all FuncType_<XXX> here
// There should be one for each MOCK_TFUNC you use in the code.
// The make files will provide the declaration but these need to be filled in by
// the developer and committed to source control
// PART-2-Start
using FuncType_open     = int(const char*, int, unsigned short);
using FuncType_fcntl    = int(int, int, int);

typedef int (*CB)(char*, int, int, void*);
typedef int (*VCB)(int, X509_STORE_CTX*);

// PART-2-End
// This default implementation of overridden functions
// Please provide a lambda for the implementation
// When you add/remove a MOCK_FUNC or MOCK_TFUNC to the source
// This list will be updated.

}

#include "coverage/MockHeaders.h"

namespace ThorsAnvil::BuildTools::Mock
{
class MockAllDefaultFunctions
{
    int version;
// PART-3-Start
    std::function<hostent*(const char*)> getHostByNameMock =[]  (char const*) {
        static char const* addrList[] = {""};
        static hostent result;
        result.h_length=1;
        result.h_addr_list = const_cast<char**>(addrList);
        return &result;
    };

    MOCK_MEMBER(read);
    MOCK_MEMBER(write);
    MOCK_MEMBER(send);
    MOCK_MEMBER(recv);
    MOCK_TMEMBER(open);
    MOCK_MEMBER(close);
    MOCK_MEMBER(thorCloseSocket);
    MOCK_MEMBER(thorCreatePipe);
    MOCK_MEMBER(thorSetFDNonBlocking);
    MOCK_MEMBER(thorSetSocketNonBlocking);
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
    MOCK_MEMBER(thorShutdownSocket);
// PART-3-End

    public:
        MockAllDefaultFunctions()
            : version(2)
// PART-4-Start
            , MOCK_PARAM(read,                                  [ ](int, void*, ssize_t size)           {return size;})
            , MOCK_PARAM(write,                                 [ ](int, void const*, ssize_t size)     {return size;})
            , MOCK_PARAM(send,                                  [ ](int, const void*, size_t len, int)  {return len;})
            , MOCK_PARAM(recv,                                  [ ](int, void*, size_t len, int)        {return len;})
            , MOCK_PARAM(open,                                  [ ](char const*, int, int)              {return 12;})
            , MOCK_PARAM(close,                                 [ ](int)                                {return 0;})
            , MOCK_PARAM(thorCloseSocket,                       [ ](int)                                {return 0;})
            , MOCK_PARAM(thorCreatePipe,                        [ ](int* p)                             {p[0] = 12; p[1] =13;return 0;})
            , MOCK_PARAM(thorSetFDNonBlocking,                  [ ](int)                                {return 0;})
            , MOCK_PARAM(thorSetSocketNonBlocking,              [ ](int)                                {return 0;})
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
            , MOCK_PARAM(connect,                               [ ](int, sockaddr const*, unsigned int) {return 0;})
            , MOCK_PARAM(thorShutdownSocket,                    [ ](int)                                {return 0;})
// PART-4-End
        {}
};


}

#endif

