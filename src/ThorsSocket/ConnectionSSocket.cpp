#include "ConnectionSSocket.h"
#include "ThorsLogging/ThorsLogging.h"

#include <map>
#include <openssl/err.h>
#include <iostream>

#define CIPHER_LIST     "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384"

#define CA_FILE         "test/data/root-ca/ca.cert.pem"
#define CA_DIR          nullptr


using namespace ThorsAnvil::ThorsSocket::ConnectionType;
using ThorsAnvil::ThorsSocket::IOResult;

extern "C" int certificateInfo_PasswdCB(char* buf, int size, int rwflag, void* userdata)
{
    CertificateInfo& certificateInfo = *static_cast<CertificateInfo*>(userdata);
    std::string&& password = certificateInfo.getPassword(rwflag);
    if (password.size() > static_cast<std::size_t>(size))
    {
        ThorsLogAndThrow("ThorsAnvil::ThorsSocket::CertificateInfo",
                         "setCertificateInfo",
                         "certificateInfo_PasswdCB failed: password size exceeds max space. Max=", size, " Actual=", password.size());
    }
    for (std::size_t loop = 0; loop < password.size(); ++loop) {
        buf[loop] = std::exchange(password[loop], 'X');
    }
    return password.size();
}

int ProtocolInfo::convertProtocolToOpenSSL(Protocol protocol) const
{
    switch (protocol)
    {
        case TLS_1_0:    return TLS1_VERSION;
        case TLS_1_1:    return TLS1_1_VERSION;
        case TLS_1_2:    return TLS1_2_VERSION;
        case TLS_1_3:    return TLS1_3_VERSION;
    }
    throw std::runtime_error("Fix");
}

void ProtocolInfo::setProtocolInfo(SSL_CTX* ctx) const
{
    //if (SSL_CTX_set_min_proto_version(ctx, convertProtocolToOpenSSL(minProtocol)) != 1)
    if (MOCK_FUNC(SSL_CTX_ctrl)(ctx, SSL_CTRL_SET_MIN_PROTO_VERSION, convertProtocolToOpenSSL(minProtocol), nullptr) != 1)
    {
        ThorsLogAndThrow("ThorsAnvil::ThorsSocket::ProtocolInfo",
                         "setProtocolInfo",
                         "SSL_CTX_set_min_proto_version() failed: ", SSocket::buildErrorMessage());
    }
    //if (SSL_CTX_set_max_proto_version(ctx, convertProtocolToOpenSSL(maxProtocol)) != 1)
    if (MOCK_FUNC(SSL_CTX_ctrl)(ctx, SSL_CTRL_SET_MAX_PROTO_VERSION, convertProtocolToOpenSSL(maxProtocol), nullptr) != 1)
    {
        ThorsLogAndThrow("ThorsAnvil::ThorsSocket::ProtocolInfo",
                         "setProtocolInfo",
                         "SSL_CTX_set_max_proto_version() failed: ", SSocket::buildErrorMessage());
    }
}

void ProtocolInfo::setProtocolInfo(SSL* ssl) const
{
    //if (SSL_set_min_proto_version(ssl, convertProtocolToOpenSSL(minProtocol)) != 1)
    if (MOCK_FUNC(SSL_ctrl)(ssl, SSL_CTRL_SET_MIN_PROTO_VERSION, convertProtocolToOpenSSL(minProtocol), nullptr) != 1)
    {
        ThorsLogAndThrow("ThorsAnvil::ThorsSocket::ProtocolInfo",
                         "setProtocolInfo",
                         "SSL_set_min_proto_version() failed: ", SSocket::buildErrorMessage());
    }
    //if (SSL_set_max_proto_version(ssl, convertProtocolToOpenSSL(maxProtocol)) != 1)
    if (MOCK_FUNC(SSL_ctrl)(ssl, SSL_CTRL_SET_MAX_PROTO_VERSION, convertProtocolToOpenSSL(maxProtocol), nullptr) != 1)
    {
        ThorsLogAndThrow("ThorsAnvil::ThorsSocket::ProtocolInfo",
                         "setProtocolInfo",
                         "SSL_set_max_proto_version() failed: ", SSocket::buildErrorMessage());
    }
}

void CipherInfo::setCipherInfo(SSL_CTX* ctx) const
{
    /*Set the Cipher List*/
    if (MOCK_FUNC(SSL_CTX_set_cipher_list)(ctx, cipherList.c_str()) <= 0)
    {
        ThorsLogAndThrow("ThorsAnvil::ThorsSocket::CipherInfo",
                         "setCipherInfo",
                         "SSL_CTX_set_cipher_list() failed: ", SSocket::buildErrorMessage());
    }
    if (MOCK_FUNC(SSL_CTX_set_ciphersuites)(ctx, cipherSuite.c_str()) <= 0)
    {
        ThorsLogAndThrow("ThorsAnvil::ThorsSocket::CipherInfo",
                         "setCipherInfo",
                         "SSL_CTX_set_ciphersuites() failed: ", SSocket::buildErrorMessage());
    }
}

void CipherInfo::setCipherInfo(SSL* ssl) const
{
    /*Set the Cipher List*/
    if (MOCK_FUNC(SSL_set_cipher_list)(ssl, cipherList.c_str()) <= 0)
    {
        ThorsLogAndThrow("ThorsAnvil::ThorsSocket::CipherInfo",
                         "setCipherInfo",
                         "SSL_set_cipher_list() failed: ", SSocket::buildErrorMessage());
    }
    if (MOCK_FUNC(SSL_set_ciphersuites)(ssl, cipherSuite.c_str()) <= 0)
    {
        ThorsLogAndThrow("ThorsAnvil::ThorsSocket::CipherInfo",
                         "setCipherInfo",
                         "SSL_set_ciphersuites() failed: ", SSocket::buildErrorMessage());
    }
}

CertificateInfo::CertificateInfo()
{}

CertificateInfo::CertificateInfo(std::string const& certificateFileName, std::string const& keyFileName, GetPasswordFunc&& getPassword)
    : certificateFileName(certificateFileName)
    , keyFileName(keyFileName)
    , getPassword(std::move(getPassword))
{
    if (certificateFileName == "" || keyFileName == "")
    {
        ThorsLogAndThrow("ThorsAnvil::ThorsSocket::CertificateInfo",
                         "CertificateInfo",
                         "Either both certificate and key are set or neither are set");
    }
}

void CertificateInfo::setCertificateInfo(SSL_CTX* ctx) const
{
    if (certificateFileName != "")
    {
        /*Load the password for the Private Key*/
        MOCK_FUNC(SSL_CTX_set_default_passwd_cb)(ctx, certificateInfo_PasswdCB);
        MOCK_FUNC(SSL_CTX_set_default_passwd_cb_userdata)(ctx, static_cast<void*>(const_cast<CertificateInfo*>(this)));

        /*Set the certificate to be used.*/
        if (MOCK_FUNC(SSL_CTX_use_certificate_file)(ctx, certificateFileName.c_str(), SSL_FILETYPE_PEM) <= 0)
        {
            ThorsLogAndThrow("ThorsAnvil::ThorsSocket::CertificateInfo",
                             "setCertificateInfo",
                             "SSL_CTX_use_certificate_file() failed: ", SSocket::buildErrorMessage());
        }

        /*Indicate the key file to be used*/
        if (MOCK_FUNC(SSL_CTX_use_PrivateKey_file)(ctx, keyFileName.c_str(), SSL_FILETYPE_PEM) <= 0)
        {
            ThorsLogAndThrow("ThorsAnvil::ThorsSocket::CertificateInfo",
                             "setCertificateInfo",
                             "SSL_CTX_use_PrivateKey_file() failed: ", SSocket::buildErrorMessage());
        }

        /*Make sure the key and certificate file match*/
        if (MOCK_FUNC(SSL_CTX_check_private_key)(ctx) == 0)
        {
            ThorsLogAndThrow("ThorsAnvil::ThorsSocket::CertificateInfo",
                             "setCertificateInfo",
                             "SSL_CTX_check_private_key() failed: ", SSocket::buildErrorMessage());
        }
    }
}

void CertificateInfo::setCertificateInfo(SSL* ssl) const
{
    if (certificateFileName != "")
    {
        /*Load the password for the Private Key*/
        //MOCK_FUNC(SSL_set_default_passwd_cb)(ssl, certificateInfo_PasswdCB);
        MOCK_FUNC(SSL_set_default_passwd_cb_userdata)(ssl, static_cast<void*>(const_cast<CertificateInfo*>(this)));

        /*Set the certificate to be used.*/
        if (MOCK_FUNC(SSL_use_certificate_file)(ssl, certificateFileName.c_str(), SSL_FILETYPE_PEM) <= 0)
        {
            ThorsLogAndThrow("ThorsAnvil::ThorsSocket::CertificateInfo",
                             "setCertificateInfo",
                             "SSL_use_certificate_file() failed: ", SSocket::buildErrorMessage());
        }

        /*Indicate the key file to be used*/
        if (MOCK_FUNC(SSL_use_PrivateKey_file)(ssl, keyFileName.c_str(), SSL_FILETYPE_PEM) <= 0)
        {
            ThorsLogAndThrow("ThorsAnvil::ThorsSocket::CertificateInfo",
                             "setCertificateInfo",
                             "SSL_use_PrivateKey_file() failed: ", SSocket::buildErrorMessage());
        }

        /*Make sure the key and certificate file match*/
        if (MOCK_FUNC(SSL_check_private_key)(ssl) == 0)
        {
            ThorsLogAndThrow("ThorsAnvil::ThorsSocket::CertificateInfo",
                             "setCertificateInfo",
                             "SSL_check_private_key() failed: ", SSocket::buildErrorMessage());
        }
    }
}

template<AuthorityType A>
void CertifcateAuthorityDataInfo<A>::setCertifcateAuthorityInfo(SSL_CTX* ctx) const
{
    int stat = setDefaultCertifcateAuthorityInfo(ctx);
    if (stat != 1)
    {
        ThorsLogAndThrow("ThorsAnvil::ThorsSocket::CertifcateAuthorityDataInfo",
                         "setCertifcateAuthority",
                         "setDefaultCertifcateAuthorityInfo() failed: ", type(), ": ", SSocket::buildErrorMessage());
    }
    for (auto const& item: items)
    {
        if (!item.empty())
        {
            int stat = setOneCertifcateAuthorityInfo(ctx, item.c_str());
            if (stat != 1)
            {
                ThorsLogAndThrow("ThorsAnvil::ThorsSocket::CertifcateAuthorityDataInfo",
                                 "setCertifcateAuthority",
                                 "setDefaultCertifcateAuthorityInfo() failed: ", type(), " ", item, ": " , SSocket::buildErrorMessage());
            }
        }
    }
}

template<> int CertifcateAuthorityDataInfo<File>::setDefaultCertifcateAuthorityInfo(SSL_CTX* ctx)               const {return MOCK_FUNC(SSL_CTX_set_default_verify_file)(ctx);}
template<> int CertifcateAuthorityDataInfo<Dir>::setDefaultCertifcateAuthorityInfo(SSL_CTX* ctx)                const {return MOCK_FUNC(SSL_CTX_set_default_verify_dir)(ctx);}
template<> int CertifcateAuthorityDataInfo<Store>::setDefaultCertifcateAuthorityInfo(SSL_CTX* ctx)              const {return MOCK_FUNC(SSL_CTX_set_default_verify_store)(ctx);}

template<> int CertifcateAuthorityDataInfo<File>::setOneCertifcateAuthorityInfo(SSL_CTX* ctx, char const* item) const {return MOCK_FUNC(SSL_CTX_load_verify_file)(ctx, item);}
template<> int CertifcateAuthorityDataInfo<Dir>::setOneCertifcateAuthorityInfo(SSL_CTX* ctx, char const* item)  const {return MOCK_FUNC(SSL_CTX_load_verify_dir)(ctx, item);}
template<> int CertifcateAuthorityDataInfo<Store>::setOneCertifcateAuthorityInfo(SSL_CTX* ctx, char const* item)const {return MOCK_FUNC(SSL_CTX_load_verify_store)(ctx, item);}

template<> std::string CertifcateAuthorityDataInfo<File>::type()  const {return "CA File";}
template<> std::string CertifcateAuthorityDataInfo<Dir>::type()   const {return "CA Dir";}
template<> std::string CertifcateAuthorityDataInfo<Store>::type() const {return "CA Store";}

void CertifcateAuthorityInfo::setCertifcateAuthorityInfo(SSL_CTX* ctx) const
{
    file.setCertifcateAuthorityInfo(ctx);
    dir.setCertifcateAuthorityInfo(ctx);
    store.setCertifcateAuthorityInfo(ctx);
}

template<> int ClientCAListDataInfo<File>::addCAToList(STACK_OF(X509_NAME)* certs, char const* item)   const {return MOCK_FUNC(SSL_add_file_cert_subjects_to_stack)(certs, item);}
template<> int ClientCAListDataInfo<Dir>::addCAToList(STACK_OF(X509_NAME)* certs, char const* item)    const {return MOCK_FUNC(SSL_add_dir_cert_subjects_to_stack)(certs, item);}
template<> int ClientCAListDataInfo<Store>::addCAToList(STACK_OF(X509_NAME)* certs, char const* item)  const {return MOCK_FUNC(SSL_add_store_cert_subjects_to_stack)(certs, item);}

STACK_OF(X509_NAME)* ClientCAListInfo::buildCAToList() const
{
    auto ignore = MOCK_FUNC(OPENSSL_sk_new_null);

    // This macro calls: OPENSSL_sk_new_null (which is mocked).
    STACK_OF(X509_NAME)* list = sk_X509_NAME_new_null();
    if (list == nullptr)
    {
        ThorsLogAndThrow("ThorsAnvil::ThorsSocket::ClientCAListInfo",
                         "buildCAToList",
                         "sk_X509_NAME_new_null() failed: ", SSocket::buildErrorMessage());
    }
    for (auto const& item: file.items)
    {
        int stat = file.addCAToList(list, item.c_str());
        if (stat != 1)
        {
            ThorsLogAndThrow("ThorsAnvil::ThorsSocket::ClientCAListDataInfo<File>",
                             "addCAToList failed: >", item, "< ", SSocket::buildErrorMessage());
        }
    }
    for (auto const& item: dir.items)
    {
        int stat = dir.addCAToList(list, item.c_str());
        if (stat != 1)
        {
            ThorsLogAndThrow("ThorsAnvil::ThorsSocket::ClientCAListDataInfo<Dir>",
                             "addCAToList failed: >", item, "< ", SSocket::buildErrorMessage());
        }
    }
    for (auto const& item: store.items)
    {
        int stat = store.addCAToList(list, item.c_str());
        if (stat != 1)
        {
            ThorsLogAndThrow("ThorsAnvil::ThorsSocket::ClientCAListDataInfo<Store>",
                             "addCAToList failed: >", item, "< ", SSocket::buildErrorMessage());
        }
    }
    return list;
}

void ClientCAListInfo::setCertifcateAuthorityInfo(SSL_CTX* ctx) const
{
    if (verifyClientCA) {
        MOCK_FUNC(SSL_CTX_set_verify)(ctx, SSL_VERIFY_PEER|SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
    }
    MOCK_FUNC(SSL_CTX_set_client_CA_list)(ctx, buildCAToList());
};

void ClientCAListInfo::setCertifcateAuthorityInfo(SSL* ssl) const
{
    if (verifyClientCA) {
        MOCK_FUNC(SSL_set_verify)(ssl, SSL_VERIFY_PEER|SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
    }
    MOCK_FUNC(SSL_set_client_CA_list)(ssl, buildCAToList());
};

SSLUtil::SSLUtil()
{
    SSL_load_error_strings();
    SSL_library_init();
    //OPENSSL_init_ssl(OPENSSL_INIT_LOAD_SSL_STRINGS, nullptr);
}

SSLUtil& SSLUtil::getInstance()
{
    static SSLUtil  instance;
    return instance;
}

SSLctx::SSLctx(SSLMethodType methodType,
               ProtocolInfo protocolRange,
               CipherInfo const& cipherList,
               CertificateInfo const& certificate,
               CertifcateAuthorityInfo const& certifcateAuthority,
               ClientCAListInfo const& clientCAList)
    : ctx(nullptr)
{
    SSLUtil::getInstance();
    SSL_METHOD const*  method;
    if (methodType == SSLMethodType::Client) {
        method = MOCK_FUNC(TLS_client_method)(); // SSLv23_client_method();
    }
    else {
        method = MOCK_FUNC(TLS_server_method)();
    }

    if (method == nullptr)
    {
        ThorsLogAndThrow("ThorsAnvil::THorsSocket::SSLctx",
                         "SSLctx",
                         "TLS_client_method() failed: ", SSocket::buildErrorMessage());
    }

    ctx = MOCK_FUNC(SSL_CTX_new)(method);
    if (ctx == nullptr)
    {
        ThorsLogAndThrow("ThorsAnvil::ThorsSocket::SSLctx",
                         "SSLctx",
                         "SSL_CTX_new() failed: ", SSocket::buildErrorMessage());
    }

    protocolRange.setProtocolInfo(ctx);
    cipherList.setCipherInfo(ctx);
    certificate.setCertificateInfo(ctx);
    certifcateAuthority.setCertifcateAuthorityInfo(ctx);
    clientCAList.setCertifcateAuthorityInfo(ctx);
}

#if 0
SSLctx::SSLctx(SSLMethod& method, std::string const& certFile, std::string const& keyFile)
    : SSLctx(method)
{
#if (OPENSSL_VERSION_NUMBER >= 0x10002000)
    if (SSL_CTX_set_ecdh_auto(ctx, 1) != 1)
    {
        SSL_CTX_free(ctx);
        ThorsLogAndThrow("ThorsAnvil::ThorsSocket::SSLctx",
                         "SSLctx",
                         "SSL_CTX_set_ecdh_auto() failed: ", SSLUtil::errorMessage());
    }
#endif
// SSL_CTX_check_private_key
// SSL_CTX_load_verify_locations
// SSL_CTX_set_verify

//Server Only
// SSL_CTX_load_and_set_client_CA_file
}
#endif

SSLctx::~SSLctx()
{
    MOCK_FUNC(SSL_CTX_free)(ctx);
}

SSocket::SSocket(SSLctx const& ctx, std::string const& host, int port, Blocking blocking, CertificateInfo&& info)
    : Socket(host, port, blocking)
    , ssl(nullptr)
{
    ssl = MOCK_FUNC(SSL_new)(ctx.ctx);
    if (!ssl)
    {
        Socket::close();
        ThorsLogAndThrow("ThorsAnvil::ThorsSocket::ConnectionType::SSocket",
                         "SSocket",
                         "SSL_new() failed: ", buildErrorMessage());
    }

    info.setCertificateInfo(ssl);

    int ret;
    int error;
    if ((ret = MOCK_FUNC(SSL_set_fd)(ssl, socketId(Mode::Read))) != 1)
    {
        MOCK_FUNC(SSL_free)(ssl);
        Socket::close();
        ThorsLogAndThrow("ThorsAnvil::ThorsSocket::ConnectionType::SSocket",
                         "SSocket",
                         "SSL_set_fd() failed: ", buildErrorMessage());
    }

    do
    {
        ret = MOCK_FUNC(SSL_connect)(ssl);
        if (ret != 1)
        {
            // If you open a non blocking connection.
            // It may take a while to get all the information you need
            // If you are simply waiting then you have to keep going.
            //
            // TODO: Opportunity for yield()?
            error = MOCK_FUNC(SSL_get_error)(ssl, ret);
            if (error == SSL_ERROR_WANT_CONNECT || error == SSL_ERROR_WANT_READ || error == SSL_ERROR_WANT_WRITE) {
                continue;
            }
        }
        break;
    }
    while (true);

    if (ret != 1)
    {
        MOCK_FUNC(SSL_free)(ssl);
        Socket::close();
        ThorsLogAndThrow("ThorsAnvil::ThorsSocket::SSocket",
                         "SSocket",
                         "SSL_connect() failed: ", buildErrorMessage(error));
    }


    X509* cert = MOCK_FUNC(SSL_get1_peer_certificate)(ssl);
    if (cert == nullptr)
    {
        MOCK_FUNC(SSL_free)(ssl);
        Socket::close();
        ThorsLogAndThrow("ThorsAnvil::ThorsSocket::SSocket",
                         "SSocket",
                         "SSL_connect() failed: ", buildErrorMessage());
    }
}

SSocket::SSocket(int fd, SSLctx const& ctx, CertificateInfo&& info)
    : Socket(fd)
{
    /*Create new ssl object*/
    ssl = SSL_new(ctx.ctx);
    if (ssl == nullptr)
    {
        Socket::close();
        ThorsLogAndThrow("ThorsAnvil::ThorsSocket::ConnectionType::SSocket",
                         "SSocket",
                         "SSL_new() failed: ", buildErrorMessage());
    }

    info.setCertificateInfo(ssl);

    /* Bind the ssl object with the socket*/
    SSL_set_fd(ssl, fd);

    /*Do the SSL Handshake*/
    int status;
    do
    {
        status = SSL_accept(ssl);
        if (status != 1)
        {
            int error = SSL_get_error(ssl, status);
            if (error == SSL_ERROR_WANT_ACCEPT || error == SSL_ERROR_WANT_READ || error == SSL_ERROR_WANT_WRITE) {
                continue;
            }
        }
        break;
    }
    while (true);

    /* Check for error in handshake*/
    if (status < 1)
    {
        int error = SSL_get_error(ssl, status);
        Socket::close();
        ThorsLogAndThrow("ThorsAnvil::ThorsSocket::ConnectionType::SSocket",
                         "SSocket",
                         "SSL_ccept() failed: ", buildErrorMessage(error));
    }

    /* Check for Client authentication error */
    if (SSL_get_verify_result(ssl) != X509_V_OK)
    {
        ::SSL_free(ssl);
        Socket::close();
        ThorsLogAndThrow("ThorsAnvil::ThorsSocket::ConnectionType::SSocket",
                         "SSocket",
                         "SSL_get_verify_result() failed: ", buildErrorMessage());
    }
}

SSocket::~SSocket()
{
    close();
}

void SSocket::tryFlushBuffer()
{
}

IOResult SSocket::read(char* buffer, std::size_t size, std::size_t read)
{
    int ret = MOCK_FUNC(SSL_read)(ssl, buffer + read, size - read);
    Result  result   = Result::OK;
    switch (MOCK_FUNC(SSL_get_error)(ssl, ret))
    {
        case SSL_ERROR_NONE:
        {
            read += ret;
            // Note result is Already OK.
            break;
        }
        case SSL_ERROR_WANT_WRITE:          // should not happen on a read.
        case SSL_ERROR_WANT_CONNECT:
        case SSL_ERROR_WANT_ACCEPT:
        case SSL_ERROR_SYSCALL:
        case SSL_ERROR_SSL:
            result = Result::CriticalBug;
            break;
        case SSL_ERROR_ZERO_RETURN:
            result = Result::ConnectionClosed;
            break;
        case SSL_ERROR_WANT_READ:
            result = Result::WouldBlock;
            break;
        case SSL_ERROR_WANT_X509_LOOKUP:    // Not sure what to do here.
        case SSL_ERROR_WANT_CLIENT_HELLO_CB:
        case SSL_ERROR_WANT_ASYNC:
        case SSL_ERROR_WANT_ASYNC_JOB:
        default:
        {
            result = Result::Unknown;
            break;
        }
    }
    return {read, result};
}

IOResult SSocket::write(char const* buffer, std::size_t size, std::size_t written)
{
    int ret = MOCK_FUNC(SSL_write)(ssl, buffer + written, size - written);
    Result  result   = Result::OK;
    switch (MOCK_FUNC(SSL_get_error)(ssl, ret))
    {
        case SSL_ERROR_NONE:
        {
            written += ret;
            // Note result is Already OK.
            break;
        }
        case SSL_ERROR_WANT_READ:           // should not happen on a read.
        case SSL_ERROR_WANT_CONNECT:
        case SSL_ERROR_WANT_ACCEPT:
        case SSL_ERROR_SYSCALL:
        case SSL_ERROR_SSL:
            result = Result::CriticalBug;
            break;
        case SSL_ERROR_ZERO_RETURN:
            result = Result::ConnectionClosed;
            break;
        case SSL_ERROR_WANT_WRITE:
            result = Result::WouldBlock;
            break;
        case SSL_ERROR_WANT_X509_LOOKUP:    // Not sure what to do here.
        case SSL_ERROR_WANT_CLIENT_HELLO_CB:
        case SSL_ERROR_WANT_ASYNC:
        case SSL_ERROR_WANT_ASYNC_JOB:
        default:
        {
            result = Result::Unknown;
            break;
        }
    }
    return {written, result};
}

void SSocket::close()
{
    if (ssl)
    {
        // Close the file descriptor
        MOCK_FUNC(SSL_shutdown)(ssl);
        MOCK_FUNC(SSL_free)(ssl);
        ssl = nullptr;
    }
    Socket::close();
}

bool SSocket::isConnected() const
{
    return ssl != nullptr;
}

std::string SSocket::errorMessage(ssize_t ret)
{
    int error = MOCK_FUNC(SSL_get_error)(ssl, ret);
    return buildErrorMessage(error);
}

std::string SSocket::buildErrorMessage(int error)
{
    static const std::map<int, char const*> errorString =
    {
        {SSL_ERROR_NONE, "SSL_ERROR_NONE"},                         {SSL_ERROR_NONE, "SSL_ERROR_NONE"},
        {SSL_ERROR_WANT_READ, "SSL_ERROR_WANT_READ"},               {SSL_ERROR_WANT_WRITE, "SSL_ERROR_WANT_WRITE"},
        {SSL_ERROR_WANT_CONNECT, "SSL_ERROR_WANT_CONNECT"},         {SSL_ERROR_WANT_ACCEPT, "SSL_ERROR_WANT_ACCEPT"},
        {SSL_ERROR_WANT_X509_LOOKUP, "SSL_ERROR_WANT_X509_LOOKUP"}, {SSL_ERROR_WANT_ASYNC, "SSL_ERROR_WANT_ASYNC"},
        {SSL_ERROR_WANT_ASYNC_JOB, "SSL_ERROR_WANT_ASYNC_JOB"},     {SSL_ERROR_WANT_CLIENT_HELLO_CB, "SSL_ERROR_WANT_CLIENT_HELLO_CB"},
        {SSL_ERROR_SYSCALL, "SSL_ERROR_SYSCALL"},                   {SSL_ERROR_SSL, "SSL_ERROR_SSL"}
    };
    auto find = errorString.find(error);
    char const* errorName = find == errorString.end() ? "Unknown" : find->second;

    std::stringstream result;
    result << "ConnectionType::SSocket: SSLErrorCode =" << error << "(" << errorName << "): msg: " << buildErrorMessage(false);
    return result.str();
}

std::string SSocket::buildErrorMessage(bool prefix)
{
    bool errorAdded = false;
    std::stringstream result;
    if (prefix) {
        result << "ConnectionType::SSocket: ";
    }
    for (long code = MOCK_FUNC(ERR_get_error)(); code != 0; code = MOCK_FUNC(ERR_get_error)())
    {
        errorAdded = true;
        result << "ErrorCode=" << code << ": msg: " << ERR_error_string(code, nullptr) << ":";
    }
    if (!errorAdded) {
        result << "No error codes found!";
    }
    return result.str();
}
#if 0
std::string sslError(SSL* ssl, int ret)
{
    int error = SSL_get_error(ssl, ret);
    switch (error)
    {
        // The TLS/SSL I/O operation completed. This result code is returned if and only if ret > 0.
        case SSL_ERROR_NONE:            return "SSL_ERROR_NONE";

        // The TLS/SSL peer has closed the connection for writing by sending the "close notify" alert. No more data can be read. Note that SSL_ERROR_ZERO_RETURN does not necessarily indicate that the underlying transport has been closed.
        case SSL_ERROR_ZERO_RETURN:     return "SSL_ERROR_ZERO_RETURN";

        // The operation did not complete and can be retried later.
        // SSL_ERROR_WANT_READ is returned when the last operation was a read operation from a non-blocking BIO.
        // It means that not enough data was available at this time to complete the operation.
        // If at a later time the underlying BIO has data available for reading the same function can be called again.
        // SSL_read() and SSL_read_ex() can also set SSL_ERROR_WANT_READ when there is still unprocessed data available at either the SSL or the BIO layer, even for a blocking BIO.
        // See SSL_read(3) for more information.
        // SSL_ERROR_WANT_WRITE is returned when the last operation was a write to a non-blocking BIO and it was unable to sent all data to the BIO.
        // When the BIO is writeable again, the same function can be called again.
        // Note that the retry may again lead to an SSL_ERROR_WANT_READ or SSL_ERROR_WANT_WRITE condition.
        // There is no fixed upper limit for the number of iterations that may be necessary until progress becomes visible at application protocol level.
        // It is safe to call SSL_read() or SSL_read_ex() when more data is available even when the call that set this error was an SSL_write() or SSL_write_ex().
        // However if the call was an SSL_write() or SSL_write_ex(), it should be called again to continue sending the application data.
        // For socket BIOs (e.g. when SSL_set_fd() was used), select() or poll() on the underlying socket can be used to find out when the TLS/SSL I/O function should be retried.
        // Caveat: Any TLS/SSL I/O function can lead to either of SSL_ERROR_WANT_READ and SSL_ERROR_WANT_WRITE.
        // In particular, SSL_read_ex(), SSL_read(), SSL_peek_ex(), or SSL_peek() may want to write data and SSL_write() or SSL_write_ex() may want to read data.
        // This is mainly because TLS/SSL handshakes may occur at any time during the protocol (initiated by either the client or the server); SSL_read_ex(), SSL_read(), SSL_peek_ex(), SSL_peek(), SSL_write_ex(), and SSL_write() will handle any pending handshakes.
        case SSL_ERROR_WANT_READ:       return "SSL_ERROR_WANT_READ";
        case SSL_ERROR_WANT_WRITE:      return "SSL_ERROR_WANT_WRITE";


        // The operation did not complete; the same TLS/SSL I/O function should be called again later.
        // The underlying BIO was not connected yet to the peer and the call would block in connect()/accept().
        // The SSL function should be called again when the connection is established.
        // These messages can only appear with a BIO_s_connect() or BIO_s_accept() BIO, respectively.
        // In order to find out, when the connection has been successfully established, on many platforms select() or poll() for writing on the socket file descriptor can be used.
        case SSL_ERROR_WANT_CONNECT:    return "SSL_ERROR_WANT_CONNECT";
        case SSL_ERROR_WANT_ACCEPT:     return "SSL_ERROR_WANT_ACCEPT";

        // The operation did not complete because an application callback set by SSL_CTX_set_client_cert_cb() has asked to be called again.
        // The TLS/SSL I/O function should be called again later. Details depend on the application.
        case SSL_ERROR_WANT_X509_LOOKUP:return "SSL_ERROR_WANT_X509_LOOKUP";

#ifdef SSL_ERROR_WANT_ASYNC
        // The operation did not complete because an asynchronous engine is still processing data.
        // This will only occur if the mode has been set to SSL_MODE_ASYNC using SSL_CTX_set_mode(3) or SSL_set_mode(3) and an asynchronous capable engine is being used.
        // An application can determine whether the engine has completed its processing using select() or poll() on the asynchronous wait file descriptor.
        // This file descriptor is available by calling SSL_get_all_async_fds(3) or SSL_get_changed_async_fds(3).
        // The TLS/SSL I/O function should be called again later. The function must be called from the same thread that the original call was made from.
        case SSL_ERROR_WANT_ASYNC:      return "SSL_ERROR_WANT_ASYNC";
#endif

#ifdef SSL_ERROR_WANT_ASYNC_JOB
        // The asynchronous job could not be started because there were no async jobs available in the pool (see ASYNC_init_thread(3)).
        // This will only occur if the mode has been set to SSL_MODE_ASYNC using SSL_CTX_set_mode(3) or SSL_set_mode(3) and a maximum limit has been set on the async job pool through a call to ASYNC_init_thread(3).
        // The application should retry the operation after a currently executing asynchronous operation for the current thread has completed.
        case SSL_ERROR_WANT_ASYNC_JOB:  return "SSL_ERROR_WANT_ASYNC_JOB";
#endif

#ifdef SSL_ERROR_WANT_CLIENT_HELLO_CB
        // The operation did not complete because an application callback set by SSL_CTX_set_client_hello_cb() has asked to be called again.
        // The TLS/SSL I/O function should be called again later. Details depend on the application.
        case SSL_ERROR_WANT_CLIENT_HELLO_CB: return "SSL_ERROR_WANT_CLIENT_HELLO_CB";
#endif

        // Some non-recoverable I/O error occurred.
        // The OpenSSL error queue may contain more information on the error.
        // For socket I/O on Unix systems, consult errno for details.
        case SSL_ERROR_SYSCALL:         return std::string("SSL_ERROR_SYSCALL: ") + systemErrorMessage();

        // This value can also be returned for other errors, check the error queue for details.
        case SSL_ERROR_SSL:             return "SSL_ERROR_SSL";
        default:
            break;
    }
    return "";
}
#endif
