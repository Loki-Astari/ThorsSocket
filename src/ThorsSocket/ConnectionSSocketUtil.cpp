#include "ConnectionSSocketUtil.h"
#include "ThorsLogging/ThorsLogging.h"
#include <openssl/err.h>
#include <iostream>
#include <utility>

using namespace ThorsAnvil::ThorsSocket::ConnectionType;

THORS_SOCKET_HEADER_ONLY_INCLUDE
extern "C" int certificateInfo_PasswdCB(char* buf, int size, int rwflag, void* userdata)
{
    return ThorsAnvil::ThorsSocket::ConnectionType::certificateInfo_PasswdCBNormal(buf, size, rwflag, userdata);
}

THORS_SOCKET_HEADER_ONLY_INCLUDE
int ThorsAnvil::ThorsSocket::ConnectionType::certificateInfo_PasswdCBNormal(char* buf, int size, int rwflag, void* userdata)
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

THORS_SOCKET_HEADER_ONLY_INCLUDE
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

THORS_SOCKET_HEADER_ONLY_INCLUDE
void ProtocolInfo::apply(SSL_CTX* ctx) const
{
    //if (SSL_CTX_set_min_proto_version(ctx, convertProtocolToOpenSSL(minProtocol)) != 1)
    if (MOCK_FUNC(SSL_CTX_ctrl)(ctx, SSL_CTRL_SET_MIN_PROTO_VERSION, convertProtocolToOpenSSL(minProtocol), nullptr) != 1)
    {
        ThorsLogAndThrow("ThorsAnvil::ThorsSocket::ProtocolInfo",
                         "setProtocolInfo",
                         "SSL_CTX_set_min_proto_version() failed: ", buildOpenSSLErrorMessage());
    }
    //if (SSL_CTX_set_max_proto_version(ctx, convertProtocolToOpenSSL(maxProtocol)) != 1)
    if (MOCK_FUNC(SSL_CTX_ctrl)(ctx, SSL_CTRL_SET_MAX_PROTO_VERSION, convertProtocolToOpenSSL(maxProtocol), nullptr) != 1)
    {
        ThorsLogAndThrow("ThorsAnvil::ThorsSocket::ProtocolInfo",
                         "setProtocolInfo",
                         "SSL_CTX_set_max_proto_version() failed: ", buildOpenSSLErrorMessage());
    }
}

THORS_SOCKET_HEADER_ONLY_INCLUDE
void ProtocolInfo::apply(SSL* ssl) const
{
    //if (SSL_set_min_proto_version(ssl, convertProtocolToOpenSSL(minProtocol)) != 1)
    if (MOCK_FUNC(SSL_ctrl)(ssl, SSL_CTRL_SET_MIN_PROTO_VERSION, convertProtocolToOpenSSL(minProtocol), nullptr) != 1)
    {
        ThorsLogAndThrow("ThorsAnvil::ThorsSocket::ProtocolInfo",
                         "setProtocolInfo",
                         "SSL_set_min_proto_version() failed: ", buildOpenSSLErrorMessage());
    }
    //if (SSL_set_max_proto_version(ssl, convertProtocolToOpenSSL(maxProtocol)) != 1)
    if (MOCK_FUNC(SSL_ctrl)(ssl, SSL_CTRL_SET_MAX_PROTO_VERSION, convertProtocolToOpenSSL(maxProtocol), nullptr) != 1)
    {
        ThorsLogAndThrow("ThorsAnvil::ThorsSocket::ProtocolInfo",
                         "setProtocolInfo",
                         "SSL_set_max_proto_version() failed: ", buildOpenSSLErrorMessage());
    }
}

THORS_SOCKET_HEADER_ONLY_INCLUDE
void CipherInfo::apply(SSL_CTX* ctx) const
{
    /*Set the Cipher List*/
    if (MOCK_FUNC(SSL_CTX_set_cipher_list)(ctx, cipherList.c_str()) <= 0)
    {
        ThorsLogAndThrow("ThorsAnvil::ThorsSocket::CipherInfo",
                         "setCipherInfo",
                         "SSL_CTX_set_cipher_list() failed: ", buildOpenSSLErrorMessage());
    }
    if (MOCK_FUNC(SSL_CTX_set_ciphersuites)(ctx, cipherSuite.c_str()) <= 0)
    {
        ThorsLogAndThrow("ThorsAnvil::ThorsSocket::CipherInfo",
                         "setCipherInfo",
                         "SSL_CTX_set_ciphersuites() failed: ", buildOpenSSLErrorMessage());
    }
}

THORS_SOCKET_HEADER_ONLY_INCLUDE
void CipherInfo::apply(SSL* ssl) const
{
    /*Set the Cipher List*/
    if (MOCK_FUNC(SSL_set_cipher_list)(ssl, cipherList.c_str()) <= 0)
    {
        ThorsLogAndThrow("ThorsAnvil::ThorsSocket::CipherInfo",
                         "setCipherInfo",
                         "SSL_set_cipher_list() failed: ", buildOpenSSLErrorMessage());
    }
    if (MOCK_FUNC(SSL_set_ciphersuites)(ssl, cipherSuite.c_str()) <= 0)
    {
        ThorsLogAndThrow("ThorsAnvil::ThorsSocket::CipherInfo",
                         "setCipherInfo",
                         "SSL_set_ciphersuites() failed: ", buildOpenSSLErrorMessage());
    }
}

THORS_SOCKET_HEADER_ONLY_INCLUDE
CertificateInfo::CertificateInfo()
{}

THORS_SOCKET_HEADER_ONLY_INCLUDE
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

THORS_SOCKET_HEADER_ONLY_INCLUDE
void CertificateInfo::apply(SSL_CTX* ctx) const
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
                             "SSL_CTX_use_certificate_file() failed: ", buildOpenSSLErrorMessage());
        }

        /*Indicate the key file to be used*/
        if (MOCK_FUNC(SSL_CTX_use_PrivateKey_file)(ctx, keyFileName.c_str(), SSL_FILETYPE_PEM) <= 0)
        {
            ThorsLogAndThrow("ThorsAnvil::ThorsSocket::CertificateInfo",
                             "setCertificateInfo",
                             "SSL_CTX_use_PrivateKey_file() failed: ", buildOpenSSLErrorMessage());
        }

        /*Make sure the key and certificate file match*/
        if (MOCK_FUNC(SSL_CTX_check_private_key)(ctx) == 0)
        {
            ThorsLogAndThrow("ThorsAnvil::ThorsSocket::CertificateInfo",
                             "setCertificateInfo",
                             "SSL_CTX_check_private_key() failed: ", buildOpenSSLErrorMessage());
        }
    }
}

THORS_SOCKET_HEADER_ONLY_INCLUDE
void CertificateInfo::apply(SSL* ssl) const
{
    if (certificateFileName != "")
    {
        /*Load the password for the Private Key*/
        MOCK_FUNC(SSL_set_default_passwd_cb)(ssl, certificateInfo_PasswdCB);
        MOCK_FUNC(SSL_set_default_passwd_cb_userdata)(ssl, static_cast<void*>(const_cast<CertificateInfo*>(this)));

        /*Set the certificate to be used.*/
        if (MOCK_FUNC(SSL_use_certificate_file)(ssl, certificateFileName.c_str(), SSL_FILETYPE_PEM) <= 0)
        {
            ThorsLogAndThrow("ThorsAnvil::ThorsSocket::CertificateInfo",
                             "setCertificateInfo",
                             "SSL_use_certificate_file() failed: ", buildOpenSSLErrorMessage());
        }

        /*Indicate the key file to be used*/
        if (MOCK_FUNC(SSL_use_PrivateKey_file)(ssl, keyFileName.c_str(), SSL_FILETYPE_PEM) <= 0)
        {
            ThorsLogAndThrow("ThorsAnvil::ThorsSocket::CertificateInfo",
                             "setCertificateInfo",
                             "SSL_use_PrivateKey_file() failed: ", buildOpenSSLErrorMessage());
        }

        /*Make sure the key and certificate file match*/
        if (MOCK_FUNC(SSL_check_private_key)(ssl) == 0)
        {
            ThorsLogAndThrow("ThorsAnvil::ThorsSocket::CertificateInfo",
                             "setCertificateInfo",
                             "SSL_check_private_key() failed: ", buildOpenSSLErrorMessage());
        }
    }
}

THORS_SOCKET_HEADER_ONLY_INCLUDE
template<AuthorityType A>
void CertifcateAuthorityDataInfo<A>::apply(SSL_CTX* ctx) const
{
    if (loadDefault)
    {
        int stat = setDefaultCertifcateAuthorityInfo(ctx);
        if (stat != 1)
        {
            ThorsLogAndThrow("ThorsAnvil::ThorsSocket::CertifcateAuthorityDataInfo",
                             "setCertifcateAuthority",
                             "setDefaultCertifcateAuthorityInfo() failed: ", type(), ": ", buildOpenSSLErrorMessage());
        }
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
                                 "setDefaultCertifcateAuthorityInfo() failed: ", type(), " ", item, ": " , buildOpenSSLErrorMessage());
            }
        }
    }
}

THORS_SOCKET_HEADER_ONLY_INCLUDE
template<> int CertifcateAuthorityDataInfo<File>::setDefaultCertifcateAuthorityInfo(SSL_CTX* ctx)               const {return MOCK_FUNC(SSL_CTX_set_default_verify_file)(ctx);}
THORS_SOCKET_HEADER_ONLY_INCLUDE
template<> int CertifcateAuthorityDataInfo<Dir>::setDefaultCertifcateAuthorityInfo(SSL_CTX* ctx)                const {return MOCK_FUNC(SSL_CTX_set_default_verify_dir)(ctx);}
THORS_SOCKET_HEADER_ONLY_INCLUDE
template<> int CertifcateAuthorityDataInfo<Store>::setDefaultCertifcateAuthorityInfo(SSL_CTX* ctx)              const {return MOCK_FUNC(SSL_CTX_set_default_verify_store)(ctx);}

THORS_SOCKET_HEADER_ONLY_INCLUDE
template<> int CertifcateAuthorityDataInfo<File>::setOneCertifcateAuthorityInfo(SSL_CTX* ctx, char const* item) const {return MOCK_FUNC(SSL_CTX_load_verify_file)(ctx, item);}
THORS_SOCKET_HEADER_ONLY_INCLUDE
template<> int CertifcateAuthorityDataInfo<Dir>::setOneCertifcateAuthorityInfo(SSL_CTX* ctx, char const* item)  const {return MOCK_FUNC(SSL_CTX_load_verify_dir)(ctx, item);}
THORS_SOCKET_HEADER_ONLY_INCLUDE
template<> int CertifcateAuthorityDataInfo<Store>::setOneCertifcateAuthorityInfo(SSL_CTX* ctx, char const* item)const {return MOCK_FUNC(SSL_CTX_load_verify_store)(ctx, item);}

THORS_SOCKET_HEADER_ONLY_INCLUDE
template<> std::string CertifcateAuthorityDataInfo<File>::type()  const {return "CA File";}
THORS_SOCKET_HEADER_ONLY_INCLUDE
template<> std::string CertifcateAuthorityDataInfo<Dir>::type()   const {return "CA Dir";}
THORS_SOCKET_HEADER_ONLY_INCLUDE
template<> std::string CertifcateAuthorityDataInfo<Store>::type() const {return "CA Store";}

THORS_SOCKET_HEADER_ONLY_INCLUDE
void CertifcateAuthorityInfo::apply(SSL_CTX* ctx) const
{
    file.apply(ctx);
    dir.apply(ctx);
    store.apply(ctx);
}

THORS_SOCKET_HEADER_ONLY_INCLUDE
template<> int ClientCAListDataInfo<File>::addCAToList(STACK_OF(X509_NAME)* certs, char const* item)   const {return MOCK_FUNC(SSL_add_file_cert_subjects_to_stack)(certs, item);}
THORS_SOCKET_HEADER_ONLY_INCLUDE
template<> int ClientCAListDataInfo<Dir>::addCAToList(STACK_OF(X509_NAME)* certs, char const* item)    const {return MOCK_FUNC(SSL_add_dir_cert_subjects_to_stack)(certs, item);}
THORS_SOCKET_HEADER_ONLY_INCLUDE
template<> int ClientCAListDataInfo<Store>::addCAToList(STACK_OF(X509_NAME)* certs, char const* item)  const {return MOCK_FUNC(SSL_add_store_cert_subjects_to_stack)(certs, item);}

THORS_SOCKET_HEADER_ONLY_INCLUDE
STACK_OF(X509_NAME)* ClientCAListInfo::buildCAToList() const
{
    if (file.items.size() + dir.items.size() + store.items.size() == 0) {
        return nullptr;
    }

    // This macro calls: OPENSSL_sk_new_null (which is mocked).
    STACK_OF(X509_NAME)* list = MOCK_FUNC(sk_X509_NAME_new_null_wrapper)();
    if (list == nullptr)
    {
        MOCK_FUNC(sk_X509_NAME_free_wrapper)(list);
        ThorsLogAndThrow("ThorsAnvil::ThorsSocket::ClientCAListInfo",
                         "buildCAToList",
                         "sk_X509_NAME_new_null() failed: ", buildOpenSSLErrorMessage());
    }
    for (auto const& item: file.items)
    {
        int stat = file.addCAToList(list, item.c_str());
        if (stat != 1)
        {
            MOCK_FUNC(sk_X509_NAME_pop_free_wrapper)(list);
            ThorsLogAndThrow("ThorsAnvil::ThorsSocket::ClientCAListDataInfo<File>",
                             "addCAToList failed: >", item, "< ", buildOpenSSLErrorMessage());
        }
    }
    for (auto const& item: dir.items)
    {
        int stat = dir.addCAToList(list, item.c_str());
        if (stat != 1)
        {
            MOCK_FUNC(sk_X509_NAME_pop_free_wrapper)(list);
            ThorsLogAndThrow("ThorsAnvil::ThorsSocket::ClientCAListDataInfo<Dir>",
                             "addCAToList failed: >", item, "< ", buildOpenSSLErrorMessage());
        }
    }
    for (auto const& item: store.items)
    {
        int stat = store.addCAToList(list, item.c_str());
        if (stat != 1)
        {
            MOCK_FUNC(sk_X509_NAME_pop_free_wrapper)(list);
            ThorsLogAndThrow("ThorsAnvil::ThorsSocket::ClientCAListDataInfo<Store>",
                             "addCAToList failed: >", item, "< ", buildOpenSSLErrorMessage());
        }
    }
    return list;
}

THORS_SOCKET_HEADER_ONLY_INCLUDE
void ClientCAListInfo::apply(SSL_CTX* ctx) const
{
    if (verifyClientCA) {
        MOCK_FUNC(SSL_CTX_set_verify)(ctx, SSL_VERIFY_PEER|SSL_VERIFY_FAIL_IF_NO_PEER_CERT, nullptr);
    }
    STACK_OF(X509_NAME)* list = buildCAToList();
    if (list != nullptr) {
        MOCK_FUNC(SSL_CTX_set_client_CA_list)(ctx, list);
    }
};

THORS_SOCKET_HEADER_ONLY_INCLUDE
void ClientCAListInfo::apply(SSL* ssl) const
{
    if (verifyClientCA) {
        MOCK_FUNC(SSL_set_verify)(ssl, SSL_VERIFY_PEER|SSL_VERIFY_FAIL_IF_NO_PEER_CERT, nullptr);
    }
    STACK_OF(X509_NAME)* list = buildCAToList();
    if (list != nullptr) {
        MOCK_FUNC(SSL_set_client_CA_list)(ssl, list);
    }
};

namespace ThorsAnvil::ThorsSocket::ConnectionType
{
THORS_SOCKET_HEADER_ONLY_INCLUDE
std::string buildOpenSSLErrorMessage(bool prefix)
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
}
