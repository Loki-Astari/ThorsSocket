#include <gtest/gtest.h>
#include "ConnectionSSocketUtil.h"
#include "test/ConnectionTest.h"
#include "test/MockDefaultThorsSocket.h"

#include <openssl/ssl.h>

using ThorsAnvil::ThorsSocket::ConnectionType::Protocol;
using ThorsAnvil::ThorsSocket::ConnectionType::ProtocolInfo;
using ThorsAnvil::ThorsSocket::ConnectionType::CipherInfo;
using ThorsAnvil::ThorsSocket::ConnectionType::CertificateInfo;
using ThorsAnvil::ThorsSocket::ConnectionType::CertifcateAuthorityInfo;
using ThorsAnvil::ThorsSocket::ConnectionType::ClientCAListInfo;
using ThorsAnvil::BuildTools::Mock::TA_TestThrow;
using ThorsAnvil::BuildTools::Mock::TA_TestNoThrow;

TEST(ConnectionSSocketUtilTest, ProtocolInfoDefaultBuild)
{
    TA_TestNoThrow([](){
        ProtocolInfo    protocol;
    })
    .run();
}

TEST(ConnectionSSocketUtilTest, ProtocolInfoBuild)
{
    TA_TestNoThrow([](){
        ProtocolInfo    protocol(Protocol::TLS_1_0, Protocol::TLS_1_1);
    })
    .run();
}

TEST(ConnectionSSocketUtilTest, ProtocolInfoSetCTX)
{
    TA_TestNoThrow([](){
        ProtocolInfo    protocol(Protocol::TLS_1_0, Protocol::TLS_1_1);
        protocol.apply(reinterpret_cast<SSL_CTX*>(0x08));
    })
    .expectCodeTA(SSL_CTX_ctrl).toReturn(1).toReturn(1)
    .run();
#if 0
    MOCK_INPUT(SSL_CTX_ctrl, reinterpret_cast<SSL_CTX*>(0x08), SSL_CTRL_SET_MIN_PROTO_VERSION, TLS1_VERSION, nullptr);
    MOCK_INPUT(SSL_CTX_ctrl, reinterpret_cast<SSL_CTX*>(0x08), SSL_CTRL_SET_MAX_PROTO_VERSION, TLS1_1_VERSION, nullptr);
#endif
}

TEST(ConnectionSSocketUtilTest, ProtocolInfoSetCTXMinFailed)
{
    TA_TestThrow([](){
        ProtocolInfo    protocol(Protocol::TLS_1_2, Protocol::TLS_1_3);
        protocol.apply(reinterpret_cast<SSL_CTX*>(0x08));
    })
    .expectCodeTA(SSL_CTX_ctrl).toReturn(-1)
    .codeTA(ERR_get_error).toReturn(0)
    .run();
}

TEST(ConnectionSSocketUtilTest, ProtocolInfoSetCTXMaxFailed)
{
    TA_TestThrow([](){
        ProtocolInfo    protocol(Protocol::TLS_1_2, Protocol::TLS_1_3);
        protocol.apply(reinterpret_cast<SSL_CTX*>(0x08));
    })
    .expectCodeTA(SSL_CTX_ctrl).toReturn(1).toReturn(-1)
    .codeTA(ERR_get_error).toReturn(0)
    .run();
}

TEST(ConnectionSSocketUtilTest, ProtocolInfoSetSSL)
{
    TA_TestNoThrow([](){
        ProtocolInfo    protocol(Protocol::TLS_1_2, Protocol::TLS_1_3);
        protocol.apply(reinterpret_cast<SSL*>(0x08));
    })
    .expectCodeTA(SSL_ctrl).toReturn(1).toReturn(1)
    .run();
#if 0
    MOCK_INPUT(SSL_ctrl, reinterpret_cast<SSL*>(0x08), SSL_CTRL_SET_MIN_PROTO_VERSION, TLS1_2_VERSION, nullptr);
    MOCK_INPUT(SSL_ctrl, reinterpret_cast<SSL*>(0x08), SSL_CTRL_SET_MAX_PROTO_VERSION, TLS1_3_VERSION, nullptr);
#endif
}

TEST(ConnectionSSocketUtilTest, ProtocolInfoSetSSLMinFailed)
{
    TA_TestThrow([](){
        ProtocolInfo    protocol(Protocol::TLS_1_2, Protocol::TLS_1_3);
        protocol.apply(reinterpret_cast<SSL*>(0x08));
    })
    .expectCodeTA(SSL_ctrl).toReturn(-1)
    .codeTA(ERR_get_error).toReturn(0)
    .run();
}

TEST(ConnectionSSocketUtilTest, ProtocolInfoSetSSLMaxFailed)
{
    TA_TestThrow([](){
        ProtocolInfo    protocol(Protocol::TLS_1_2, Protocol::TLS_1_3);
        protocol.apply(reinterpret_cast<SSL*>(0x08));
    })
    .expectCodeTA(SSL_ctrl).toReturn(1).toReturn(-1)
    .codeTA(ERR_get_error).toReturn(0)
    .run();
}

TEST(ConnectionSSocketUtilTest, CipherInfoConstruct)
{
    TA_TestNoThrow([](){
        CipherInfo      cipherInfo;
        ASSERT_EQ(cipherInfo.cipherList, "ECDHE-ECDSA-AES128-GCM-SHA256"     ":"
                                         "ECDHE-RSA-AES128-GCM-SHA256"       ":"
                                         "ECDHE-ECDSA-AES256-GCM-SHA384"     ":"
                                         "ECDHE-RSA-AES256-GCM-SHA384"       ":"
                                         "ECDHE-ECDSA-CHACHA20-POLY1305"     ":"
                                         "ECDHE-RSA-CHACHA20-POLY1305"       ":"
                                         "DHE-RSA-AES128-GCM-SHA256"         ":"
                                         "DHE-RSA-AES256-GCM-SHA384");
        ASSERT_EQ(cipherInfo.cipherSuite,"TLS_AES_256_GCM_SHA384"            ":"
                                         "TLS_CHACHA20_POLY1305_SHA256"      ":"
                                         "TLS_AES_128_GCM_SHA256");
    })
    .run();
}

TEST(ConnectionSSocketUtilTest, CipherInfoConstructWithAlternativeValues)
{
    TA_TestNoThrow([](){
        CipherInfo      cipherInfo{"Value1", "Value2"};;

        ASSERT_EQ(cipherInfo.cipherList, "Value1");
        ASSERT_EQ(cipherInfo.cipherSuite,"Value2");
    })
    .run();
}

TEST(ConnectionSSocketUtilTest, CipherInfoSetCTX)
{
    std::string input1 = "List1";
    std::string input2 = "Suite2";

    TA_TestNoThrow([&](){
        CipherInfo      cipherInfo{input1, input2};
        cipherInfo.apply(reinterpret_cast<SSL_CTX*>(0x08));
    })
    .expectCodeTA(SSL_CTX_set_cipher_list).toReturn(1)
    .codeTA(SSL_CTX_set_ciphersuites).toReturn(1)
    .run();
#if 0
    MOCK_INPUT(SSL_CTX_set_cipher_list, reinterpret_cast<SSL_CTX*>(0x08), input1);
    MOCK_INPUT(SSL_CTX_set_ciphersuites, reinterpret_cast<SSL_CTX*>(0x08), input2);
#endif
}

TEST(ConnectionSSocketUtilTest, CipherInfoSetSSL)
{
    std::string input1 = "List1";
    std::string input2 = "Suite2";

    TA_TestNoThrow([&](){
        CipherInfo      cipherInfo{input1, input2};
        cipherInfo.apply(reinterpret_cast<SSL*>(0x08));
    })
    .expectCodeTA(SSL_set_cipher_list).toReturn(1)
    .codeTA(SSL_set_ciphersuites).toReturn(1)
    .run();
#if 0
    MOCK_INPUT(SSL_set_cipher_list, reinterpret_cast<SSL*>(0x08), input1);
    MOCK_INPUT(SSL_set_ciphersuites, reinterpret_cast<SSL*>(0x08), input2);
#endif
}

TEST(ConnectionSSocketUtilTest, CipherInfoSetCTXListFail)
{
    TA_TestThrow([](){
        CipherInfo      cipherInfo{"List1", "Suite2"};
        cipherInfo.apply(reinterpret_cast<SSL_CTX*>(0x08));
    })
    .expectCodeTA(SSL_CTX_set_cipher_list).toReturn(0)
    .codeTA(ERR_get_error).toReturn(0)
    .run();
}

TEST(ConnectionSSocketUtilTest, CipherInfoSetCTXSuiteFail)
{
    TA_TestThrow([](){
        CipherInfo      cipherInfo{"List1", "Suite2"};
        cipherInfo.apply(reinterpret_cast<SSL_CTX*>(0x08));
    })
    .expectCodeTA(SSL_CTX_set_cipher_list).toReturn(1)
    .codeTA(SSL_CTX_set_ciphersuites).toReturn(0)
    .codeTA(ERR_get_error).toReturn(0)
    .run();
}

TEST(ConnectionSSocketUtilTest, CipherInfoSetSSLListFail)
{
    TA_TestThrow([](){
        CipherInfo      cipherInfo{"List1", "Suite2"};
        cipherInfo.apply(reinterpret_cast<SSL*>(0x08));
    })
    .expectCodeTA(SSL_set_cipher_list).toReturn(0)
    .codeTA(ERR_get_error).toReturn(0)
    .run();
}

TEST(ConnectionSSocketUtilTest, CipherInfoSetSSLSuiteFail)
{
    TA_TestThrow([](){
        CipherInfo      cipherInfo{"List1", "Suite2"};
        cipherInfo.apply(reinterpret_cast<SSL*>(0x08));
    })
    .expectCodeTA(SSL_set_cipher_list).toReturn(1)
    .codeTA(SSL_set_ciphersuites).toReturn(0)
    .codeTA(ERR_get_error).toReturn(0)
    .run();
}

TEST(ConnectionSSocketUtilTest, CertificateInfoDefaultConstruct)
{
    TA_TestNoThrow([](){
        CertificateInfo     ca;
    })
    .run();
}

TEST(ConnectionSSocketUtilTest, CertificateInfoConstruct)
{
    TA_TestNoThrow([](){
        CertificateInfo     ca("File1", "File2", [](int){return "password";});;
    })
    .run();
}

TEST(ConnectionSSocketUtilTest, CertificateInfoDefaultConstructNoAction)
{
    TA_TestNoThrow([](){
        CertificateInfo     ca;
        ca.apply(reinterpret_cast<SSL_CTX*>(0x08));
    })
    .run();
}

TEST(ConnectionSSocketUtilTest, CertificateInfoActionCTXDone)
{
    std::string certFile = "certFile1";
    std::string keyFile  = "keyFile2";

    TA_TestNoThrow([&](){
        CertificateInfo     ca(certFile, keyFile, [](int){return "password";});
        ca.apply(reinterpret_cast<SSL_CTX*>(0x08));
    })
    .expectCodeTA(SSL_CTX_set_default_passwd_cb).toReturn(1)
    .codeTA(SSL_CTX_set_default_passwd_cb_userdata).toReturn(1)
    .codeTA(SSL_CTX_use_certificate_file).toReturn(1)
    .codeTA(SSL_CTX_use_PrivateKey_file).toReturn(1)
    .codeTA(SSL_CTX_check_private_key).toReturn(1)
    .run();
#if 0
    MOCK_INPUT(SSL_CTX_use_certificate_file, reinterpret_cast<SSL_CTX*>(0x08), certFile, SSL_FILETYPE_PEM);
    MOCK_INPUT(SSL_CTX_use_PrivateKey_file, reinterpret_cast<SSL_CTX*>(0x08), keyFile, SSL_FILETYPE_PEM);
#endif
}

TEST(ConnectionSSocketUtilTest, CertificateInfoActionSSLDone)
{
    std::string certFile = "certFile1";
    std::string keyFile  = "keyFile2";

    TA_TestNoThrow([&](){
        CertificateInfo     ca(certFile, keyFile, [](int){return "password";});
        ca.apply(reinterpret_cast<SSL*>(0x08));
    })
    .expectCodeTA(SSL_set_default_passwd_cb).toReturn(1)
    .codeTA(SSL_set_default_passwd_cb_userdata).toReturn(1)
    .codeTA(SSL_use_certificate_file).toReturn(1)
    .codeTA(SSL_use_PrivateKey_file).toReturn(1)
    .codeTA(SSL_check_private_key).toReturn(1)
    .run();
#if 0
    MOCK_INPUT(SSL_use_certificate_file, reinterpret_cast<SSL*>(0x08), certFile, SSL_FILETYPE_PEM);
    MOCK_INPUT(SSL_use_PrivateKey_file, reinterpret_cast<SSL*>(0x08), keyFile, SSL_FILETYPE_PEM);
#endif
}

TEST(ConnectionSSocketUtilTest, CertificateInfoConstructionInvalidCert)
{
    TA_TestThrow([](){
        CertificateInfo     ca("File1", "");
    })
    .run();
}

TEST(ConnectionSSocketUtilTest, CertificateInfoConstructionInvalidKey)
{
    TA_TestThrow([](){
        CertificateInfo     ca("", "File2");
    })
    .run();
}

TEST(ConnectionSSocketUtilTest, CertificateInfoActionCTXInvalidCert)
{
    std::string certFile = "certFile1";
    std::string keyFile  = "keyFile2";

    TA_TestThrow([&](){
        CertificateInfo     ca(certFile, keyFile, [](int){return "password";});
        ca.apply(reinterpret_cast<SSL_CTX*>(0x08));
    })
    .expectCodeTA(SSL_CTX_set_default_passwd_cb).toReturn(1)
    .codeTA(SSL_CTX_set_default_passwd_cb_userdata).toReturn(1)
    .codeTA(SSL_CTX_use_certificate_file).toReturn(0)
    .codeTA(ERR_get_error).toReturn(0)
    .run();
#if 0
    MOCK_INPUT(SSL_CTX_use_certificate_file, reinterpret_cast<SSL_CTX*>(0x08), certFile, SSL_FILETYPE_PEM);
#endif
}

TEST(ConnectionSSocketUtilTest, CertificateInfoActionCTXInvalidKey)
{
    std::string certFile = "certFile1";
    std::string keyFile  = "keyFile2";

    TA_TestThrow([&](){
        CertificateInfo     ca(certFile, keyFile, [](int){return "password";});
        ca.apply(reinterpret_cast<SSL_CTX*>(0x08));
    })
    .expectCodeTA(SSL_CTX_set_default_passwd_cb).toReturn(1)
    .codeTA(SSL_CTX_set_default_passwd_cb_userdata).toReturn(1)
    .codeTA(SSL_CTX_use_certificate_file).toReturn(1)
    .codeTA(SSL_CTX_use_PrivateKey_file).toReturn(0)
    .codeTA(ERR_get_error).toReturn(0)
    .run();
#if 0
    MOCK_INPUT(SSL_CTX_use_certificate_file, reinterpret_cast<SSL_CTX*>(0x08), certFile, SSL_FILETYPE_PEM);
    MOCK_INPUT(SSL_CTX_use_PrivateKey_file, reinterpret_cast<SSL_CTX*>(0x08), keyFile, SSL_FILETYPE_PEM);
#endif
}

TEST(ConnectionSSocketUtilTest, CertificateInfoActionCTXInvalidCheck)
{
    std::string certFile = "certFile1";
    std::string keyFile  = "keyFile2";

    TA_TestThrow([&](){
        CertificateInfo     ca(certFile, keyFile, [](int){return "password";});
        ca.apply(reinterpret_cast<SSL_CTX*>(0x08));
    })
    .expectCodeTA(SSL_CTX_set_default_passwd_cb).toReturn(1)
    .codeTA(SSL_CTX_set_default_passwd_cb_userdata).toReturn(1)
    .codeTA(SSL_CTX_use_certificate_file).toReturn(1)
    .codeTA(SSL_CTX_use_PrivateKey_file).toReturn(1)
    .codeTA(SSL_CTX_check_private_key).toReturn(0)
    .codeTA(ERR_get_error).toReturn(0)
    .run();
#if 0
    MOCK_INPUT(SSL_CTX_use_certificate_file, reinterpret_cast<SSL_CTX*>(0x08), certFile, SSL_FILETYPE_PEM);
    MOCK_INPUT(SSL_CTX_use_PrivateKey_file, reinterpret_cast<SSL_CTX*>(0x08), keyFile, SSL_FILETYPE_PEM);
#endif
}

TEST(ConnectionSSocketUtilTest, CertificateInfoActionSSLInvalidCert)
{
    std::string certFile = "certFile1";
    std::string keyFile  = "keyFile2";

    TA_TestThrow([&](){
        CertificateInfo     ca(certFile, keyFile, [](int){return "password";});
        ca.apply(reinterpret_cast<SSL*>(0x08));
    })
    .expectCodeTA(SSL_set_default_passwd_cb).toReturn(1)
    .codeTA(SSL_set_default_passwd_cb_userdata).toReturn(1)
    .codeTA(SSL_use_certificate_file).toReturn(0)
    .codeTA(ERR_get_error).toReturn(0)
    .run();
#if 0
    MOCK_INPUT(SSL_use_certificate_file, reinterpret_cast<SSL*>(0x08), certFile, SSL_FILETYPE_PEM);
#endif
}

TEST(ConnectionSSocketUtilTest, CertificateInfoActionSSLInvalidKey)
{
    std::string certFile = "certFile1";
    std::string keyFile  = "keyFile2";

    TA_TestThrow([&](){
        CertificateInfo     ca(certFile, keyFile, [](int){return "password";});
        ca.apply(reinterpret_cast<SSL*>(0x08));
    })
    .expectCodeTA(SSL_set_default_passwd_cb).toReturn(1)
    .codeTA(SSL_set_default_passwd_cb_userdata).toReturn(1)
    .codeTA(SSL_use_certificate_file).toReturn(1)
    .codeTA(SSL_use_PrivateKey_file).toReturn(0)
    .codeTA(ERR_get_error).toReturn(0)
    .run();
#if 0
    MOCK_INPUT(SSL_use_certificate_file, reinterpret_cast<SSL*>(0x08), certFile, SSL_FILETYPE_PEM);
    MOCK_INPUT(SSL_use_PrivateKey_file, reinterpret_cast<SSL*>(0x08), keyFile, SSL_FILETYPE_PEM);
#endif
}

TEST(ConnectionSSocketUtilTest, CertificateInfoActionSSLInvalidCheck)
{
    std::string certFile = "certFile1";
    std::string keyFile  = "keyFile2";

    TA_TestThrow([&](){
        CertificateInfo     ca(certFile, keyFile, [](int){return "password";});
        ca.apply(reinterpret_cast<SSL*>(0x08));
    })
    .expectCodeTA(SSL_set_default_passwd_cb).toReturn(1)
    .codeTA(SSL_set_default_passwd_cb_userdata).toReturn(1)
    .codeTA(SSL_use_certificate_file).toReturn(1)
    .codeTA(SSL_use_PrivateKey_file).toReturn(1)
    .codeTA(SSL_check_private_key).toReturn(0)
    .codeTA(ERR_get_error).toReturn(0)
    .run();
#if 0
    MOCK_INPUT(SSL_use_certificate_file, reinterpret_cast<SSL*>(0x08), certFile, SSL_FILETYPE_PEM);
    MOCK_INPUT(SSL_use_PrivateKey_file, reinterpret_cast<SSL*>(0x08), keyFile, SSL_FILETYPE_PEM);
#endif
}

TEST(ConnectionSSocketUtilTest, CertifcateAuthorityInfoDefaultConstruct)
{
    TA_TestNoThrow([](){
        CertifcateAuthorityInfo     ca;
        ca.apply(reinterpret_cast<SSL_CTX*>(0x08));
    })
    .run();
}

TEST(ConnectionSSocketUtilTest, CertifcateAuthoritySetDefaultFile)
{
    TA_TestNoThrow([&](){
        CertifcateAuthorityInfo     ca;
        ca.file.loadDefault = true;
        ca.apply(reinterpret_cast<SSL_CTX*>(0x08));
    })
    .expectCodeTA(SSL_CTX_set_default_verify_file).toReturn(1)
    .run();
}

TEST(ConnectionSSocketUtilTest, CertifcateAuthoritySetDefaultDir)
{
    TA_TestNoThrow([](){
        CertifcateAuthorityInfo     ca;
        ca.dir.loadDefault = true;
        ca.apply(reinterpret_cast<SSL_CTX*>(0x08));
    })
    .expectCodeTA(SSL_CTX_set_default_verify_dir).toReturn(1)
    .run();
}

TEST(ConnectionSSocketUtilTest, CertifcateAuthoritySetDefaultStore)
{
    TA_TestNoThrow([](){
        CertifcateAuthorityInfo     ca;
        ca.store.loadDefault = true;
        ca.apply(reinterpret_cast<SSL_CTX*>(0x08));
    })
    .expectCodeTA(SSL_CTX_set_default_verify_store).toReturn(1)
    .run();
}

TEST(ConnectionSSocketUtilTest, CertifcateAuthorityAddFile)
{
    std::string  file = "Item 1";

    TA_TestNoThrow([&](){
        CertifcateAuthorityInfo     ca;
        ca.file.items.push_back(file);
        ca.apply(reinterpret_cast<SSL_CTX*>(0x08));
    })
    .expectCodeTA(SSL_CTX_load_verify_file).toReturn(1)
    .run();
#if 0
    MOCK_INPUT(SSL_CTX_load_verify_file, reinterpret_cast<SSL_CTX*>(0x08), file);
#endif
}

TEST(ConnectionSSocketUtilTest, CertifcateAuthorityAddDir)
{
    std::string  file = "Item 1";

    TA_TestNoThrow([&](){
        CertifcateAuthorityInfo     ca;
        ca.dir.items.push_back(file);
        ca.apply(reinterpret_cast<SSL_CTX*>(0x08));
    })
    .expectCodeTA(SSL_CTX_load_verify_dir).toReturn(1)
    .run();
#if 0
    MOCK_INPUT(SSL_CTX_load_verify_dir, reinterpret_cast<SSL_CTX*>(0x08), file);
#endif
}

TEST(ConnectionSSocketUtilTest, CertifcateAuthorityAddStore)
{
    std::string  file = "Item 1";

    TA_TestNoThrow([&](){
        CertifcateAuthorityInfo     ca;
        ca.store.items.push_back(file);
        ca.apply(reinterpret_cast<SSL_CTX*>(0x08));
    })
    .expectCodeTA(SSL_CTX_load_verify_store).toReturn(1)
    .run();
#if 0
    MOCK_INPUT(SSL_CTX_load_verify_store, reinterpret_cast<SSL_CTX*>(0x08), file);
#endif
}


TEST(ConnectionSSocketUtilTest, CertifcateAuthorityFailedDefaultFile)
{
    TA_TestThrow([](){
        CertifcateAuthorityInfo     ca;
        ca.file.loadDefault = true;
        ca.apply(reinterpret_cast<SSL_CTX*>(0x08));
    })
    .expectCodeTA(SSL_CTX_set_default_verify_file).toReturn(0)
    .codeTA(ERR_get_error).toReturn(0)
    .run();
}

TEST(ConnectionSSocketUtilTest, CertifcateAuthorityFailedDefaultDir)
{
    TA_TestThrow([](){
        CertifcateAuthorityInfo     ca;
        ca.dir.loadDefault = true;
        ca.apply(reinterpret_cast<SSL_CTX*>(0x08));
    })
    .expectCodeTA(SSL_CTX_set_default_verify_dir).toReturn(0)
    .codeTA(ERR_get_error).toReturn(0)
    .run();
}

TEST(ConnectionSSocketUtilTest, CertifcateAuthorityFailedDefaultStore)
{
    TA_TestThrow([](){
        CertifcateAuthorityInfo     ca;
        ca.store.loadDefault = true;
        ca.apply(reinterpret_cast<SSL_CTX*>(0x08));
    })
    .expectCodeTA(SSL_CTX_set_default_verify_store).toReturn(0)
    .codeTA(ERR_get_error).toReturn(0)
    .run();
}

TEST(ConnectionSSocketUtilTest, CertifcateAuthorityAddFileFail)
{
    std::string  file = "Item 1";

    TA_TestThrow([&](){
        CertifcateAuthorityInfo     ca;
        ca.file.items.push_back(file);
        ca.apply(reinterpret_cast<SSL_CTX*>(0x08));
    })
    .expectCodeTA(SSL_CTX_load_verify_file).toReturn(0)
    .codeTA(ERR_get_error).toReturn(0)
    .run();
}

TEST(ConnectionSSocketUtilTest, CertifcateAuthorityAddDirFail)
{
    std::string  file = "Item 1";

    TA_TestThrow([&](){
        CertifcateAuthorityInfo     ca;
        ca.dir.items.push_back(file);
        ca.apply(reinterpret_cast<SSL_CTX*>(0x08));
    })
    .expectCodeTA(SSL_CTX_load_verify_dir).toReturn(0)
    .codeTA(ERR_get_error).toReturn(0)
    .run();
}

TEST(ConnectionSSocketUtilTest, CertifcateAuthorityAddStoreFail)
{
    std::string  file = "Item 1";

    TA_TestThrow([&](){
        CertifcateAuthorityInfo     ca;
        ca.store.items.push_back(file);
        ca.apply(reinterpret_cast<SSL_CTX*>(0x08));
    })
    .expectCodeTA(SSL_CTX_load_verify_store).toReturn(0)
    .codeTA(ERR_get_error).toReturn(0)
    .run();
}

TEST(ConnectionSSocketUtilTest, ClientCAListInfoCTX)
{
    TA_TestNoThrow([](){
        ClientCAListInfo  list;
        list.apply(reinterpret_cast<SSL_CTX*>(0x08));
    })
    .run();
}

TEST(ConnectionSSocketUtilTest, ClientCAListInfoValidateClientCTX)
{
    TA_TestNoThrow([](){
        ClientCAListInfo  list;
        list.verifyClientCA = true;
        list.apply(reinterpret_cast<SSL_CTX*>(0x08));
    })
    .expectCodeTA(SSL_CTX_set_verify).toReturn(1)
    .run();
}

TEST(ConnectionSSocketUtilTest, ClientCAListInfoAddClientFileCTX)
{
    TA_TestNoThrow([](){
        ClientCAListInfo  list;
        list.file.items.push_back("File 1");
        list.apply(reinterpret_cast<SSL_CTX*>(0x08));
    })
    .expectCodeTA(sk_X509_NAME_new_null_wrapper).toReturn(reinterpret_cast<STACK_OF(X509_NAME)*>(0x08))
    .codeTA(SSL_add_file_cert_subjects_to_stack).toReturn(1)
    .codeTA(SSL_CTX_set_client_CA_list).toReturn(1)
    .run();
}

TEST(ConnectionSSocketUtilTest, ClientCAListInfoAddClientDirCTX)
{
    TA_TestNoThrow([](){
        ClientCAListInfo  list;
        list.dir.items.push_back("File 1");
        list.apply(reinterpret_cast<SSL_CTX*>(0x08));
    })
    .expectCodeTA(sk_X509_NAME_new_null_wrapper).toReturn(reinterpret_cast<STACK_OF(X509_NAME)*>(0x08))
    .codeTA(SSL_add_dir_cert_subjects_to_stack).toReturn(1)
    .codeTA(SSL_CTX_set_client_CA_list).toReturn(1)
    .run();
}

TEST(ConnectionSSocketUtilTest, ClientCAListInfoAddClientStoreCTX)
{
    TA_TestNoThrow([](){
        ClientCAListInfo  list;
        list.store.items.push_back("File 1");
        list.apply(reinterpret_cast<SSL_CTX*>(0x08));
    })
    .expectCodeTA(sk_X509_NAME_new_null_wrapper).toReturn(reinterpret_cast<STACK_OF(X509_NAME)*>(0x08))
    .codeTA(SSL_add_store_cert_subjects_to_stack).toReturn(1)
    .codeTA(SSL_CTX_set_client_CA_list).toReturn(1)
    .run();
}

TEST(ConnectionSSocketUtilTest, ClientCAListInfoValidateClientFailCTX)
{
    TA_TestNoThrow([](){
        ClientCAListInfo  list;
        list.verifyClientCA = true;
        list.apply(reinterpret_cast<SSL_CTX*>(0x08));
    })
    .expectCodeTA(SSL_CTX_set_verify).toReturn(0)
    .run();
}

TEST(ConnectionSSocketUtilTest, ClientCAListInfoAddClientFileFailCTX)
{
    TA_TestThrow([](){
        ClientCAListInfo  list;
        list.file.items.push_back("File 1");
        list.apply(reinterpret_cast<SSL_CTX*>(0x08));
    })
    .expectCodeTA(sk_X509_NAME_new_null_wrapper).toReturn(reinterpret_cast<STACK_OF(X509_NAME)*>(0x08))
    .codeTA(SSL_add_file_cert_subjects_to_stack).toReturn(0)
    .codeTA(sk_X509_NAME_pop_free_wrapper)
    .codeTA(ERR_get_error).toReturn(0)
    .run();
}

TEST(ConnectionSSocketUtilTest, ClientCAListInfoAddClientDirFailCTX)
{
    TA_TestThrow([](){
        ClientCAListInfo            list;
        list.dir.items.push_back("File 1");
        list.apply(reinterpret_cast<SSL_CTX*>(0x08));
    })
    .expectCodeTA(sk_X509_NAME_new_null_wrapper).toReturn(reinterpret_cast<STACK_OF(X509_NAME)*>(0x08))
    .codeTA(SSL_add_dir_cert_subjects_to_stack).toReturn(0)
    .codeTA(sk_X509_NAME_pop_free_wrapper)
    .codeTA(ERR_get_error).toReturn(0)
    .run();
}

TEST(ConnectionSSocketUtilTest, ClientCAListInfoAddClientStoreFailCTX)
{
    TA_TestThrow([](){
        ClientCAListInfo  list;
        list.store.items.push_back("File 1");
        list.apply(reinterpret_cast<SSL_CTX*>(0x08));
    })
    .expectCodeTA(sk_X509_NAME_new_null_wrapper).toReturn(reinterpret_cast<STACK_OF(X509_NAME)*>(0x08))
    .codeTA(SSL_add_store_cert_subjects_to_stack).toReturn(0)
    .codeTA(sk_X509_NAME_pop_free_wrapper)
    .codeTA(ERR_get_error).toReturn(0)
    .run();
}

TEST(ConnectionSSocketUtilTest, ClientCAListInfoSSL)
{
    TA_TestNoThrow([](){
        ClientCAListInfo  list;
        list.apply(reinterpret_cast<SSL*>(0x08));
    })
    .run();
}

TEST(ConnectionSSocketUtilTest, ClientCAListInfoValidateClientSSL)
{
    TA_TestNoThrow([](){
        ClientCAListInfo            list;
        list.verifyClientCA = true;
        list.apply(reinterpret_cast<SSL*>(0x08));
    })
    .expectCodeTA(SSL_set_verify).toReturn(1)
    .run();
}

TEST(ConnectionSSocketUtilTest, ClientCAListInfoAddClientFileSSL)
{
    TA_TestNoThrow([](){
        ClientCAListInfo            list;
        list.file.items.push_back("File 1");
        list.apply(reinterpret_cast<SSL*>(0x08));
    })
    .expectCodeTA(sk_X509_NAME_new_null_wrapper).toReturn(reinterpret_cast<STACK_OF(X509_NAME)*>(0x08))
    .codeTA(SSL_add_file_cert_subjects_to_stack).toReturn(1)
    .codeTA(SSL_set_client_CA_list).toReturn(1)
    .run();
}

TEST(ConnectionSSocketUtilTest, ClientCAListInfoAddClientDirSSL)
{
    TA_TestNoThrow([](){
        ClientCAListInfo            list;
        list.dir.items.push_back("File 1");
        list.apply(reinterpret_cast<SSL*>(0x08));
    })
    .expectCodeTA(sk_X509_NAME_new_null_wrapper).toReturn(reinterpret_cast<STACK_OF(X509_NAME)*>(0x08))
    .codeTA(SSL_add_dir_cert_subjects_to_stack).toReturn(1)
    .codeTA(SSL_set_client_CA_list).toReturn(1)
    .run();
}

TEST(ConnectionSSocketUtilTest, ClientCAListInfoAddClientStoreSSL)
{
    TA_TestNoThrow([](){
        ClientCAListInfo            list;
        list.store.items.push_back("File 1");
        list.apply(reinterpret_cast<SSL*>(0x08));
    })
    .expectCodeTA(sk_X509_NAME_new_null_wrapper).toReturn(reinterpret_cast<STACK_OF(X509_NAME)*>(0x08))
    .codeTA(SSL_add_store_cert_subjects_to_stack).toReturn(1)
    .codeTA(SSL_set_client_CA_list).toReturn(1)
    .run();
}

TEST(ConnectionSSocketUtilTest, ClientCAListInfoValidateClientFailSSL)
{
    TA_TestNoThrow([](){
        ClientCAListInfo            list;
        list.verifyClientCA = true;
        list.apply(reinterpret_cast<SSL*>(0x08));
    })
    .expectCodeTA(SSL_set_verify).toReturn(0)
    .run();
}

TEST(ConnectionSSocketUtilTest, ClientCAListInfoAddClientFileFailSSL)
{
    TA_TestThrow([](){
        ClientCAListInfo            list;
        list.file.items.push_back("File 1");
        list.apply(reinterpret_cast<SSL*>(0x08));
    })
    .expectCodeTA(sk_X509_NAME_new_null_wrapper).toReturn(reinterpret_cast<STACK_OF(X509_NAME)*>(0x08))
    .codeTA(SSL_add_file_cert_subjects_to_stack).toReturn(0)
    .codeTA(sk_X509_NAME_pop_free_wrapper)
    .codeTA(ERR_get_error).toReturn(0)
    .run();
}

TEST(ConnectionSSocketUtilTest, ClientCAListInfoAddClientDirFailSSL)
{
    TA_TestThrow([](){
        ClientCAListInfo            list;
        list.dir.items.push_back("File 1");
        list.apply(reinterpret_cast<SSL*>(0x08));
    })
    .expectCodeTA(sk_X509_NAME_new_null_wrapper).toReturn(reinterpret_cast<STACK_OF(X509_NAME)*>(0x08))
    .codeTA(SSL_add_dir_cert_subjects_to_stack).toReturn(0)
    .codeTA(sk_X509_NAME_pop_free_wrapper)
    .codeTA(ERR_get_error).toReturn(0)
    .run();
}

TEST(ConnectionSSocketUtilTest, ClientCAListInfoAddClientStoreFailSSL)
{
    TA_TestThrow([](){
        ClientCAListInfo            list;
        list.store.items.push_back("File 1");
        list.apply(reinterpret_cast<SSL*>(0x08));
    })
    .expectCodeTA(sk_X509_NAME_new_null_wrapper).toReturn(reinterpret_cast<STACK_OF(X509_NAME)*>(0x08))
    .codeTA(SSL_add_store_cert_subjects_to_stack).toReturn(0)
    .codeTA(sk_X509_NAME_pop_free_wrapper)
    .codeTA(ERR_get_error).toReturn(0)
    .run();
}

