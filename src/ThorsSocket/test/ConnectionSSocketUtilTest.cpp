#define THOR_LOGGING_DEFAULT_LOG_LEVEL  0
#include <gtest/gtest.h>
#include "test/ConnectionTest.h"
#include "SecureSocketUtil.h"

using ThorsAnvil::ThorsSocket::Protocol;
using ThorsAnvil::ThorsSocket::ProtocolInfo;
using ThorsAnvil::ThorsSocket::CipherInfo;
using ThorsAnvil::ThorsSocket::CertificateInfo;
using ThorsAnvil::ThorsSocket::CertifcateAuthorityInfo;
using ThorsAnvil::ThorsSocket::ClientCAListInfo;
using ThorsAnvil::BuildTools::Mock::TA_TestThrow;
using ThorsAnvil::BuildTools::Mock::TA_TestNoThrow;

TEST(ConnectionSSocketUtilTest, ProtocolInfoDefaultBuild)
{
    GTEST_SKIP();
    TA_TestNoThrow([](){
        ProtocolInfo    protocol;
    })
    .run();
}

TEST(ConnectionSSocketUtilTest, ProtocolInfoBuild)
{
    GTEST_SKIP();
    TA_TestNoThrow([](){
        ProtocolInfo    protocol(Protocol::TLS_1_0, Protocol::TLS_1_1);
    })
    .run();
}

TEST(ConnectionSSocketUtilTest, ProtocolInfoSetCTX)
{
    GTEST_SKIP();
    TA_TestNoThrow([](){
        ProtocolInfo    protocol(Protocol::TLS_1_0, Protocol::TLS_1_1);
        protocol.apply(reinterpret_cast<SSL_CTX*>(0x08));
    })
    .expectCallTA(SSL_CTX_ctrl).checkInput(reinterpret_cast<SSL_CTX*>(0x08), SSL_CTRL_SET_MIN_PROTO_VERSION, TLS1_VERSION, nullptr).toReturn(1)
    .expectCallTA(SSL_CTX_ctrl).checkInput(reinterpret_cast<SSL_CTX*>(0x08), SSL_CTRL_SET_MAX_PROTO_VERSION, TLS1_1_VERSION, nullptr).toReturn(1)
    .run();
}

TEST(ConnectionSSocketUtilTest, ProtocolInfoSetCTXMinFailed)
{
    GTEST_SKIP();
    TA_TestThrow([](){
        ProtocolInfo    protocol(Protocol::TLS_1_2, Protocol::TLS_1_3);
        protocol.apply(reinterpret_cast<SSL_CTX*>(0x08));
    })
    .expectCallTA(SSL_CTX_ctrl).toReturn(-1)
    .expectCallTA(ERR_get_error).toReturn(0)
    .run();
}

TEST(ConnectionSSocketUtilTest, ProtocolInfoSetCTXMaxFailed)
{
    GTEST_SKIP();
    TA_TestThrow([](){
        ProtocolInfo    protocol(Protocol::TLS_1_2, Protocol::TLS_1_3);
        protocol.apply(reinterpret_cast<SSL_CTX*>(0x08));
    })
    .expectCallTA(SSL_CTX_ctrl).toReturn(1).toReturn(-1)
    .expectCallTA(ERR_get_error).toReturn(0)
    .run();
}

TEST(ConnectionSSocketUtilTest, ProtocolInfoSetSSL)
{
    GTEST_SKIP();
    TA_TestNoThrow([](){
        ProtocolInfo    protocol(Protocol::TLS_1_2, Protocol::TLS_1_3);
        protocol.apply(reinterpret_cast<SSL*>(0x08));
    })
    .expectCallTA(SSL_ctrl).checkInput(reinterpret_cast<SSL*>(0x08), SSL_CTRL_SET_MIN_PROTO_VERSION, TLS1_2_VERSION, nullptr).toReturn(1)
    .expectCallTA(SSL_ctrl).checkInput(reinterpret_cast<SSL*>(0x08), SSL_CTRL_SET_MAX_PROTO_VERSION, TLS1_3_VERSION, nullptr).toReturn(1)
    .run();
}

TEST(ConnectionSSocketUtilTest, ProtocolInfoSetSSLMinFailed)
{
    GTEST_SKIP();
    TA_TestThrow([](){
        ProtocolInfo    protocol(Protocol::TLS_1_2, Protocol::TLS_1_3);
        protocol.apply(reinterpret_cast<SSL*>(0x08));
    })
    .expectCallTA(SSL_ctrl).toReturn(-1)
    .expectCallTA(ERR_get_error).toReturn(0)
    .run();
}

TEST(ConnectionSSocketUtilTest, ProtocolInfoSetSSLMaxFailed)
{
    GTEST_SKIP();
    TA_TestThrow([](){
        ProtocolInfo    protocol(Protocol::TLS_1_2, Protocol::TLS_1_3);
        protocol.apply(reinterpret_cast<SSL*>(0x08));
    })
    .expectCallTA(SSL_ctrl).toReturn(1).toReturn(-1)
    .expectCallTA(ERR_get_error).toReturn(0)
    .run();
}

TEST(ConnectionSSocketUtilTest, CipherInfoConstruct)
{
    GTEST_SKIP();
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
    GTEST_SKIP();
    TA_TestNoThrow([](){
        CipherInfo      cipherInfo{"Value1", "Value2"};;

        ASSERT_EQ(cipherInfo.cipherList, "Value1");
        ASSERT_EQ(cipherInfo.cipherSuite,"Value2");
    })
    .run();
}

TEST(ConnectionSSocketUtilTest, CipherInfoSetCTX)
{
    GTEST_SKIP();
    std::string input1 = "List1";
    std::string input2 = "Suite2";

    TA_TestNoThrow([&](){
        CipherInfo      cipherInfo{input1, input2};
        cipherInfo.apply(reinterpret_cast<SSL_CTX*>(0x08));
    })
    .expectCallTA(SSL_CTX_set_cipher_list).checkInput(reinterpret_cast<SSL_CTX*>(0x08), input1).toReturn(1)
    .expectCallTA(SSL_CTX_set_ciphersuites).checkInput( reinterpret_cast<SSL_CTX*>(0x08), input2).toReturn(1)
    .run();
}

TEST(ConnectionSSocketUtilTest, CipherInfoSetSSL)
{
    GTEST_SKIP();
    std::string input1 = "List1";
    std::string input2 = "Suite2";

    TA_TestNoThrow([&](){
        CipherInfo      cipherInfo{input1, input2};
        cipherInfo.apply(reinterpret_cast<SSL*>(0x08));
    })
    .expectCallTA(SSL_set_cipher_list).checkInput(reinterpret_cast<SSL*>(0x08), input1).toReturn(1)
    .expectCallTA(SSL_set_ciphersuites).checkInput(reinterpret_cast<SSL*>(0x08), input2).toReturn(1)
    .run();
}

TEST(ConnectionSSocketUtilTest, CipherInfoSetCTXListFail)
{
    GTEST_SKIP();
    TA_TestThrow([](){
        CipherInfo      cipherInfo{"List1", "Suite2"};
        cipherInfo.apply(reinterpret_cast<SSL_CTX*>(0x08));
    })
    .expectCallTA(SSL_CTX_set_cipher_list).toReturn(0)
    .expectCallTA(ERR_get_error).toReturn(0)
    .run();
}

TEST(ConnectionSSocketUtilTest, CipherInfoSetCTXSuiteFail)
{
    GTEST_SKIP();
    TA_TestThrow([](){
        CipherInfo      cipherInfo{"List1", "Suite2"};
        cipherInfo.apply(reinterpret_cast<SSL_CTX*>(0x08));
    })
    .expectCallTA(SSL_CTX_set_cipher_list).toReturn(1)
    .expectCallTA(SSL_CTX_set_ciphersuites).toReturn(0)
    .expectCallTA(ERR_get_error).toReturn(0)
    .run();
}

TEST(ConnectionSSocketUtilTest, CipherInfoSetSSLListFail)
{
    GTEST_SKIP();
    TA_TestThrow([](){
        CipherInfo      cipherInfo{"List1", "Suite2"};
        cipherInfo.apply(reinterpret_cast<SSL*>(0x08));
    })
    .expectCallTA(SSL_set_cipher_list).toReturn(0)
    .expectCallTA(ERR_get_error).toReturn(0)
    .run();
}

TEST(ConnectionSSocketUtilTest, CipherInfoSetSSLSuiteFail)
{
    GTEST_SKIP();
    TA_TestThrow([](){
        CipherInfo      cipherInfo{"List1", "Suite2"};
        cipherInfo.apply(reinterpret_cast<SSL*>(0x08));
    })
    .expectCallTA(SSL_set_cipher_list).toReturn(1)
    .expectCallTA(SSL_set_ciphersuites).toReturn(0)
    .expectCallTA(ERR_get_error).toReturn(0)
    .run();
}

TEST(ConnectionSSocketUtilTest, CertificateInfoConstruct)
{
    GTEST_SKIP();
    TA_TestNoThrow([](){
        CertificateInfo     ca("File1", "File2", [](int){return "password";});;
    })
    .run();
}

TEST(ConnectionSSocketUtilTest, CertificateInfoActionCTXDone)
{
    GTEST_SKIP();
    std::string certFile = "certFile1";
    std::string keyFile  = "keyFile2";

    TA_TestNoThrow([&](){
        CertificateInfo     ca(certFile, keyFile, [](int){return "password";});
        ca.apply(reinterpret_cast<SSL_CTX*>(0x08));
    })
    .expectCallTA(SSL_CTX_set_default_passwd_cb).toReturn(1)
    .expectCallTA(SSL_CTX_set_default_passwd_cb_userdata).toReturn(1)
    .expectCallTA(SSL_CTX_use_certificate_file).checkInput(reinterpret_cast<SSL_CTX*>(0x08), certFile, SSL_FILETYPE_PEM).toReturn(1)
    .expectCallTA(SSL_CTX_use_PrivateKey_file).checkInput(reinterpret_cast<SSL_CTX*>(0x08), keyFile, SSL_FILETYPE_PEM).toReturn(1)
    .expectCallTA(SSL_CTX_check_private_key).toReturn(1)
    .run();
}

TEST(ConnectionSSocketUtilTest, CertificateInfoActionSSLDone)
{
    GTEST_SKIP();
    std::string certFile = "certFile1";
    std::string keyFile  = "keyFile2";

    TA_TestNoThrow([&](){
        CertificateInfo     ca(certFile, keyFile, [](int){return "password";});
        ca.apply(reinterpret_cast<SSL*>(0x08));
    })
    .expectCallTA(SSL_set_default_passwd_cb).toReturn(1)
    .expectCallTA(SSL_set_default_passwd_cb_userdata).toReturn(1)
    .expectCallTA(SSL_use_certificate_file).checkInput(reinterpret_cast<SSL*>(0x08), certFile, SSL_FILETYPE_PEM).toReturn(1)
    .expectCallTA(SSL_use_PrivateKey_file).checkInput(reinterpret_cast<SSL*>(0x08), keyFile, SSL_FILETYPE_PEM).toReturn(1)
    .expectCallTA(SSL_check_private_key).toReturn(1)
    .run();
}

TEST(ConnectionSSocketUtilTest, CertificateInfoConstructionInvalidCert)
{
    GTEST_SKIP();
    TA_TestThrow([](){
        CertificateInfo     ca("File1", "");
    })
    .run();
}

TEST(ConnectionSSocketUtilTest, CertificateInfoConstructionInvalidKey)
{
    GTEST_SKIP();
    TA_TestThrow([](){
        CertificateInfo     ca("", "File2");
    })
    .run();
}

TEST(ConnectionSSocketUtilTest, CertificateInfoActionCTXInvalidCert)
{
    GTEST_SKIP();
    std::string certFile = "certFile1";
    std::string keyFile  = "keyFile2";

    TA_TestThrow([&](){
        CertificateInfo     ca(certFile, keyFile, [](int){return "password";});
        ca.apply(reinterpret_cast<SSL_CTX*>(0x08));
    })
    .expectCallTA(SSL_CTX_set_default_passwd_cb).toReturn(1)
    .expectCallTA(SSL_CTX_set_default_passwd_cb_userdata).toReturn(1)
    .expectCallTA(SSL_CTX_use_certificate_file).checkInput(reinterpret_cast<SSL_CTX*>(0x08), certFile, SSL_FILETYPE_PEM).toReturn(0)
    .expectCallTA(ERR_get_error).toReturn(0)
    .run();
}

TEST(ConnectionSSocketUtilTest, CertificateInfoActionCTXInvalidKey)
{
    GTEST_SKIP();
    std::string certFile = "certFile1";
    std::string keyFile  = "keyFile2";

    TA_TestThrow([&](){
        CertificateInfo     ca(certFile, keyFile, [](int){return "password";});
        ca.apply(reinterpret_cast<SSL_CTX*>(0x08));
    })
    .expectCallTA(SSL_CTX_set_default_passwd_cb).toReturn(1)
    .expectCallTA(SSL_CTX_set_default_passwd_cb_userdata).toReturn(1)
    .expectCallTA(SSL_CTX_use_certificate_file).checkInput(reinterpret_cast<SSL_CTX*>(0x08), certFile, SSL_FILETYPE_PEM).toReturn(1)
    .expectCallTA(SSL_CTX_use_PrivateKey_file).checkInput(reinterpret_cast<SSL_CTX*>(0x08), keyFile, SSL_FILETYPE_PEM).toReturn(0)
    .expectCallTA(ERR_get_error).toReturn(0)
    .run();
}

TEST(ConnectionSSocketUtilTest, CertificateInfoActionCTXInvalidCheck)
{
    GTEST_SKIP();
    std::string certFile = "certFile1";
    std::string keyFile  = "keyFile2";

    TA_TestThrow([&](){
        CertificateInfo     ca(certFile, keyFile, [](int){return "password";});
        ca.apply(reinterpret_cast<SSL_CTX*>(0x08));
    })
    .expectCallTA(SSL_CTX_set_default_passwd_cb).toReturn(1)
    .expectCallTA(SSL_CTX_set_default_passwd_cb_userdata).toReturn(1)
    .expectCallTA(SSL_CTX_use_certificate_file).checkInput(reinterpret_cast<SSL_CTX*>(0x08), certFile, SSL_FILETYPE_PEM).toReturn(1)
    .expectCallTA(SSL_CTX_use_PrivateKey_file).checkInput(reinterpret_cast<SSL_CTX*>(0x08), keyFile, SSL_FILETYPE_PEM).toReturn(1)
    .expectCallTA(SSL_CTX_check_private_key).toReturn(0)
    .expectCallTA(ERR_get_error).toReturn(0)
    .run();
}

TEST(ConnectionSSocketUtilTest, CertificateInfoActionSSLInvalidCert)
{
    GTEST_SKIP();
    std::string certFile = "certFile1";
    std::string keyFile  = "keyFile2";

    TA_TestThrow([&](){
        CertificateInfo     ca(certFile, keyFile, [](int){return "password";});
        ca.apply(reinterpret_cast<SSL*>(0x08));
    })
    .expectCallTA(SSL_set_default_passwd_cb).toReturn(1)
    .expectCallTA(SSL_set_default_passwd_cb_userdata).toReturn(1)
    .expectCallTA(SSL_use_certificate_file).checkInput(reinterpret_cast<SSL*>(0x08), certFile, SSL_FILETYPE_PEM).toReturn(0)
    .expectCallTA(ERR_get_error).toReturn(0)
    .run();
}

TEST(ConnectionSSocketUtilTest, CertificateInfoActionSSLInvalidKey)
{
    GTEST_SKIP();
    std::string certFile = "certFile1";
    std::string keyFile  = "keyFile2";

    TA_TestThrow([&](){
        CertificateInfo     ca(certFile, keyFile, [](int){return "password";});
        ca.apply(reinterpret_cast<SSL*>(0x08));
    })
    .expectCallTA(SSL_set_default_passwd_cb).toReturn(1)
    .expectCallTA(SSL_set_default_passwd_cb_userdata).toReturn(1)
    .expectCallTA(SSL_use_certificate_file).checkInput(reinterpret_cast<SSL*>(0x08), certFile, SSL_FILETYPE_PEM).toReturn(1)
    .expectCallTA(SSL_use_PrivateKey_file).checkInput(reinterpret_cast<SSL*>(0x08), keyFile, SSL_FILETYPE_PEM).toReturn(0)
    .expectCallTA(ERR_get_error).toReturn(0)
    .run();
}

TEST(ConnectionSSocketUtilTest, CertificateInfoActionSSLInvalidCheck)
{
    GTEST_SKIP();
    std::string certFile = "certFile1";
    std::string keyFile  = "keyFile2";

    TA_TestThrow([&](){
        CertificateInfo     ca(certFile, keyFile, [](int){return "password";});
        ca.apply(reinterpret_cast<SSL*>(0x08));
    })
    .expectCallTA(SSL_set_default_passwd_cb).toReturn(1)
    .expectCallTA(SSL_set_default_passwd_cb_userdata).toReturn(1)
    .expectCallTA(SSL_use_certificate_file).checkInput(reinterpret_cast<SSL*>(0x08), certFile, SSL_FILETYPE_PEM).toReturn(1)
    .expectCallTA(SSL_use_PrivateKey_file).checkInput(reinterpret_cast<SSL*>(0x08), keyFile, SSL_FILETYPE_PEM).toReturn(1)
    .expectCallTA(SSL_check_private_key).toReturn(0)
    .expectCallTA(ERR_get_error).toReturn(0)
    .run();
}

TEST(ConnectionSSocketUtilTest, CertifcateAuthorityInfoDefaultConstruct)
{
    GTEST_SKIP();
    TA_TestNoThrow([](){
        CertifcateAuthorityInfo     ca;
        ca.apply(reinterpret_cast<SSL_CTX*>(0x08));
    })
    .run();
}

TEST(ConnectionSSocketUtilTest, CertifcateAuthoritySetDefaultFile)
{
    GTEST_SKIP();
    TA_TestNoThrow([&](){
        CertifcateAuthorityInfo     ca;
        ca.file.loadDefault = true;
        ca.apply(reinterpret_cast<SSL_CTX*>(0x08));
    })
    .expectCallTA(SSL_CTX_set_default_verify_file).toReturn(1)
    .run();
}

TEST(ConnectionSSocketUtilTest, CertifcateAuthoritySetDefaultDir)
{
    GTEST_SKIP();
    TA_TestNoThrow([](){
        CertifcateAuthorityInfo     ca;
        ca.dir.loadDefault = true;
        ca.apply(reinterpret_cast<SSL_CTX*>(0x08));
    })
    .expectCallTA(SSL_CTX_set_default_verify_dir).toReturn(1)
    .run();
}

TEST(ConnectionSSocketUtilTest, CertifcateAuthoritySetDefaultStore)
{
    GTEST_SKIP();
    TA_TestNoThrow([](){
        CertifcateAuthorityInfo     ca;
        ca.store.loadDefault = true;
        ca.apply(reinterpret_cast<SSL_CTX*>(0x08));
    })
    .expectCallTA(SSL_CTX_set_default_verify_store).toReturn(1)
    .run();
}

TEST(ConnectionSSocketUtilTest, CertifcateAuthorityAddFile)
{
    GTEST_SKIP();
    std::string  file = "Item 1";

    TA_TestNoThrow([&](){
        CertifcateAuthorityInfo     ca;
        ca.file.items.push_back(file);
        ca.apply(reinterpret_cast<SSL_CTX*>(0x08));
    })
    .expectCallTA(SSL_CTX_load_verify_file).checkInput(reinterpret_cast<SSL_CTX*>(0x08), file).toReturn(1)
    .run();
}

TEST(ConnectionSSocketUtilTest, CertifcateAuthorityAddDir)
{
    GTEST_SKIP();
    std::string  file = "Item 1";

    TA_TestNoThrow([&](){
        CertifcateAuthorityInfo     ca;
        ca.dir.items.push_back(file);
        ca.apply(reinterpret_cast<SSL_CTX*>(0x08));
    })
    .expectCallTA(SSL_CTX_load_verify_dir).checkInput(reinterpret_cast<SSL_CTX*>(0x08), file).toReturn(1)
    .run();
}

TEST(ConnectionSSocketUtilTest, CertifcateAuthorityAddStore)
{
    GTEST_SKIP();
    std::string  file = "Item 1";

    TA_TestNoThrow([&](){
        CertifcateAuthorityInfo     ca;
        ca.store.items.push_back(file);
        ca.apply(reinterpret_cast<SSL_CTX*>(0x08));
    })
    .expectCallTA(SSL_CTX_load_verify_store).checkInput(reinterpret_cast<SSL_CTX*>(0x08), file).toReturn(1)
    .run();
}


TEST(ConnectionSSocketUtilTest, CertifcateAuthorityFailedDefaultFile)
{
    GTEST_SKIP();
    TA_TestThrow([](){
        CertifcateAuthorityInfo     ca;
        ca.file.loadDefault = true;
        ca.apply(reinterpret_cast<SSL_CTX*>(0x08));
    })
    .expectCallTA(SSL_CTX_set_default_verify_file).toReturn(0)
    .expectCallTA(ERR_get_error).toReturn(0)
    .run();
}

TEST(ConnectionSSocketUtilTest, CertifcateAuthorityFailedDefaultDir)
{
    GTEST_SKIP();
    TA_TestThrow([](){
        CertifcateAuthorityInfo     ca;
        ca.dir.loadDefault = true;
        ca.apply(reinterpret_cast<SSL_CTX*>(0x08));
    })
    .expectCallTA(SSL_CTX_set_default_verify_dir).toReturn(0)
    .expectCallTA(ERR_get_error).toReturn(0)
    .run();
}

TEST(ConnectionSSocketUtilTest, CertifcateAuthorityFailedDefaultStore)
{
    GTEST_SKIP();
    TA_TestThrow([](){
        CertifcateAuthorityInfo     ca;
        ca.store.loadDefault = true;
        ca.apply(reinterpret_cast<SSL_CTX*>(0x08));
    })
    .expectCallTA(SSL_CTX_set_default_verify_store).toReturn(0)
    .expectCallTA(ERR_get_error).toReturn(0)
    .run();
}

TEST(ConnectionSSocketUtilTest, CertifcateAuthorityAddFileFail)
{
    GTEST_SKIP();
    std::string  file = "Item 1";

    TA_TestThrow([&](){
        CertifcateAuthorityInfo     ca;
        ca.file.items.push_back(file);
        ca.apply(reinterpret_cast<SSL_CTX*>(0x08));
    })
    .expectCallTA(SSL_CTX_load_verify_file).toReturn(0)
    .expectCallTA(ERR_get_error).toReturn(0)
    .run();
}

TEST(ConnectionSSocketUtilTest, CertifcateAuthorityAddDirFail)
{
    GTEST_SKIP();
    std::string  file = "Item 1";

    TA_TestThrow([&](){
        CertifcateAuthorityInfo     ca;
        ca.dir.items.push_back(file);
        ca.apply(reinterpret_cast<SSL_CTX*>(0x08));
    })
    .expectCallTA(SSL_CTX_load_verify_dir).toReturn(0)
    .expectCallTA(ERR_get_error).toReturn(0)
    .run();
}

TEST(ConnectionSSocketUtilTest, CertifcateAuthorityAddStoreFail)
{
    GTEST_SKIP();
    std::string  file = "Item 1";

    TA_TestThrow([&](){
        CertifcateAuthorityInfo     ca;
        ca.store.items.push_back(file);
        ca.apply(reinterpret_cast<SSL_CTX*>(0x08));
    })
    .expectCallTA(SSL_CTX_load_verify_store).toReturn(0)
    .expectCallTA(ERR_get_error).toReturn(0)
    .run();
}

TEST(ConnectionSSocketUtilTest, ClientCAListInfoCTX)
{
    GTEST_SKIP();
    TA_TestNoThrow([](){
        ClientCAListInfo  list;
        list.apply(reinterpret_cast<SSL_CTX*>(0x08));
    })
    .run();
}

TEST(ConnectionSSocketUtilTest, ClientCAListInfoValidateClientCTX)
{
    GTEST_SKIP();
    TA_TestNoThrow([](){
        ClientCAListInfo  list;
        list.verifyClientCA = true;
        list.apply(reinterpret_cast<SSL_CTX*>(0x08));
    })
    .expectCallTA(SSL_CTX_set_verify).toReturn(1)
    .run();
}

TEST(ConnectionSSocketUtilTest, ClientCAListInfoAddClientFileCTX)
{
    GTEST_SKIP();
    TA_TestNoThrow([](){
        ClientCAListInfo  list;
        list.file.items.push_back("File 1");
        list.apply(reinterpret_cast<SSL_CTX*>(0x08));
    })
    .expectCallTA(sk_X509_NAME_new_null_wrapper).toReturn(reinterpret_cast<STACK_OF(X509_NAME)*>(0x08))
    .expectCallTA(SSL_add_file_cert_subjects_to_stack).toReturn(1)
    .expectCallTA(SSL_CTX_set_client_CA_list).toReturn(1)
    .run();
}

TEST(ConnectionSSocketUtilTest, ClientCAListInfoAddClientDirCTX)
{
    GTEST_SKIP();
    TA_TestNoThrow([](){
        ClientCAListInfo  list;
        list.dir.items.push_back("File 1");
        list.apply(reinterpret_cast<SSL_CTX*>(0x08));
    })
    .expectCallTA(sk_X509_NAME_new_null_wrapper).toReturn(reinterpret_cast<STACK_OF(X509_NAME)*>(0x08))
    .expectCallTA(SSL_add_dir_cert_subjects_to_stack).toReturn(1)
    .expectCallTA(SSL_CTX_set_client_CA_list).toReturn(1)
    .run();
}

TEST(ConnectionSSocketUtilTest, ClientCAListInfoAddClientStoreCTX)
{
    GTEST_SKIP();
    TA_TestNoThrow([](){
        ClientCAListInfo  list;
        list.store.items.push_back("File 1");
        list.apply(reinterpret_cast<SSL_CTX*>(0x08));
    })
    .expectCallTA(sk_X509_NAME_new_null_wrapper).toReturn(reinterpret_cast<STACK_OF(X509_NAME)*>(0x08))
    .expectCallTA(SSL_add_store_cert_subjects_to_stack).toReturn(1)
    .expectCallTA(SSL_CTX_set_client_CA_list).toReturn(1)
    .run();
}

TEST(ConnectionSSocketUtilTest, ClientCAListInfoValidateClientFailCTX)
{
    GTEST_SKIP();
    TA_TestNoThrow([](){
        ClientCAListInfo  list;
        list.verifyClientCA = true;
        list.apply(reinterpret_cast<SSL_CTX*>(0x08));
    })
    .expectCallTA(SSL_CTX_set_verify).toReturn(0)
    .run();
}

TEST(ConnectionSSocketUtilTest, ClientCAListInfoAddClientFileFailCTX)
{
    GTEST_SKIP();
    TA_TestThrow([](){
        ClientCAListInfo  list;
        list.file.items.push_back("File 1");
        list.apply(reinterpret_cast<SSL_CTX*>(0x08));
    })
    .expectCallTA(sk_X509_NAME_new_null_wrapper).toReturn(reinterpret_cast<STACK_OF(X509_NAME)*>(0x08))
    .expectCallTA(SSL_add_file_cert_subjects_to_stack).toReturn(0)
    .expectCallTA(sk_X509_NAME_pop_free_wrapper)
    .expectCallTA(ERR_get_error).toReturn(0)
    .run();
}

class X1
{
	public:
		X1() 	{std::cerr << "Construct X1\n";}
		~X1()	{std::cerr << "Destroy   X1\n";}
};
TEST(ConnectionSSocketUtilTest, ClientCAListInfoAddClientDirFailCTX)
{
    GTEST_SKIP();
	X1	mark;
std::cerr << "ClientCAListInfoAddClientDirFailCTX\n";
    TA_TestThrow([](){
        ClientCAListInfo            list;
        list.dir.items.push_back("File 1");
        list.apply(reinterpret_cast<SSL_CTX*>(0x08));
    })
    .expectCallTA(sk_X509_NAME_new_null_wrapper).toReturn(reinterpret_cast<STACK_OF(X509_NAME)*>(0x08))
    .expectCallTA(SSL_add_dir_cert_subjects_to_stack).toReturn(0)
    .expectCallTA(sk_X509_NAME_pop_free_wrapper)
    .expectCallTA(ERR_get_error).toReturn(0)
    .run();
std::cerr << "ClientCAListInfoAddClientDirFailCTX DONE\n";
}

TEST(ConnectionSSocketUtilTest, ClientCAListInfoAddClientStoreFailCTX)
{
    GTEST_SKIP();
	X1	mark;
std::cerr << "ClientCAListInfoAddClientStoreFailCTX\n";
    TA_TestThrow([](){
        ClientCAListInfo  list;
        list.store.items.push_back("File 1");
        list.apply(reinterpret_cast<SSL_CTX*>(0x08));
    })
    .expectCallTA(sk_X509_NAME_new_null_wrapper).toReturn(reinterpret_cast<STACK_OF(X509_NAME)*>(0x08))
    .expectCallTA(SSL_add_store_cert_subjects_to_stack).toReturn(0)
    .expectCallTA(sk_X509_NAME_pop_free_wrapper)
    .expectCallTA(ERR_get_error).toReturn(0)
    .run();
std::cerr << "ClientCAListInfoAddClientStoreFailCTX DONE\n";
}

TEST(ConnectionSSocketUtilTest, ClientCAListInfoSSL)
{
    GTEST_SKIP();
	X1	mark;
std::cerr << "ClientCAListInfoSSL\n";
    TA_TestNoThrow([](){
        ClientCAListInfo  list;
        list.apply(reinterpret_cast<SSL*>(0x08));
    })
    .run();
std::cerr << "ClientCAListInfoSSL DONE\n";
}

TEST(ConnectionSSocketUtilTest, ClientCAListInfoValidateClientSSL)
{
    GTEST_SKIP();
	X1	mark;
std::cerr << "ClientCAListInfoValidateClientSSL\n";
    TA_TestNoThrow([](){
        ClientCAListInfo            list;
        list.verifyClientCA = true;
        list.apply(reinterpret_cast<SSL*>(0x08));
    })
    .expectCallTA(SSL_set_verify).toReturn(1)
    .run();
std::cerr << "ClientCAListInfoValidateClientSSL DONE\n";
}

TEST(ConnectionSSocketUtilTest, ClientCAListInfoAddClientFileSSL)
{
    GTEST_SKIP();
	X1	mark;
std::cerr << "ClientCAListInfoAddClientFileSSL\n";
    TA_TestNoThrow([](){
        ClientCAListInfo            list;
        list.file.items.push_back("File 1");
        list.apply(reinterpret_cast<SSL*>(0x08));
    })
    .expectCallTA(sk_X509_NAME_new_null_wrapper).toReturn(reinterpret_cast<STACK_OF(X509_NAME)*>(0x08))
    .expectCallTA(SSL_add_file_cert_subjects_to_stack).toReturn(1)
    .expectCallTA(SSL_set_client_CA_list).toReturn(1)
    .run();
std::cerr << "ClientCAListInfoAddClientFileSSL DONE\n";
}

TEST(ConnectionSSocketUtilTest, ClientCAListInfoAddClientDirSSL)
{
    GTEST_SKIP();
	X1	mark;
std::cerr << "ClientCAListInfoAddClientDirSSL\n";
    TA_TestNoThrow([](){
        ClientCAListInfo            list;
        list.dir.items.push_back("File 1");
        list.apply(reinterpret_cast<SSL*>(0x08));
    })
    .expectCallTA(sk_X509_NAME_new_null_wrapper).toReturn(reinterpret_cast<STACK_OF(X509_NAME)*>(0x08))
    .expectCallTA(SSL_add_dir_cert_subjects_to_stack).toReturn(1)
    .expectCallTA(SSL_set_client_CA_list).toReturn(1)
    .run();
std::cerr << "ClientCAListInfoAddClientDirSSL DONE\n";
}

TEST(ConnectionSSocketUtilTest, ClientCAListInfoAddClientStoreSSL)
{
    GTEST_SKIP();
	X1	mark;
std::cerr << "ClientCAListInfoAddClientStoreSSL\n";
    TA_TestNoThrow([](){
        ClientCAListInfo            list;
        list.store.items.push_back("File 1");
        list.apply(reinterpret_cast<SSL*>(0x08));
    })
    .expectCallTA(sk_X509_NAME_new_null_wrapper).toReturn(reinterpret_cast<STACK_OF(X509_NAME)*>(0x08))
    .expectCallTA(SSL_add_store_cert_subjects_to_stack).toReturn(1)
    .expectCallTA(SSL_set_client_CA_list).toReturn(1)
    .run();
std::cerr << "ClientCAListInfoAddClientStoreSSL DONE\n";
}

TEST(ConnectionSSocketUtilTest, ClientCAListInfoValidateClientFailSSL)
{
    GTEST_SKIP();
	X1	mark;
std::cerr << "ClientCAListInfoValidateClientFailSSL\n";
    TA_TestNoThrow([](){
        ClientCAListInfo            list;
        list.verifyClientCA = true;
        list.apply(reinterpret_cast<SSL*>(0x08));
    })
    .expectCallTA(SSL_set_verify).toReturn(0)
    .run();
std::cerr << "ClientCAListInfoValidateClientFailSSL DONE\n";
}

TEST(ConnectionSSocketUtilTest, ClientCAListInfoAddClientFileFailSSL)
{
    GTEST_SKIP();
	X1	mark;
std::cerr << "ClientCAListInfoAddClientFileFailSSL\n";
    TA_TestThrow([](){
        ClientCAListInfo            list;
        list.file.items.push_back("File 1");
        list.apply(reinterpret_cast<SSL*>(0x08));
    })
    .expectCallTA(sk_X509_NAME_new_null_wrapper).toReturn(reinterpret_cast<STACK_OF(X509_NAME)*>(0x08))
    .expectCallTA(SSL_add_file_cert_subjects_to_stack).toReturn(0)
    .expectCallTA(sk_X509_NAME_pop_free_wrapper)
    .expectCallTA(ERR_get_error).toReturn(0)
    .run();
std::cerr << "ClientCAListInfoAddClientFileFailSSL DONE\n";
}

TEST(ConnectionSSocketUtilTest, ClientCAListInfoAddClientDirFailSSL)
{
    GTEST_SKIP();
	X1	mark;
std::cerr << "ClientCAListInfoAddClientDirFailSSL\n";
    TA_TestThrow([](){
        ClientCAListInfo            list;
        list.dir.items.push_back("File 1");
        list.apply(reinterpret_cast<SSL*>(0x08));
    })
    .expectCallTA(sk_X509_NAME_new_null_wrapper).toReturn(reinterpret_cast<STACK_OF(X509_NAME)*>(0x08))
    .expectCallTA(SSL_add_dir_cert_subjects_to_stack).toReturn(0)
    .expectCallTA(sk_X509_NAME_pop_free_wrapper)
    .expectCallTA(ERR_get_error).toReturn(0)
    .run();
std::cerr << "ClientCAListInfoAddClientDirFailSSL DONE\n";
}

TEST(ConnectionSSocketUtilTest, ClientCAListInfoAddClientStoreFailSSL)
{
    GTEST_SKIP();
	X1	mark;
std::cerr << "ClientCAListInfoAddClientStoreFailSSL\n";
    TA_TestThrow([](){
        ClientCAListInfo            list;
        list.store.items.push_back("File 1");
        list.apply(reinterpret_cast<SSL*>(0x08));
    })
    .expectCallTA(sk_X509_NAME_new_null_wrapper).toReturn(reinterpret_cast<STACK_OF(X509_NAME)*>(0x08))
    .expectCallTA(SSL_add_store_cert_subjects_to_stack).toReturn(0)
    .expectCallTA(sk_X509_NAME_pop_free_wrapper)
    .expectCallTA(ERR_get_error).toReturn(0)
    .run();
std::cerr << "ClientCAListInfoAddClientStoreFailSSL DONE\n";
}
