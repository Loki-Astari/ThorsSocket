#include <gtest/gtest.h>
#include "ConnectionSSocketUtil.h"
#include "test/ConnectionSSocketUtilTest.h"

using ThorsAnvil::ThorsSocket::ConnectionType::Protocol;
using ThorsAnvil::ThorsSocket::ConnectionType::ProtocolInfo;
using ThorsAnvil::ThorsSocket::ConnectionType::CipherInfo;
using ThorsAnvil::ThorsSocket::ConnectionType::CertificateInfo;
using ThorsAnvil::ThorsSocket::ConnectionType::CertifcateAuthorityInfo;
using ThorsAnvil::ThorsSocket::ConnectionType::ClientCAListInfo;
using ThorsAnvil::BuildTools::Mock::MockActionThrowDetext;
using ThorsAnvil::BuildTools::Mock::MockActionAddObject;
using ThorsAnvil::BuildTools::Mock::MockAction;

TEST(ConnectionSSocketUtilTest, ProtocolInfoDefaultBuild)
{
    MockConnectionSSocketUtil   defaultMockedFunctions;

    auto action = [](){
        ProtocolInfo    protocol;
    };
    ASSERT_NO_THROW(
        MockActionThrowDetext detect(defaultMockedFunctions);action()
    );
}

TEST(ConnectionSSocketUtilTest, ProtocolInfoBuild)
{
    MockConnectionSSocketUtil   defaultMockedFunctions;

    auto action = [](){
        ProtocolInfo    protocol(Protocol::TLS_1_0, Protocol::TLS_1_1);
    };
    ASSERT_NO_THROW(
        MockActionThrowDetext detect(defaultMockedFunctions);action()
    );
}

TEST(ConnectionSSocketUtilTest, ProtocolInfoSetCTX)
{
    MockConnectionSSocketUtil   defaultMockedFunctions;
    MOCK_INPUT(SSL_CTX_ctrl, reinterpret_cast<SSL_CTX*>(0x08), SSL_CTRL_SET_MIN_PROTO_VERSION, TLS1_VERSION, nullptr);
    MOCK_INPUT(SSL_CTX_ctrl, reinterpret_cast<SSL_CTX*>(0x08), SSL_CTRL_SET_MAX_PROTO_VERSION, TLS1_1_VERSION, nullptr);

    ProtocolInfo    protocol(Protocol::TLS_1_0, Protocol::TLS_1_1);

    auto action = [&](){
        MockActionAddObject         checksetProtocolInfo(defaultMockedFunctions, {"Protocol", {"SSL_CTX_ctrl", "SSL_CTX_ctrl"}, {}, {}, {}});
        protocol.setProtocolInfo(reinterpret_cast<SSL_CTX*>(0x08));
    };
    ASSERT_NO_THROW(
        MockActionThrowDetext detect(defaultMockedFunctions);action()
    );
}

TEST(ConnectionSSocketUtilTest, ProtocolInfoSetCTXMinFailed)
{
    MockConnectionSSocketUtil   defaultMockedFunctions;
    MOCK_SYS(SSL_CTX_ctrl,  [&](SSL_CTX*, int v, long m, void*)   {defaultMockedFunctions.checkExpected("SSL_CTX_ctrl");static int count = 0;++count;return count == 1 ? 1 : 0;});
    ProtocolInfo    protocol(Protocol::TLS_1_2, Protocol::TLS_1_3);

    auto action = [&](){
        MockActionAddObject         checksetProtocolInfo(defaultMockedFunctions, {"Protocol", {"SSL_CTX_ctrl", "SSL_CTX_ctrl"}, {}, {}, {}});
        protocol.setProtocolInfo(reinterpret_cast<SSL_CTX*>(0x08));
    };

    ASSERT_THROW(
        MockActionThrowDetext detect(defaultMockedFunctions);action(),
        std::runtime_error
    );
}

TEST(ConnectionSSocketUtilTest, ProtocolInfoSetCTXMaxFailed)
{
    MockConnectionSSocketUtil   defaultMockedFunctions;
    MOCK_SYS(SSL_CTX_ctrl,  [&](SSL_CTX*, int v, long m, void*)   {defaultMockedFunctions.checkExpected("SSL_CTX_ctrl");static int count = 0;++count;return count == 2 ? 1 : 0;});
    ProtocolInfo    protocol(Protocol::TLS_1_2, Protocol::TLS_1_3);

    auto action = [&](){
        MockActionAddObject         checksetProtocolInfo(defaultMockedFunctions, {"Protocol", {"SSL_CTX_ctrl", "SSL_CTX_ctrl"}, {}, {}, {}});
        protocol.setProtocolInfo(reinterpret_cast<SSL_CTX*>(0x08));
    };

    ASSERT_THROW(
        MockActionThrowDetext detect(defaultMockedFunctions);action(),
        std::runtime_error
    );
}

TEST(ConnectionSSocketUtilTest, ProtocolInfoSetSSL)
{
    MockConnectionSSocketUtil   defaultMockedFunctions;
    MOCK_INPUT(SSL_ctrl, reinterpret_cast<SSL*>(0x08), SSL_CTRL_SET_MIN_PROTO_VERSION, TLS1_2_VERSION, nullptr);
    MOCK_INPUT(SSL_ctrl, reinterpret_cast<SSL*>(0x08), SSL_CTRL_SET_MAX_PROTO_VERSION, TLS1_3_VERSION, nullptr);

    ProtocolInfo    protocol(Protocol::TLS_1_2, Protocol::TLS_1_3);

    auto action = [&](){
        MockActionAddObject         checksetProtocolInfo(defaultMockedFunctions, {"Protocol", {"SSL_ctrl", "SSL_ctrl"}, {}, {}, {}});
        protocol.setProtocolInfo(reinterpret_cast<SSL*>(0x08));
    };
    ASSERT_NO_THROW(
        MockActionThrowDetext detect(defaultMockedFunctions);action()
    );
}

TEST(ConnectionSSocketUtilTest, ProtocolInfoSetSSLMinFailed)
{
    MockConnectionSSocketUtil   defaultMockedFunctions;
    MOCK_SYS(SSL_ctrl,  [&](SSL*, int v, long m, void*)   {defaultMockedFunctions.checkExpected("SSL_ctrl");static int count = 0;++count;return count == 1 ? 1 : 0;});
    ProtocolInfo    protocol(Protocol::TLS_1_2, Protocol::TLS_1_3);

    auto action = [&](){
        MockActionAddObject         checksetProtocolInfo(defaultMockedFunctions, {"Protocol", {"SSL_ctrl", "SSL_ctrl"}, {}, {}, {}});
        protocol.setProtocolInfo(reinterpret_cast<SSL*>(0x08));
    };

    ASSERT_THROW(
        MockActionThrowDetext detect(defaultMockedFunctions);action(),
        std::runtime_error
    );
}

TEST(ConnectionSSocketUtilTest, ProtocolInfoSetSSLMaxFailed)
{
    MockConnectionSSocketUtil   defaultMockedFunctions;
    MOCK_SYS(SSL_ctrl,  [&](SSL*, int v, long m, void*)   {defaultMockedFunctions.checkExpected("SSL_ctrl");static int count = 0;++count;return count == 2 ? 1 : 0;});
    ProtocolInfo    protocol(Protocol::TLS_1_2, Protocol::TLS_1_3);

    auto action = [&](){
        MockActionAddObject         checksetProtocolInfo(defaultMockedFunctions, {"Protocol", {"SSL_ctrl", "SSL_ctrl"}, {}, {}, {}});
        protocol.setProtocolInfo(reinterpret_cast<SSL*>(0x08));
    };

    ASSERT_THROW(
        MockActionThrowDetext detect(defaultMockedFunctions);action(),
        std::runtime_error
    );
}

TEST(ConnectionSSocketUtilTest, CipherInfoConstruct)
{
    MockConnectionSSocketUtil   defaultMockedFunctions;

    auto action = [&](){
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
    };
    ASSERT_NO_THROW(
        MockActionThrowDetext detect(defaultMockedFunctions);action()
    );
}

TEST(ConnectionSSocketUtilTest, CipherInfoConstructWithAlternativeValues)
{
    MockConnectionSSocketUtil   defaultMockedFunctions;
    auto action = [](){
        CipherInfo      cipherInfo{"Value1", "Value2"};;

        ASSERT_EQ(cipherInfo.cipherList, "Value1");
        ASSERT_EQ(cipherInfo.cipherSuite,"Value2");
    };
    ASSERT_NO_THROW(
        MockActionThrowDetext detect(defaultMockedFunctions);action()
    );
}

TEST(ConnectionSSocketUtilTest, CipherInfoSetCTX)
{
    MockConnectionSSocketUtil   defaultMockedFunctions;
    std::string input1 = "List1";
    std::string input2 = "Suite2";
    MOCK_INPUT(SSL_CTX_set_cipher_list, reinterpret_cast<SSL_CTX*>(0x08), input1);
    MOCK_INPUT(SSL_CTX_set_ciphersuites, reinterpret_cast<SSL_CTX*>(0x08), input2);
    CipherInfo      cipherInfo{input1, input2};

    auto action = [&](){
        MockActionAddObject         checksetCipherInfo(defaultMockedFunctions, {"Cipher", {"SSL_CTX_set_cipher_list", "SSL_CTX_set_ciphersuites"}, {}, {}, {}});
        cipherInfo.setCipherInfo(reinterpret_cast<SSL_CTX*>(0x08));
    };
    ASSERT_NO_THROW(
        MockActionThrowDetext detect(defaultMockedFunctions);action()
    );
}

TEST(ConnectionSSocketUtilTest, CipherInfoSetSSL)
{
    MockConnectionSSocketUtil   defaultMockedFunctions;
    std::string const input1 = "List1";
    std::string const input2 = "Suite2";
    MOCK_INPUT(SSL_set_cipher_list, reinterpret_cast<SSL*>(0x08), input1);
    MOCK_INPUT(SSL_set_ciphersuites, reinterpret_cast<SSL*>(0x08), input2);
    CipherInfo      cipherInfo{input1, input2};

    auto action = [&](){
        MockActionAddObject         checksetCipherInfo(defaultMockedFunctions, {"Cipher", {"SSL_set_cipher_list", "SSL_set_ciphersuites"}, {}, {}, {}});
        cipherInfo.setCipherInfo(reinterpret_cast<SSL*>(0x08));
    };
    ASSERT_NO_THROW(
        MockActionThrowDetext detect(defaultMockedFunctions);action()
    );
}

TEST(ConnectionSSocketUtilTest, CipherInfoSetCTXListFail)
{
    MockConnectionSSocketUtil   defaultMockedFunctions;
    MOCK_SYS(SSL_CTX_set_cipher_list,   [&](SSL_CTX*, char const* val)    {return 0;});
    CipherInfo      cipherInfo{"List1", "Suite2"};

    auto action = [&]() {
        MockActionAddObject         checksetCipherInfo(defaultMockedFunctions, {"Cipher", {"SSL_CTX_set_cipher_list", "SSL_CTX_set_ciphersuites"}, {}, {}, {}});
        cipherInfo.setCipherInfo(reinterpret_cast<SSL_CTX*>(0x08));
    };
    ASSERT_THROW(
        MockActionThrowDetext detect(defaultMockedFunctions);action(),
        std::runtime_error
    );
}

TEST(ConnectionSSocketUtilTest, CipherInfoSetCTXSuiteFail)
{
    MockConnectionSSocketUtil   defaultMockedFunctions;
    MOCK_SYS(SSL_CTX_set_ciphersuites,  [&](SSL_CTX*, char const* val)    {return 0;});
    CipherInfo      cipherInfo{"List1", "Suite2"};

    auto action = [&]() {
        MockActionAddObject         checksetCipherInfo(defaultMockedFunctions, {"Cipher", {"SSL_CTX_set_cipher_list", "SSL_CTX_set_ciphersuites"}, {}, {}, {}});
        cipherInfo.setCipherInfo(reinterpret_cast<SSL_CTX*>(0x08));
    };
    ASSERT_THROW(
        MockActionThrowDetext detect(defaultMockedFunctions);action(),
        std::runtime_error
    );
}

TEST(ConnectionSSocketUtilTest, CipherInfoSetSSLListFail)
{
    MockConnectionSSocketUtil   defaultMockedFunctions;
    MOCK_SYS(SSL_set_cipher_list,   [&](SSL*, char const* val)    {return 0;});
    CipherInfo      cipherInfo{"List1", "Suite2"};

    auto action = [&]() {
        MockActionAddObject         checksetCipherInfo(defaultMockedFunctions, {"Cipher", {"SSL_set_cipher_list", "SSL_set_ciphersuites"}, {}, {}, {}});
        cipherInfo.setCipherInfo(reinterpret_cast<SSL*>(0x08));
    };
    ASSERT_THROW(
        MockActionThrowDetext detect(defaultMockedFunctions);action(),
        std::runtime_error
    );
}

TEST(ConnectionSSocketUtilTest, CipherInfoSetSSLSuiteFail)
{
    MockConnectionSSocketUtil   defaultMockedFunctions;
    MOCK_SYS(SSL_set_ciphersuites,  [&](SSL*, char const* val)    {return 0;});
    CipherInfo      cipherInfo{"List1", "Suite2"};

    auto action = [&]() {
        MockActionAddObject         checksetCipherInfo(defaultMockedFunctions, {"Cipher", {"SSL_set_cipher_list", "SSL_set_ciphersuites"}, {}, {}, {}});
        cipherInfo.setCipherInfo(reinterpret_cast<SSL*>(0x08));
    };
    ASSERT_THROW(
        MockActionThrowDetext detect(defaultMockedFunctions);action(),
        std::runtime_error
    );
}

TEST(ConnectionSSocketUtilTest, CertificateInfoDefaultConstruct)
{
    MockConnectionSSocketUtil   defaultMockedFunctions;
    auto action = [](){
        CertificateInfo     ca;
    };
    ASSERT_NO_THROW(
        MockActionThrowDetext detect(defaultMockedFunctions);action()
    );
}

TEST(ConnectionSSocketUtilTest, CertificateInfoConstruct)
{
    MockConnectionSSocketUtil   defaultMockedFunctions;
    auto action = [](){
        CertificateInfo     ca("File1", "File2", [](int){return "password";});;
    };
    ASSERT_NO_THROW(
        MockActionThrowDetext detect(defaultMockedFunctions);action()
    );
}


TEST(ConnectionSSocketUtilTest, CertificateInfoDefaultConstructNoAction)
{
    MockConnectionSSocketUtil   defaultMockedFunctions;
    CertificateInfo     ca;

    auto action = [&](){
        ca.setCertificateInfo(reinterpret_cast<SSL_CTX*>(0x08));
    };
    ASSERT_NO_THROW(
        MockActionThrowDetext detect(defaultMockedFunctions);action()
    );
}

MockAction getsetCertificateInfoCTX()
{
    return {
                "setCertificateInfo",
                {"SSL_CTX_set_default_passwd_cb", "SSL_CTX_set_default_passwd_cb_userdata", "SSL_CTX_use_certificate_file", "SSL_CTX_use_PrivateKey_file", "SSL_CTX_check_private_key"},
                {}, {}, {}
            };
}
MockAction getsetCertificateInfoSSL()
{
    return {
                "setCertificateInfo",
                {"SSL_set_default_passwd_cb", "SSL_set_default_passwd_cb_userdata", "SSL_use_certificate_file", "SSL_use_PrivateKey_file", "SSL_check_private_key"},
                {}, {}, {}
            };
}
TEST(ConnectionSSocketUtilTest, CertificateInfoActionCTXDone)
{
    MockConnectionSSocketUtil   defaultMockedFunctions;
    std::string certFile = "certFile1";
    std::string keyFile  = "keyFile2";
    MOCK_INPUT(SSL_CTX_use_certificate_file, reinterpret_cast<SSL_CTX*>(0x08), certFile, SSL_FILETYPE_PEM);
    MOCK_INPUT(SSL_CTX_use_PrivateKey_file, reinterpret_cast<SSL_CTX*>(0x08), keyFile, SSL_FILETYPE_PEM);

    CertificateInfo     ca(certFile, keyFile, [](int){return "password";});

    auto action = [&](){
        MockActionAddObject         checksetCertificateInfo(defaultMockedFunctions, getsetCertificateInfoCTX());
        ca.setCertificateInfo(reinterpret_cast<SSL_CTX*>(0x08));
    };
    ASSERT_NO_THROW(
        MockActionThrowDetext detect(defaultMockedFunctions);action()
    );
}

TEST(ConnectionSSocketUtilTest, CertificateInfoActionSSLDone)
{
    MockConnectionSSocketUtil   defaultMockedFunctions;
    std::string certFile = "certFile1";
    std::string keyFile  = "keyFile2";
    MOCK_INPUT(SSL_use_certificate_file, reinterpret_cast<SSL*>(0x08), certFile, SSL_FILETYPE_PEM);
    MOCK_INPUT(SSL_use_PrivateKey_file, reinterpret_cast<SSL*>(0x08), keyFile, SSL_FILETYPE_PEM);

    CertificateInfo     ca(certFile, keyFile, [](int){return "password";});

    auto action = [&](){
        MockActionAddObject         checksetCertificateInfo(defaultMockedFunctions, getsetCertificateInfoSSL());
        ca.setCertificateInfo(reinterpret_cast<SSL*>(0x08));
    };
    ASSERT_NO_THROW(
        MockActionThrowDetext detect(defaultMockedFunctions);action()
    );
}

TEST(ConnectionSSocketUtilTest, CertificateInfoConstructionInvalidCert)
{
    MockConnectionSSocketUtil   defaultMockedFunctions;
    auto action = [](){
        CertificateInfo     ca("File1", "");
    };
    ASSERT_THROW(
        MockActionThrowDetext detect(defaultMockedFunctions);action(),
        std::runtime_error
    );
}

TEST(ConnectionSSocketUtilTest, CertificateInfoConstructionInvalidKey)
{
    MockConnectionSSocketUtil   defaultMockedFunctions;
    auto action = [](){
        CertificateInfo     ca("", "File2");
    };
    ASSERT_THROW(
        MockActionThrowDetext detect(defaultMockedFunctions);action(),
        std::runtime_error
    );
}

TEST(ConnectionSSocketUtilTest, CertificateInfoActionCTXInvalidCert)
{
    MockConnectionSSocketUtil   defaultMockedFunctions;
    std::string certFile = "certFile1";
    std::string keyFile  = "keyFile2";
    MOCK_SYS(SSL_CTX_use_certificate_file,              [&](SSL_CTX*, char const* v, int)   {defaultMockedFunctions.checkExpected("SSL_CTX_use_certificate_file");return 0;});
    MOCK_INPUT(SSL_CTX_use_certificate_file, reinterpret_cast<SSL_CTX*>(0x08), certFile, SSL_FILETYPE_PEM);

    CertificateInfo     ca(certFile, keyFile, [](int){return "password";});

    auto action = [&](){
        MockActionAddObject         checksetCertificateInfo(defaultMockedFunctions, getsetCertificateInfoCTX());
        ca.setCertificateInfo(reinterpret_cast<SSL_CTX*>(0x08));
    };
    ASSERT_THROW(
        MockActionThrowDetext detect(defaultMockedFunctions);action(),
        std::runtime_error
    );
}

TEST(ConnectionSSocketUtilTest, CertificateInfoActionCTXInvalidKey)
{
    MockConnectionSSocketUtil   defaultMockedFunctions;
    std::string certFile = "certFile1";
    std::string keyFile  = "keyFile2";
    MOCK_SYS(SSL_CTX_use_PrivateKey_file,               [&](SSL_CTX*, char const* v, int)   {defaultMockedFunctions.checkExpected("SSL_CTX_use_PrivateKey_file");return 0;});
    MOCK_INPUT(SSL_CTX_use_certificate_file, reinterpret_cast<SSL_CTX*>(0x08), certFile, SSL_FILETYPE_PEM);
    MOCK_INPUT(SSL_CTX_use_PrivateKey_file, reinterpret_cast<SSL_CTX*>(0x08), keyFile, SSL_FILETYPE_PEM);

    CertificateInfo     ca(certFile, keyFile, [](int){return "password";});

    auto action = [&](){
        MockActionAddObject         checksetCertificateInfo(defaultMockedFunctions, getsetCertificateInfoCTX());
        ca.setCertificateInfo(reinterpret_cast<SSL_CTX*>(0x08));
    };
    ASSERT_THROW(
        MockActionThrowDetext detect(defaultMockedFunctions);action(),
        std::runtime_error
    );
}

TEST(ConnectionSSocketUtilTest, CertificateInfoActionCTXInvalidCheck)
{
    MockConnectionSSocketUtil   defaultMockedFunctions;
    std::string certFile = "certFile1";
    std::string keyFile  = "keyFile2";
    MOCK_SYS(SSL_CTX_check_private_key,                 [&](SSL_CTX const*)                 {defaultMockedFunctions.checkExpected("SSL_CTX_check_private_key");return 0;});
    MOCK_INPUT(SSL_CTX_use_certificate_file, reinterpret_cast<SSL_CTX*>(0x08), certFile, SSL_FILETYPE_PEM);
    MOCK_INPUT(SSL_CTX_use_PrivateKey_file, reinterpret_cast<SSL_CTX*>(0x08), keyFile, SSL_FILETYPE_PEM);

    CertificateInfo     ca(certFile, keyFile, [](int){return "password";});

    auto action = [&](){
        MockActionAddObject         checksetCertificateInfo(defaultMockedFunctions, getsetCertificateInfoCTX());
        ca.setCertificateInfo(reinterpret_cast<SSL_CTX*>(0x08));
    };
    ASSERT_THROW(
        MockActionThrowDetext detect(defaultMockedFunctions);action(),
        std::runtime_error
    );
}

TEST(ConnectionSSocketUtilTest, CertificateInfoActionSSLInvalidCert)
{
    MockConnectionSSocketUtil   defaultMockedFunctions;
    std::string certFile = "certFile1";
    std::string keyFile  = "keyFile2";
    MOCK_SYS(SSL_use_certificate_file,              [&](SSL*, char const* v, int)   {defaultMockedFunctions.checkExpected("SSL_use_certificate_file");return 0;});
    MOCK_INPUT(SSL_use_certificate_file, reinterpret_cast<SSL*>(0x08), certFile, SSL_FILETYPE_PEM);
    //MOCK_INPUT(SSL_use_PrivateKey_file, reinterpret_cast<SSL*>(0x08), keyFile, SSL_FILETYPE_PEM);

    CertificateInfo     ca(certFile, keyFile, [](int){return "password";});

    auto action = [&](){
        MockActionAddObject         checksetCertificateInfo(defaultMockedFunctions, getsetCertificateInfoSSL());
        ca.setCertificateInfo(reinterpret_cast<SSL*>(0x08));
    };
    ASSERT_THROW(
        MockActionThrowDetext detect(defaultMockedFunctions);action(),
        std::runtime_error
    );
}

TEST(ConnectionSSocketUtilTest, CertificateInfoActionSSLInvalidKey)
{
    MockConnectionSSocketUtil   defaultMockedFunctions;
    std::string certFile = "certFile1";
    std::string keyFile  = "keyFile2";
    MOCK_SYS(SSL_use_PrivateKey_file,               [&](SSL*, char const* v, int)   {defaultMockedFunctions.checkExpected("SSL_use_PrivateKey_file");return 0;});
    MOCK_INPUT(SSL_use_certificate_file, reinterpret_cast<SSL*>(0x08), certFile, SSL_FILETYPE_PEM);
    MOCK_INPUT(SSL_use_PrivateKey_file, reinterpret_cast<SSL*>(0x08), keyFile, SSL_FILETYPE_PEM);

    CertificateInfo     ca(certFile, keyFile, [](int){return "password";});

    auto action = [&](){
        MockActionAddObject         checksetCertificateInfo(defaultMockedFunctions, getsetCertificateInfoSSL());
        ca.setCertificateInfo(reinterpret_cast<SSL*>(0x08));
    };
    ASSERT_THROW(
        MockActionThrowDetext detect(defaultMockedFunctions);action(),
        std::runtime_error
    );
}

TEST(ConnectionSSocketUtilTest, CertificateInfoActionSSLInvalidCheck)
{
    MockConnectionSSocketUtil   defaultMockedFunctions;
    std::string certFile = "certFile1";
    std::string keyFile  = "keyFile2";
    MOCK_SYS(SSL_check_private_key,                 [&](SSL const*)                 {defaultMockedFunctions.checkExpected("SSL_check_private_key");return 0;});
    MOCK_INPUT(SSL_use_certificate_file, reinterpret_cast<SSL*>(0x08), certFile, SSL_FILETYPE_PEM);
    MOCK_INPUT(SSL_use_PrivateKey_file, reinterpret_cast<SSL*>(0x08), keyFile, SSL_FILETYPE_PEM);

    CertificateInfo     ca(certFile, keyFile, [](int){return "password";});

    auto action = [&](){
        MockActionAddObject         checksetCertificateInfo(defaultMockedFunctions, getsetCertificateInfoSSL());
        ca.setCertificateInfo(reinterpret_cast<SSL*>(0x08));
    };
    ASSERT_THROW(
        MockActionThrowDetext detect(defaultMockedFunctions);action(),
        std::runtime_error
    );
}

TEST(ConnectionSSocketUtilTest, CertifcateAuthorityInfoDefaultConstruct)
{
    MockConnectionSSocketUtil   defaultMockedFunctions;
    CertifcateAuthorityInfo     ca;

    auto action = [&](){
        ca.setCertifcateAuthorityInfo(reinterpret_cast<SSL_CTX*>(0x08));
    };
    ASSERT_NO_THROW(
        MockActionThrowDetext detect(defaultMockedFunctions);action()
    );
}

TEST(ConnectionSSocketUtilTest, CertifcateAuthoritySetDefaultFile)
{
    MockConnectionSSocketUtil   defaultMockedFunctions;
    CertifcateAuthorityInfo     ca;

    auto action = [&](){
        MockActionAddObject         checksetCertifcateAuthorityInfo(defaultMockedFunctions, {"CertificateAuthroty", {"SSL_CTX_set_default_verify_file"}, {}, {}, {}});
        ca.file.loadDefault = true;
        ca.setCertifcateAuthorityInfo(reinterpret_cast<SSL_CTX*>(0x08));
    };
    ASSERT_NO_THROW(
        MockActionThrowDetext detect(defaultMockedFunctions);action()
    );
}

TEST(ConnectionSSocketUtilTest, CertifcateAuthoritySetDefaultDir)
{
    MockConnectionSSocketUtil   defaultMockedFunctions;
    CertifcateAuthorityInfo     ca;

    auto action = [&](){
        MockActionAddObject         checksetCertifcateAuthorityInfo(defaultMockedFunctions, {"CertificateAuthroty", {"SSL_CTX_set_default_verify_dir"}, {}, {}, {}});
        ca.dir.loadDefault = true;
        ca.setCertifcateAuthorityInfo(reinterpret_cast<SSL_CTX*>(0x08));
    };
    ASSERT_NO_THROW(
        MockActionThrowDetext detect(defaultMockedFunctions);action()
    );
}

TEST(ConnectionSSocketUtilTest, CertifcateAuthoritySetDefaultStore)
{
    MockConnectionSSocketUtil   defaultMockedFunctions;
    CertifcateAuthorityInfo     ca;

    auto action = [&](){
        MockActionAddObject         checksetCertifcateAuthorityInfo(defaultMockedFunctions, {"CertificateAuthroty", {"SSL_CTX_set_default_verify_store"}, {}, {}, {}});
        ca.store.loadDefault = true;
        ca.setCertifcateAuthorityInfo(reinterpret_cast<SSL_CTX*>(0x08));
    };
    ASSERT_NO_THROW(
        MockActionThrowDetext detect(defaultMockedFunctions);action()
    );
}

TEST(ConnectionSSocketUtilTest, CertifcateAuthorityAddFile)
{
    MockConnectionSSocketUtil   defaultMockedFunctions;
    std::string  file = "Item 1";
    MOCK_INPUT(SSL_CTX_load_verify_file, reinterpret_cast<SSL_CTX*>(0x08), file);
    CertifcateAuthorityInfo     ca;

    auto action = [&](){
        MockActionAddObject         checksetCertifcateAuthorityInfo(defaultMockedFunctions, {"CertificateAuthroty", {"SSL_CTX_load_verify_file"}, {}, {}, {}});
        ca.file.items.push_back(file);
        ca.setCertifcateAuthorityInfo(reinterpret_cast<SSL_CTX*>(0x08));
    };
    ASSERT_NO_THROW(
        MockActionThrowDetext detect(defaultMockedFunctions);action()
    );
}

TEST(ConnectionSSocketUtilTest, CertifcateAuthorityAddDir)
{
    MockConnectionSSocketUtil   defaultMockedFunctions;
    std::string  file = "Item 1";
    MOCK_INPUT(SSL_CTX_load_verify_dir, reinterpret_cast<SSL_CTX*>(0x08), file);
    CertifcateAuthorityInfo     ca;

    auto action = [&](){
        MockActionAddObject         checksetCertifcateAuthorityInfo(defaultMockedFunctions, {"CertificateAuthroty", {"SSL_CTX_load_verify_dir"}, {}, {}, {}});
        ca.dir.items.push_back(file);
        ca.setCertifcateAuthorityInfo(reinterpret_cast<SSL_CTX*>(0x08));
    };
    ASSERT_NO_THROW(
        MockActionThrowDetext detect(defaultMockedFunctions);action()
    );
}

TEST(ConnectionSSocketUtilTest, CertifcateAuthorityAddStore)
{
    MockConnectionSSocketUtil   defaultMockedFunctions;
    std::string  file = "Item 1";
    MOCK_INPUT(SSL_CTX_load_verify_store, reinterpret_cast<SSL_CTX*>(0x08), file);
    CertifcateAuthorityInfo     ca;

    auto action = [&](){
        MockActionAddObject         checksetCertifcateAuthorityInfo(defaultMockedFunctions, {"CertificateAuthroty", {"SSL_CTX_load_verify_store"}, {}, {}, {}});
        ca.store.items.push_back(file);
        ca.setCertifcateAuthorityInfo(reinterpret_cast<SSL_CTX*>(0x08));
    };
    ASSERT_NO_THROW(
        MockActionThrowDetext detect(defaultMockedFunctions);action()
    );
}

TEST(ConnectionSSocketUtilTest, CertifcateAuthorityFailedDefaultFile)
{
    MockConnectionSSocketUtil   defaultMockedFunctions;
    MOCK_SYS(SSL_CTX_set_default_verify_file,   [&](SSL_CTX*)               {defaultMockedFunctions.checkExpected("SSL_CTX_set_default_verify_file");return 0;});
    CertifcateAuthorityInfo     ca;

    auto action = [&](){
        MockActionAddObject         checksetCertifcateAuthorityInfo(defaultMockedFunctions, {"CertificateAuthroty", {"SSL_CTX_set_default_verify_file"}, {}, {}, {}});
        ca.file.loadDefault = true;
        ca.setCertifcateAuthorityInfo(reinterpret_cast<SSL_CTX*>(0x08));
    };
    ASSERT_THROW(
        MockActionThrowDetext detect(defaultMockedFunctions);action(),
        std::runtime_error
    );
}

TEST(ConnectionSSocketUtilTest, CertifcateAuthorityFailedDefaultDir)
{
    MockConnectionSSocketUtil   defaultMockedFunctions;
    MOCK_SYS(SSL_CTX_set_default_verify_dir,    [&](SSL_CTX*)               {defaultMockedFunctions.checkExpected("SSL_CTX_set_default_verify_dir");return 0;});
    CertifcateAuthorityInfo     ca;

    auto action = [&](){
        MockActionAddObject         checksetCertifcateAuthorityInfo(defaultMockedFunctions, {"CertificateAuthroty", {"SSL_CTX_set_default_verify_dir"}, {}, {}, {}});
        ca.dir.loadDefault = true;
        ca.setCertifcateAuthorityInfo(reinterpret_cast<SSL_CTX*>(0x08));
    };
    ASSERT_THROW(
        MockActionThrowDetext detect(defaultMockedFunctions);action(),
        std::runtime_error
    );
}

TEST(ConnectionSSocketUtilTest, CertifcateAuthorityFailedDefaultStore)
{
    MockConnectionSSocketUtil   defaultMockedFunctions;
    MOCK_SYS(SSL_CTX_set_default_verify_store,    [&](SSL_CTX*)             {defaultMockedFunctions.checkExpected("SSL_CTX_set_default_verify_store");return 0;});
    CertifcateAuthorityInfo     ca;

    auto action = [&](){
        MockActionAddObject         checksetCertifcateAuthorityInfo(defaultMockedFunctions, {"CertificateAuthroty", {"SSL_CTX_set_default_verify_store"}, {}, {}, {}});
        ca.store.loadDefault = true;
        ca.setCertifcateAuthorityInfo(reinterpret_cast<SSL_CTX*>(0x08));
    };
    ASSERT_THROW(
        MockActionThrowDetext detect(defaultMockedFunctions);action(),
        std::runtime_error
    );
}

TEST(ConnectionSSocketUtilTest, CertifcateAuthorityAddFileFail)
{
    MockConnectionSSocketUtil   defaultMockedFunctions;
    std::string  file = "Item 1";
    MOCK_SYS(SSL_CTX_load_verify_file,         [&](SSL_CTX*, char const*)  {defaultMockedFunctions.checkExpected("SSL_CTX_load_verify_file");return 0;});
    MOCK_INPUT(SSL_CTX_load_verify_file, reinterpret_cast<SSL_CTX*>(0x08), file);
    CertifcateAuthorityInfo     ca;

    auto action = [&](){
        MockActionAddObject         checksetCertifcateAuthorityInfo(defaultMockedFunctions, {"CertificateAuthroty", {"SSL_CTX_load_verify_file"}, {}, {}, {}});
        ca.file.items.push_back(file);
        ca.setCertifcateAuthorityInfo(reinterpret_cast<SSL_CTX*>(0x08));
    };
    ASSERT_THROW(
        MockActionThrowDetext detect(defaultMockedFunctions);action(),
        std::runtime_error
    );
}

TEST(ConnectionSSocketUtilTest, CertifcateAuthorityAddDirFail)
{
    MockConnectionSSocketUtil   defaultMockedFunctions;
    std::string  file = "Item 1";
    MOCK_SYS(SSL_CTX_load_verify_dir,           [&](SSL_CTX*, char const* v){defaultMockedFunctions.checkExpected("SSL_CTX_load_verify_dir");return 0;});
    MOCK_INPUT(SSL_CTX_load_verify_dir, reinterpret_cast<SSL_CTX*>(0x08), file);
    CertifcateAuthorityInfo     ca;

    auto action = [&](){
        MockActionAddObject         checksetCertifcateAuthorityInfo(defaultMockedFunctions, {"CertificateAuthroty", {"SSL_CTX_load_verify_dir"}, {}, {}, {}});
        ca.dir.items.push_back(file);
        ca.setCertifcateAuthorityInfo(reinterpret_cast<SSL_CTX*>(0x08));
    };
    ASSERT_THROW(
        MockActionThrowDetext detect(defaultMockedFunctions);action(),
        std::runtime_error
    );
}

TEST(ConnectionSSocketUtilTest, CertifcateAuthorityAddStoreFail)
{
    MockConnectionSSocketUtil   defaultMockedFunctions;
    std::string  file = "Item 1";
    MOCK_SYS(SSL_CTX_load_verify_store,           [&](SSL_CTX*, char const* v){defaultMockedFunctions.checkExpected("SSL_CTX_load_verify_store");return 0;});
    MOCK_INPUT(SSL_CTX_load_verify_store, reinterpret_cast<SSL_CTX*>(0x08), file);
    CertifcateAuthorityInfo     ca;

    auto action = [&](){
        MockActionAddObject         checksetCertifcateAuthorityInfo(defaultMockedFunctions, {"CertificateAuthroty", {"SSL_CTX_load_verify_store"}, {}, {}, {}});
        ca.store.items.push_back(file);
        ca.setCertifcateAuthorityInfo(reinterpret_cast<SSL_CTX*>(0x08));
    };
    ASSERT_THROW(
        MockActionThrowDetext detect(defaultMockedFunctions);action(),
        std::runtime_error
    );
}

TEST(ConnectionSSocketUtilTest, ClientCAListInfoCTX)
{
    MockConnectionSSocketUtil   defaultMockedFunctions;

    auto action = [](){
        ClientCAListInfo  list;
        list.setCertifcateAuthorityInfo(reinterpret_cast<SSL_CTX*>(0x08));
    };
    ASSERT_NO_THROW(
        MockActionThrowDetext detect(defaultMockedFunctions);action()
    );
}

TEST(ConnectionSSocketUtilTest, ClientCAListInfoValidateClientCTX)
{
    MockConnectionSSocketUtil   defaultMockedFunctions;
    ClientCAListInfo            list;

    auto action = [&](){
        MockActionAddObject         checksetCertifcateAuthorityInfo(defaultMockedFunctions, {"ClientCAList", {"SSL_CTX_set_verify"}, {}, {}, {}});
        list.verifyClientCA = true;
        list.setCertifcateAuthorityInfo(reinterpret_cast<SSL_CTX*>(0x08));
    };
    ASSERT_NO_THROW(
        MockActionThrowDetext detect(defaultMockedFunctions);action()
    );
}

TEST(ConnectionSSocketUtilTest, ClientCAListInfoAddClientFileCTX)
{
    MockConnectionSSocketUtil   defaultMockedFunctions;
    ClientCAListInfo            list;

    auto action = [&](){
        MockActionAddObject         checksetCertifcateAuthorityInfo(defaultMockedFunctions, {"CertificateAuthroty", {"SSL_add_file_cert_subjects_to_stack", "SSL_CTX_set_client_CA_list"}, {}, {"sk_X509_NAME_new_null_wrapper"}, {}});
        list.file.items.push_back("File 1");
        list.setCertifcateAuthorityInfo(reinterpret_cast<SSL_CTX*>(0x08));
    };
    ASSERT_NO_THROW(
        MockActionThrowDetext detect(defaultMockedFunctions);action()
    );
}

TEST(ConnectionSSocketUtilTest, ClientCAListInfoAddClientDirCTX)
{
    MockConnectionSSocketUtil   defaultMockedFunctions;
    ClientCAListInfo            list;

    auto action = [&](){
        MockActionAddObject         checksetCertifcateAuthorityInfo(defaultMockedFunctions, {"CertificateAuthroty", {"SSL_add_dir_cert_subjects_to_stack", "SSL_CTX_set_client_CA_list"}, {}, {"sk_X509_NAME_new_null_wrapper"}, {}});
        list.dir.items.push_back("File 1");
        list.setCertifcateAuthorityInfo(reinterpret_cast<SSL_CTX*>(0x08));
    };
    ASSERT_NO_THROW(
        MockActionThrowDetext detect(defaultMockedFunctions);action()
    );
}

TEST(ConnectionSSocketUtilTest, ClientCAListInfoAddClientStoreCTX)
{
    MockConnectionSSocketUtil   defaultMockedFunctions;
    ClientCAListInfo            list;

    auto action = [&](){
        MockActionAddObject         checksetCertifcateAuthorityInfo(defaultMockedFunctions, {"CertificateAuthroty", {"SSL_add_store_cert_subjects_to_stack", "SSL_CTX_set_client_CA_list"}, {}, {"sk_X509_NAME_new_null_wrapper"}, {}});
        list.store.items.push_back("File 1");
        list.setCertifcateAuthorityInfo(reinterpret_cast<SSL_CTX*>(0x08));
    };
    ASSERT_NO_THROW(
        MockActionThrowDetext detect(defaultMockedFunctions);action()
    );
}

TEST(ConnectionSSocketUtilTest, ClientCAListInfoValidateClientFailCTX)
{
    MockConnectionSSocketUtil   defaultMockedFunctions;
    ClientCAListInfo            list;

    auto action = [&](){
        MockActionAddObject         checksetCertifcateAuthorityInfo(defaultMockedFunctions, {"CertificateAuthroty", {"SSL_CTX_set_verify"}, {}, {}, {}});
        list.verifyClientCA = true;
        list.setCertifcateAuthorityInfo(reinterpret_cast<SSL_CTX*>(0x08));
    };
    ASSERT_NO_THROW(
        MockActionThrowDetext detect(defaultMockedFunctions);action()
    );
}

TEST(ConnectionSSocketUtilTest, ClientCAListInfoAddClientFileFailCTX)
{
    MockConnectionSSocketUtil   defaultMockedFunctions;
    MOCK_SYS(SSL_add_file_cert_subjects_to_stack,   [&](STACK_OF(X509_NAME)*, char const*)   {defaultMockedFunctions.checkExpected("SSL_add_file_cert_subjects_to_stack");return 0;});
    ClientCAListInfo            list;

    auto action = [&](){
        MockActionAddObject         checksetCertifcateAuthorityInfo(defaultMockedFunctions, {"CertificateAuthroty", {"SSL_add_file_cert_subjects_to_stack"}, {}, {"sk_X509_NAME_new_null_wrapper", "sk_X509_NAME_pop_free_wrapper"}, {}});
        list.file.items.push_back("File 1");
        list.setCertifcateAuthorityInfo(reinterpret_cast<SSL_CTX*>(0x08));
    };
    ASSERT_THROW(
        MockActionThrowDetext detect(defaultMockedFunctions);action(),
        std::runtime_error
    );
}

TEST(ConnectionSSocketUtilTest, ClientCAListInfoAddClientDirFailCTX)
{
    MockConnectionSSocketUtil   defaultMockedFunctions;
    MOCK_SYS(SSL_add_dir_cert_subjects_to_stack,    [&](STACK_OF(X509_NAME)*, char const*)   {defaultMockedFunctions.checkExpected("SSL_add_dir_cert_subjects_to_stack");return 0;});
    ClientCAListInfo            list;

    auto action = [&](){
        MockActionAddObject         checksetCertifcateAuthorityInfo(defaultMockedFunctions, {"CertificateAuthroty", {"SSL_add_dir_cert_subjects_to_stack"}, {}, {"sk_X509_NAME_new_null_wrapper", "sk_X509_NAME_pop_free_wrapper"}, {}});
        list.dir.items.push_back("File 1");
        list.setCertifcateAuthorityInfo(reinterpret_cast<SSL_CTX*>(0x08));
    };
    ASSERT_THROW(
        MockActionThrowDetext detect(defaultMockedFunctions);action(),
        std::runtime_error
    );
}

TEST(ConnectionSSocketUtilTest, ClientCAListInfoAddClientStoreFailCTX)
{
    MockConnectionSSocketUtil   defaultMockedFunctions;
    MOCK_SYS(SSL_add_store_cert_subjects_to_stack,  [&](STACK_OF(X509_NAME)*, char const*)   {defaultMockedFunctions.checkExpected("SSL_add_store_cert_subjects_to_stack");return 0;});
    ClientCAListInfo            list;

    auto action = [&](){
        MockActionAddObject         checksetCertifcateAuthorityInfo(defaultMockedFunctions, {"CertificateAuthroty", {"SSL_add_store_cert_subjects_to_stack"}, {}, {"sk_X509_NAME_new_null_wrapper", "sk_X509_NAME_pop_free_wrapper"}, {}});
        list.store.items.push_back("File 1");
        list.setCertifcateAuthorityInfo(reinterpret_cast<SSL_CTX*>(0x08));
    };
    ASSERT_THROW(
        MockActionThrowDetext detect(defaultMockedFunctions);action(),
        std::runtime_error
    );
}

TEST(ConnectionSSocketUtilTest, ClientCAListInfoSSL)
{
    MockConnectionSSocketUtil   defaultMockedFunctions;

    auto action = [](){
        ClientCAListInfo  list;
        list.setCertifcateAuthorityInfo(reinterpret_cast<SSL*>(0x08));
    };
    ASSERT_NO_THROW(
        MockActionThrowDetext detect(defaultMockedFunctions);action()
    );
}

TEST(ConnectionSSocketUtilTest, ClientCAListInfoValidateClientSSL)
{
    MockConnectionSSocketUtil   defaultMockedFunctions;
    ClientCAListInfo            list;

    auto action = [&](){
        MockActionAddObject         checksetCertifcateAuthorityInfo(defaultMockedFunctions, {"ClientCAList", {"SSL_set_verify"}, {}, {}, {}});
        list.verifyClientCA = true;
        list.setCertifcateAuthorityInfo(reinterpret_cast<SSL*>(0x08));
    };
    ASSERT_NO_THROW(
        MockActionThrowDetext detect(defaultMockedFunctions);action()
    );
}

TEST(ConnectionSSocketUtilTest, ClientCAListInfoAddClientFileSSL)
{
    MockConnectionSSocketUtil   defaultMockedFunctions;
    ClientCAListInfo            list;

    auto action = [&](){
        MockActionAddObject         checksetCertifcateAuthorityInfo(defaultMockedFunctions, {"CertificateAuthroty", {"SSL_add_file_cert_subjects_to_stack", "SSL_set_client_CA_list"}, {}, {"sk_X509_NAME_new_null_wrapper"}, {}});
        list.file.items.push_back("File 1");
        list.setCertifcateAuthorityInfo(reinterpret_cast<SSL*>(0x08));
    };
    ASSERT_NO_THROW(
        MockActionThrowDetext detect(defaultMockedFunctions);action()
    );
}

TEST(ConnectionSSocketUtilTest, ClientCAListInfoAddClientDirSSL)
{
    MockConnectionSSocketUtil   defaultMockedFunctions;
    ClientCAListInfo            list;

    auto action = [&](){
        MockActionAddObject         checksetCertifcateAuthorityInfo(defaultMockedFunctions, {"CertificateAuthroty", {"SSL_add_dir_cert_subjects_to_stack", "SSL_set_client_CA_list"}, {}, {"sk_X509_NAME_new_null_wrapper"}, {}});
        list.dir.items.push_back("File 1");
        list.setCertifcateAuthorityInfo(reinterpret_cast<SSL*>(0x08));
    };
    ASSERT_NO_THROW(
        MockActionThrowDetext detect(defaultMockedFunctions);action()
    );
}

TEST(ConnectionSSocketUtilTest, ClientCAListInfoAddClientStoreSSL)
{
    MockConnectionSSocketUtil   defaultMockedFunctions;
    ClientCAListInfo            list;

    auto action = [&](){
        MockActionAddObject         checksetCertifcateAuthorityInfo(defaultMockedFunctions, {"CertificateAuthroty", {"SSL_add_store_cert_subjects_to_stack", "SSL_set_client_CA_list"}, {}, {"sk_X509_NAME_new_null_wrapper"}, {}});
        list.store.items.push_back("File 1");
        list.setCertifcateAuthorityInfo(reinterpret_cast<SSL*>(0x08));
    };
    ASSERT_NO_THROW(
        MockActionThrowDetext detect(defaultMockedFunctions);action()
    );
}

TEST(ConnectionSSocketUtilTest, ClientCAListInfoValidateClientFailSSL)
{
    MockConnectionSSocketUtil   defaultMockedFunctions;
    ClientCAListInfo            list;

    auto action = [&](){
        MockActionAddObject         checksetCertifcateAuthorityInfo(defaultMockedFunctions, {"CertificateAuthroty", {"SSL_set_verify"}, {}, {}, {}});
        list.verifyClientCA = true;
        list.setCertifcateAuthorityInfo(reinterpret_cast<SSL*>(0x08));
    };
    ASSERT_NO_THROW(
        MockActionThrowDetext detect(defaultMockedFunctions);action()
    );
}

TEST(ConnectionSSocketUtilTest, ClientCAListInfoAddClientFileFailSSL)
{
    MockConnectionSSocketUtil   defaultMockedFunctions;
    MOCK_SYS(SSL_add_file_cert_subjects_to_stack,   [&](STACK_OF(X509_NAME)*, char const*)   {defaultMockedFunctions.checkExpected("SSL_add_file_cert_subjects_to_stack");return 0;});
    ClientCAListInfo            list;

    auto action = [&](){
        MockActionAddObject         checksetCertifcateAuthorityInfo(defaultMockedFunctions, {"CertificateAuthroty", {"SSL_add_file_cert_subjects_to_stack"}, {}, {"sk_X509_NAME_new_null_wrapper", "sk_X509_NAME_pop_free_wrapper"}, {}});
        list.file.items.push_back("File 1");
        list.setCertifcateAuthorityInfo(reinterpret_cast<SSL*>(0x08));
    };
    ASSERT_THROW(
        MockActionThrowDetext detect(defaultMockedFunctions);action(),
        std::runtime_error
    );
}

TEST(ConnectionSSocketUtilTest, ClientCAListInfoAddClientDirFailSSL)
{
    MockConnectionSSocketUtil   defaultMockedFunctions;
    MOCK_SYS(SSL_add_dir_cert_subjects_to_stack,    [&](STACK_OF(X509_NAME)*, char const*)   {defaultMockedFunctions.checkExpected("SSL_add_dir_cert_subjects_to_stack");return 0;});
    ClientCAListInfo            list;

    auto action = [&](){
        MockActionAddObject         checksetCertifcateAuthorityInfo(defaultMockedFunctions, {"CertificateAuthroty", {"SSL_add_dir_cert_subjects_to_stack"}, {}, {"sk_X509_NAME_new_null_wrapper", "sk_X509_NAME_pop_free_wrapper"}, {}});
        list.dir.items.push_back("File 1");
        list.setCertifcateAuthorityInfo(reinterpret_cast<SSL*>(0x08));
    };
    ASSERT_THROW(
        MockActionThrowDetext detect(defaultMockedFunctions);action(),
        std::runtime_error
    );
}

TEST(ConnectionSSocketUtilTest, ClientCAListInfoAddClientStoreFailSSL)
{
    MockConnectionSSocketUtil   defaultMockedFunctions;
    MOCK_SYS(SSL_add_store_cert_subjects_to_stack,  [&](STACK_OF(X509_NAME)*, char const*)   {defaultMockedFunctions.checkExpected("SSL_add_store_cert_subjects_to_stack");return 0;});
    ClientCAListInfo            list;

    auto action = [&](){
        MockActionAddObject         checksetCertifcateAuthorityInfo(defaultMockedFunctions, {"CertificateAuthroty", {"SSL_add_store_cert_subjects_to_stack"}, {}, {"sk_X509_NAME_new_null_wrapper", "sk_X509_NAME_pop_free_wrapper"}, {}});
        list.store.items.push_back("File 1");
        list.setCertifcateAuthorityInfo(reinterpret_cast<SSL*>(0x08));
    };
    ASSERT_THROW(
        MockActionThrowDetext detect(defaultMockedFunctions);action(),
        std::runtime_error
    );
}

