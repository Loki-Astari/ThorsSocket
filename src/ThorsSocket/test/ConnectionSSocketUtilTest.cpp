#include <gtest/gtest.h>
#include "ConnectionSSocketUtil.h"
#include "test/MockDefaultThorsSocket.h"

using ThorsAnvil::ThorsSocket::ConnectionType::Protocol;
using ThorsAnvil::ThorsSocket::ConnectionType::ProtocolInfo;
using ThorsAnvil::ThorsSocket::ConnectionType::CipherInfo;
using ThorsAnvil::ThorsSocket::ConnectionType::CertificateInfo;
using ThorsAnvil::ThorsSocket::ConnectionType::CertifcateAuthorityInfo;
using ThorsAnvil::ThorsSocket::ConnectionType::ClientCAListInfo;
using ThorsAnvil::BuildTools::Mock1::MockActionThrowDetext;
using ThorsAnvil::BuildTools::Mock1::MockActionAddObject;
using ThorsAnvil::BuildTools::Mock1::MockAction;

TEST(ConnectionSSocketUtilTest, ProtocolInfoDefaultBuild)
{
    MockDefaultThorsSocket      defaultMockedFunctions;

    auto action = [](){
        ProtocolInfo    protocol;
    };
    ASSERT_NO_THROW(
        MockActionThrowDetext detect;action()
    );
}

TEST(ConnectionSSocketUtilTest, ProtocolInfoBuild)
{
    MockDefaultThorsSocket      defaultMockedFunctions;

    auto action = [](){
        ProtocolInfo    protocol(Protocol::TLS_1_0, Protocol::TLS_1_1);
    };
    ASSERT_NO_THROW(
        MockActionThrowDetext detect;action()
    );
}

TEST(ConnectionSSocketUtilTest, ProtocolInfoSetCTX)
{
    MockDefaultThorsSocket      defaultMockedFunctions;
    MOCK_INPUT(SSL_CTX_ctrl, reinterpret_cast<SSL_CTX*>(0x08), SSL_CTRL_SET_MIN_PROTO_VERSION, TLS1_VERSION, nullptr);
    MOCK_INPUT(SSL_CTX_ctrl, reinterpret_cast<SSL_CTX*>(0x08), SSL_CTRL_SET_MAX_PROTO_VERSION, TLS1_1_VERSION, nullptr);

    ProtocolInfo    protocol(Protocol::TLS_1_0, Protocol::TLS_1_1);

    auto action = [&](){
        MockActionAddObject         checksetProtocolInfo({"Protocol", {"SSL_CTX_ctrl", "SSL_CTX_ctrl"}, {}, {}, {}});
        protocol.apply(reinterpret_cast<SSL_CTX*>(0x08));
    };
    ASSERT_NO_THROW(
        MockActionThrowDetext detect;action()
    );
}

TEST(ConnectionSSocketUtilTest, ProtocolInfoSetCTXMinFailed)
{
    MockDefaultThorsSocket      defaultMockedFunctions;
    MOCK_SYS(SSL_CTX_ctrl,  [](SSL_CTX*, int v, long m, void*)   {static int count = 0;++count;return count == 1 ? 1 : 0;});
    ProtocolInfo    protocol(Protocol::TLS_1_2, Protocol::TLS_1_3);

    auto action = [&](){
        MockActionAddObject         checksetProtocolInfo({"Protocol", {"SSL_CTX_ctrl", "SSL_CTX_ctrl"}, {}, {}, {}}, {"ERR_get_error"});
        protocol.apply(reinterpret_cast<SSL_CTX*>(0x08));
    };

    ASSERT_THROW(
        MockActionThrowDetext detect;action(),
        std::runtime_error
    );
}

TEST(ConnectionSSocketUtilTest, ProtocolInfoSetCTXMaxFailed)
{
    MockDefaultThorsSocket      defaultMockedFunctions;
    MOCK_SYS(SSL_CTX_ctrl,  [](SSL_CTX*, int v, long m, void*)   {static int count = 0;++count;return count == 2 ? 1 : 0;});
    ProtocolInfo    protocol(Protocol::TLS_1_2, Protocol::TLS_1_3);

    auto action = [&](){
        MockActionAddObject         checksetProtocolInfo({"Protocol", {"SSL_CTX_ctrl", "SSL_CTX_ctrl"}, {}, {}, {}}, {"ERR_get_error"});
        protocol.apply(reinterpret_cast<SSL_CTX*>(0x08));
    };

    ASSERT_THROW(
        MockActionThrowDetext detect;action(),
        std::runtime_error
    );
}

TEST(ConnectionSSocketUtilTest, ProtocolInfoSetSSL)
{
    MockDefaultThorsSocket      defaultMockedFunctions;
    MOCK_INPUT(SSL_ctrl, reinterpret_cast<SSL*>(0x08), SSL_CTRL_SET_MIN_PROTO_VERSION, TLS1_2_VERSION, nullptr);
    MOCK_INPUT(SSL_ctrl, reinterpret_cast<SSL*>(0x08), SSL_CTRL_SET_MAX_PROTO_VERSION, TLS1_3_VERSION, nullptr);

    ProtocolInfo    protocol(Protocol::TLS_1_2, Protocol::TLS_1_3);

    auto action = [&](){
        MockActionAddObject         checksetProtocolInfo({"Protocol", {"SSL_ctrl", "SSL_ctrl"}, {}, {}, {}}, {"ERR_get_error"});
        protocol.apply(reinterpret_cast<SSL*>(0x08));
    };
    ASSERT_NO_THROW(
        MockActionThrowDetext detect;action()
    );
}

TEST(ConnectionSSocketUtilTest, ProtocolInfoSetSSLMinFailed)
{
    MockDefaultThorsSocket      defaultMockedFunctions;
    MOCK_SYS(SSL_ctrl,  [](SSL*, int v, long m, void*)   {static int count = 0;++count;return count == 1 ? 1 : 0;});
    ProtocolInfo    protocol(Protocol::TLS_1_2, Protocol::TLS_1_3);

    auto action = [&](){
        MockActionAddObject         checksetProtocolInfo({"Protocol", {"SSL_ctrl", "SSL_ctrl"}, {}, {}, {}}, {"ERR_get_error"});
        protocol.apply(reinterpret_cast<SSL*>(0x08));
    };

    ASSERT_THROW(
        MockActionThrowDetext detect;action(),
        std::runtime_error
    );
}

TEST(ConnectionSSocketUtilTest, ProtocolInfoSetSSLMaxFailed)
{
    MockDefaultThorsSocket      defaultMockedFunctions;
    MOCK_SYS(SSL_ctrl,  [](SSL*, int v, long m, void*)   {static int count = 0;++count;return count == 2 ? 1 : 0;});
    ProtocolInfo    protocol(Protocol::TLS_1_2, Protocol::TLS_1_3);

    auto action = [&](){
        MockActionAddObject         checksetProtocolInfo({"Protocol", {"SSL_ctrl", "SSL_ctrl"}, {}, {}, {}}, {"ERR_get_error"});
        protocol.apply(reinterpret_cast<SSL*>(0x08));
    };

    ASSERT_THROW(
        MockActionThrowDetext detect;action(),
        std::runtime_error
    );
}

TEST(ConnectionSSocketUtilTest, CipherInfoConstruct)
{
    MockDefaultThorsSocket      defaultMockedFunctions;

    auto action = [](){
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
        MockActionThrowDetext detect;action()
    );
}

TEST(ConnectionSSocketUtilTest, CipherInfoConstructWithAlternativeValues)
{
    MockDefaultThorsSocket      defaultMockedFunctions;
    auto action = [](){
        CipherInfo      cipherInfo{"Value1", "Value2"};;

        ASSERT_EQ(cipherInfo.cipherList, "Value1");
        ASSERT_EQ(cipherInfo.cipherSuite,"Value2");
    };
    ASSERT_NO_THROW(
        MockActionThrowDetext detect;action()
    );
}

TEST(ConnectionSSocketUtilTest, CipherInfoSetCTX)
{
    MockDefaultThorsSocket      defaultMockedFunctions;
    std::string input1 = "List1";
    std::string input2 = "Suite2";
    MOCK_INPUT(SSL_CTX_set_cipher_list, reinterpret_cast<SSL_CTX*>(0x08), input1);
    MOCK_INPUT(SSL_CTX_set_ciphersuites, reinterpret_cast<SSL_CTX*>(0x08), input2);
    CipherInfo      cipherInfo{input1, input2};

    auto action = [&](){
        MockActionAddObject         checksetCipherInfo({"Cipher", {"SSL_CTX_set_cipher_list", "SSL_CTX_set_ciphersuites"}, {}, {}, {}});
        cipherInfo.apply(reinterpret_cast<SSL_CTX*>(0x08));
    };
    ASSERT_NO_THROW(
        MockActionThrowDetext detect;action()
    );
}

TEST(ConnectionSSocketUtilTest, CipherInfoSetSSL)
{
    MockDefaultThorsSocket      defaultMockedFunctions;
    std::string const input1 = "List1";
    std::string const input2 = "Suite2";
    MOCK_INPUT(SSL_set_cipher_list, reinterpret_cast<SSL*>(0x08), input1);
    MOCK_INPUT(SSL_set_ciphersuites, reinterpret_cast<SSL*>(0x08), input2);
    CipherInfo      cipherInfo{input1, input2};

    auto action = [&](){
        MockActionAddObject         checksetCipherInfo({"Cipher", {"SSL_set_cipher_list", "SSL_set_ciphersuites"}, {}, {}, {}});
        cipherInfo.apply(reinterpret_cast<SSL*>(0x08));
    };
    ASSERT_NO_THROW(
        MockActionThrowDetext detect;action()
    );
}

TEST(ConnectionSSocketUtilTest, CipherInfoSetCTXListFail)
{
    MockDefaultThorsSocket      defaultMockedFunctions;
    MOCK_SYS(SSL_CTX_set_cipher_list,   [](SSL_CTX*, char const* val)    {return 0;});
    CipherInfo      cipherInfo{"List1", "Suite2"};

    auto action = [&]() {
        MockActionAddObject         checksetCipherInfo({"Cipher", {"SSL_CTX_set_cipher_list", "SSL_CTX_set_ciphersuites"}, {}, {}, {}}, {"ERR_get_error"});
        cipherInfo.apply(reinterpret_cast<SSL_CTX*>(0x08));
    };
    ASSERT_THROW(
        MockActionThrowDetext detect;action(),
        std::runtime_error
    );
}

TEST(ConnectionSSocketUtilTest, CipherInfoSetCTXSuiteFail)
{
    MockDefaultThorsSocket      defaultMockedFunctions;
    MOCK_SYS(SSL_CTX_set_ciphersuites,  [](SSL_CTX*, char const* val)    {return 0;});
    CipherInfo      cipherInfo{"List1", "Suite2"};

    auto action = [&]() {
        MockActionAddObject         checksetCipherInfo({"Cipher", {"SSL_CTX_set_cipher_list", "SSL_CTX_set_ciphersuites"}, {}, {}, {}}, {"ERR_get_error"});
        cipherInfo.apply(reinterpret_cast<SSL_CTX*>(0x08));
    };
    ASSERT_THROW(
        MockActionThrowDetext detect;action(),
        std::runtime_error
    );
}

TEST(ConnectionSSocketUtilTest, CipherInfoSetSSLListFail)
{
    MockDefaultThorsSocket      defaultMockedFunctions;
    MOCK_SYS(SSL_set_cipher_list,   [](SSL*, char const* val)    {return 0;});
    CipherInfo      cipherInfo{"List1", "Suite2"};

    auto action = [&]() {
        MockActionAddObject         checksetCipherInfo({"Cipher", {"SSL_set_cipher_list", "SSL_set_ciphersuites"}, {}, {}, {}}, {"ERR_get_error"});
        cipherInfo.apply(reinterpret_cast<SSL*>(0x08));
    };
    ASSERT_THROW(
        MockActionThrowDetext detect;action(),
        std::runtime_error
    );
}

TEST(ConnectionSSocketUtilTest, CipherInfoSetSSLSuiteFail)
{
    MockDefaultThorsSocket      defaultMockedFunctions;
    MOCK_SYS(SSL_set_ciphersuites,  [](SSL*, char const* val)    {return 0;});
    CipherInfo      cipherInfo{"List1", "Suite2"};

    auto action = [&]() {
        MockActionAddObject         checksetCipherInfo({"Cipher", {"SSL_set_cipher_list", "SSL_set_ciphersuites"}, {}, {}, {}}, {"ERR_get_error"});
        cipherInfo.apply(reinterpret_cast<SSL*>(0x08));
    };
    ASSERT_THROW(
        MockActionThrowDetext detect;action(),
        std::runtime_error
    );
}

TEST(ConnectionSSocketUtilTest, CertificateInfoDefaultConstruct)
{
    MockDefaultThorsSocket      defaultMockedFunctions;
    auto action = [](){
        CertificateInfo     ca;
    };
    ASSERT_NO_THROW(
        MockActionThrowDetext detect;action()
    );
}

TEST(ConnectionSSocketUtilTest, CertificateInfoConstruct)
{
    MockDefaultThorsSocket      defaultMockedFunctions;
    auto action = [](){
        CertificateInfo     ca("File1", "File2", [](int){return "password";});;
    };
    ASSERT_NO_THROW(
        MockActionThrowDetext detect;action()
    );
}


TEST(ConnectionSSocketUtilTest, CertificateInfoDefaultConstructNoAction)
{
    MockDefaultThorsSocket      defaultMockedFunctions;
    CertificateInfo     ca;

    auto action = [&](){
        ca.apply(reinterpret_cast<SSL_CTX*>(0x08));
    };
    ASSERT_NO_THROW(
        MockActionThrowDetext detect;action()
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
    MockDefaultThorsSocket      defaultMockedFunctions;
    std::string certFile = "certFile1";
    std::string keyFile  = "keyFile2";
    MOCK_INPUT(SSL_CTX_use_certificate_file, reinterpret_cast<SSL_CTX*>(0x08), certFile, SSL_FILETYPE_PEM);
    MOCK_INPUT(SSL_CTX_use_PrivateKey_file, reinterpret_cast<SSL_CTX*>(0x08), keyFile, SSL_FILETYPE_PEM);

    CertificateInfo     ca(certFile, keyFile, [](int){return "password";});

    auto action = [&](){
        MockActionAddObject         checksetCertificateInfo(getsetCertificateInfoCTX());
        ca.apply(reinterpret_cast<SSL_CTX*>(0x08));
    };
    ASSERT_NO_THROW(
        MockActionThrowDetext detect;action()
    );
}

TEST(ConnectionSSocketUtilTest, CertificateInfoActionSSLDone)
{
    MockDefaultThorsSocket      defaultMockedFunctions;
    std::string certFile = "certFile1";
    std::string keyFile  = "keyFile2";
    MOCK_INPUT(SSL_use_certificate_file, reinterpret_cast<SSL*>(0x08), certFile, SSL_FILETYPE_PEM);
    MOCK_INPUT(SSL_use_PrivateKey_file, reinterpret_cast<SSL*>(0x08), keyFile, SSL_FILETYPE_PEM);

    CertificateInfo     ca(certFile, keyFile, [](int){return "password";});

    auto action = [&](){
        MockActionAddObject         checksetCertificateInfo(getsetCertificateInfoSSL());
        ca.apply(reinterpret_cast<SSL*>(0x08));
    };
    ASSERT_NO_THROW(
        MockActionThrowDetext detect;action()
    );
}

TEST(ConnectionSSocketUtilTest, CertificateInfoConstructionInvalidCert)
{
    MockDefaultThorsSocket      defaultMockedFunctions;
    auto action = [](){
        CertificateInfo     ca("File1", "");
    };
    ASSERT_THROW(
        MockActionThrowDetext detect;action(),
        std::runtime_error
    );
}

TEST(ConnectionSSocketUtilTest, CertificateInfoConstructionInvalidKey)
{
    MockDefaultThorsSocket      defaultMockedFunctions;
    auto action = [](){
        CertificateInfo     ca("", "File2");
    };
    ASSERT_THROW(
        MockActionThrowDetext detect;action(),
        std::runtime_error
    );
}

TEST(ConnectionSSocketUtilTest, CertificateInfoActionCTXInvalidCert)
{
    MockDefaultThorsSocket      defaultMockedFunctions;
    std::string certFile = "certFile1";
    std::string keyFile  = "keyFile2";
    MOCK_SYS(SSL_CTX_use_certificate_file,              [](SSL_CTX*, char const* v, int)   {return 0;});
    MOCK_INPUT(SSL_CTX_use_certificate_file, reinterpret_cast<SSL_CTX*>(0x08), certFile, SSL_FILETYPE_PEM);

    CertificateInfo     ca(certFile, keyFile, [](int){return "password";});

    auto action = [&](){
        MockActionAddObject         checksetCertificateInfo(getsetCertificateInfoCTX(), {"ERR_get_error"});
        ca.apply(reinterpret_cast<SSL_CTX*>(0x08));
    };
    ASSERT_THROW(
        MockActionThrowDetext detect;action(),
        std::runtime_error
    );
}

TEST(ConnectionSSocketUtilTest, CertificateInfoActionCTXInvalidKey)
{
    MockDefaultThorsSocket      defaultMockedFunctions;
    std::string certFile = "certFile1";
    std::string keyFile  = "keyFile2";
    MOCK_SYS(SSL_CTX_use_PrivateKey_file,               [](SSL_CTX*, char const* v, int)   {return 0;});
    MOCK_INPUT(SSL_CTX_use_certificate_file, reinterpret_cast<SSL_CTX*>(0x08), certFile, SSL_FILETYPE_PEM);
    MOCK_INPUT(SSL_CTX_use_PrivateKey_file, reinterpret_cast<SSL_CTX*>(0x08), keyFile, SSL_FILETYPE_PEM);

    CertificateInfo     ca(certFile, keyFile, [](int){return "password";});

    auto action = [&](){
        MockActionAddObject         checksetCertificateInfo(getsetCertificateInfoCTX(), {"ERR_get_error"});
        ca.apply(reinterpret_cast<SSL_CTX*>(0x08));
    };
    ASSERT_THROW(
        MockActionThrowDetext detect;action(),
        std::runtime_error
    );
}

TEST(ConnectionSSocketUtilTest, CertificateInfoActionCTXInvalidCheck)
{
    MockDefaultThorsSocket      defaultMockedFunctions;
    std::string certFile = "certFile1";
    std::string keyFile  = "keyFile2";
    MOCK_SYS(SSL_CTX_check_private_key,                 [](SSL_CTX const*)                 {return 0;});
    MOCK_INPUT(SSL_CTX_use_certificate_file, reinterpret_cast<SSL_CTX*>(0x08), certFile, SSL_FILETYPE_PEM);
    MOCK_INPUT(SSL_CTX_use_PrivateKey_file, reinterpret_cast<SSL_CTX*>(0x08), keyFile, SSL_FILETYPE_PEM);

    CertificateInfo     ca(certFile, keyFile, [](int){return "password";});

    auto action = [&](){
        MockActionAddObject         checksetCertificateInfo(getsetCertificateInfoCTX(), {"ERR_get_error"});
        ca.apply(reinterpret_cast<SSL_CTX*>(0x08));
    };
    ASSERT_THROW(
        MockActionThrowDetext detect;action(),
        std::runtime_error
    );
}

TEST(ConnectionSSocketUtilTest, CertificateInfoActionSSLInvalidCert)
{
    MockDefaultThorsSocket      defaultMockedFunctions;
    std::string certFile = "certFile1";
    std::string keyFile  = "keyFile2";
    MOCK_SYS(SSL_use_certificate_file,              [](SSL*, char const* v, int)   {return 0;});
    MOCK_INPUT(SSL_use_certificate_file, reinterpret_cast<SSL*>(0x08), certFile, SSL_FILETYPE_PEM);

    CertificateInfo     ca(certFile, keyFile, [](int){return "password";});

    auto action = [&](){
        MockActionAddObject         checksetCertificateInfo(getsetCertificateInfoSSL(), {"ERR_get_error"});
        ca.apply(reinterpret_cast<SSL*>(0x08));
    };
    ASSERT_THROW(
        MockActionThrowDetext detect;action(),
        std::runtime_error
    );
}

TEST(ConnectionSSocketUtilTest, CertificateInfoActionSSLInvalidKey)
{
    MockDefaultThorsSocket      defaultMockedFunctions;
    std::string certFile = "certFile1";
    std::string keyFile  = "keyFile2";
    MOCK_SYS(SSL_use_PrivateKey_file,               [](SSL*, char const* v, int)   {return 0;});
    MOCK_INPUT(SSL_use_certificate_file, reinterpret_cast<SSL*>(0x08), certFile, SSL_FILETYPE_PEM);
    MOCK_INPUT(SSL_use_PrivateKey_file, reinterpret_cast<SSL*>(0x08), keyFile, SSL_FILETYPE_PEM);

    CertificateInfo     ca(certFile, keyFile, [](int){return "password";});

    auto action = [&](){
        MockActionAddObject         checksetCertificateInfo(getsetCertificateInfoSSL(), {"ERR_get_error"});
        ca.apply(reinterpret_cast<SSL*>(0x08));
    };
    ASSERT_THROW(
        MockActionThrowDetext detect;action(),
        std::runtime_error
    );
}

TEST(ConnectionSSocketUtilTest, CertificateInfoActionSSLInvalidCheck)
{
    MockDefaultThorsSocket      defaultMockedFunctions;
    std::string certFile = "certFile1";
    std::string keyFile  = "keyFile2";
    MOCK_SYS(SSL_check_private_key,                 [](SSL const*)                 {return 0;});
    MOCK_INPUT(SSL_use_certificate_file, reinterpret_cast<SSL*>(0x08), certFile, SSL_FILETYPE_PEM);
    MOCK_INPUT(SSL_use_PrivateKey_file, reinterpret_cast<SSL*>(0x08), keyFile, SSL_FILETYPE_PEM);

    CertificateInfo     ca(certFile, keyFile, [](int){return "password";});

    auto action = [&](){
        MockActionAddObject         checksetCertificateInfo(getsetCertificateInfoSSL(), {"ERR_get_error"});
        ca.apply(reinterpret_cast<SSL*>(0x08));
    };
    ASSERT_THROW(
        MockActionThrowDetext detect;action(),
        std::runtime_error
    );
}

TEST(ConnectionSSocketUtilTest, CertifcateAuthorityInfoDefaultConstruct)
{
    MockDefaultThorsSocket      defaultMockedFunctions;
    CertifcateAuthorityInfo     ca;

    auto action = [&](){
        ca.apply(reinterpret_cast<SSL_CTX*>(0x08));
    };
    ASSERT_NO_THROW(
        MockActionThrowDetext detect;action()
    );
}

TEST(ConnectionSSocketUtilTest, CertifcateAuthoritySetDefaultFile)
{
    MockDefaultThorsSocket      defaultMockedFunctions;
    CertifcateAuthorityInfo     ca;

    auto action = [&](){
        MockActionAddObject         checksetCertifcateAuthorityInfo({"CertificateAuthroty", {"SSL_CTX_set_default_verify_file"}, {}, {}, {}});
        ca.file.loadDefault = true;
        ca.apply(reinterpret_cast<SSL_CTX*>(0x08));
    };
    ASSERT_NO_THROW(
        MockActionThrowDetext detect;action()
    );
}

TEST(ConnectionSSocketUtilTest, CertifcateAuthoritySetDefaultDir)
{
    MockDefaultThorsSocket      defaultMockedFunctions;
    CertifcateAuthorityInfo     ca;

    auto action = [&](){
        MockActionAddObject         checksetCertifcateAuthorityInfo({"CertificateAuthroty", {"SSL_CTX_set_default_verify_dir"}, {}, {}, {}});
        ca.dir.loadDefault = true;
        ca.apply(reinterpret_cast<SSL_CTX*>(0x08));
    };
    ASSERT_NO_THROW(
        MockActionThrowDetext detect;action()
    );
}

TEST(ConnectionSSocketUtilTest, CertifcateAuthoritySetDefaultStore)
{
    MockDefaultThorsSocket      defaultMockedFunctions;
    CertifcateAuthorityInfo     ca;

    auto action = [&](){
        MockActionAddObject         checksetCertifcateAuthorityInfo({"CertificateAuthroty", {"SSL_CTX_set_default_verify_store"}, {}, {}, {}});
        ca.store.loadDefault = true;
        ca.apply(reinterpret_cast<SSL_CTX*>(0x08));
    };
    ASSERT_NO_THROW(
        MockActionThrowDetext detect;action()
    );
}

TEST(ConnectionSSocketUtilTest, CertifcateAuthorityAddFile)
{
    MockDefaultThorsSocket      defaultMockedFunctions;
    std::string  file = "Item 1";
    MOCK_INPUT(SSL_CTX_load_verify_file, reinterpret_cast<SSL_CTX*>(0x08), file);
    CertifcateAuthorityInfo     ca;

    auto action = [&](){
        MockActionAddObject         checksetCertifcateAuthorityInfo({"CertificateAuthroty", {"SSL_CTX_load_verify_file"}, {}, {}, {}});
        ca.file.items.push_back(file);
        ca.apply(reinterpret_cast<SSL_CTX*>(0x08));
    };
    ASSERT_NO_THROW(
        MockActionThrowDetext detect;action()
    );
}

TEST(ConnectionSSocketUtilTest, CertifcateAuthorityAddDir)
{
    MockDefaultThorsSocket      defaultMockedFunctions;
    std::string  file = "Item 1";
    MOCK_INPUT(SSL_CTX_load_verify_dir, reinterpret_cast<SSL_CTX*>(0x08), file);
    CertifcateAuthorityInfo     ca;

    auto action = [&](){
        MockActionAddObject         checksetCertifcateAuthorityInfo({"CertificateAuthroty", {"SSL_CTX_load_verify_dir"}, {}, {}, {}});
        ca.dir.items.push_back(file);
        ca.apply(reinterpret_cast<SSL_CTX*>(0x08));
    };
    ASSERT_NO_THROW(
        MockActionThrowDetext detect;action()
    );
}

TEST(ConnectionSSocketUtilTest, CertifcateAuthorityAddStore)
{
    MockDefaultThorsSocket      defaultMockedFunctions;
    std::string  file = "Item 1";
    MOCK_INPUT(SSL_CTX_load_verify_store, reinterpret_cast<SSL_CTX*>(0x08), file);
    CertifcateAuthorityInfo     ca;

    auto action = [&](){
        MockActionAddObject         checksetCertifcateAuthorityInfo({"CertificateAuthroty", {"SSL_CTX_load_verify_store"}, {}, {}, {}});
        ca.store.items.push_back(file);
        ca.apply(reinterpret_cast<SSL_CTX*>(0x08));
    };
    ASSERT_NO_THROW(
        MockActionThrowDetext detect;action()
    );
}

TEST(ConnectionSSocketUtilTest, CertifcateAuthorityFailedDefaultFile)
{
    MockDefaultThorsSocket      defaultMockedFunctions;
    MOCK_SYS(SSL_CTX_set_default_verify_file,   [](SSL_CTX*)               {return 0;});
    CertifcateAuthorityInfo     ca;

    auto action = [&](){
        MockActionAddObject         checksetCertifcateAuthorityInfo({"CertificateAuthroty", {"SSL_CTX_set_default_verify_file"}, {}, {}, {}}, {"ERR_get_error"});
        ca.file.loadDefault = true;
        ca.apply(reinterpret_cast<SSL_CTX*>(0x08));
    };
    ASSERT_THROW(
        MockActionThrowDetext detect;action(),
        std::runtime_error
    );
}

TEST(ConnectionSSocketUtilTest, CertifcateAuthorityFailedDefaultDir)
{
    MockDefaultThorsSocket      defaultMockedFunctions;
    MOCK_SYS(SSL_CTX_set_default_verify_dir,    [](SSL_CTX*)               {return 0;});
    CertifcateAuthorityInfo     ca;

    auto action = [&](){
        MockActionAddObject         checksetCertifcateAuthorityInfo({"CertificateAuthroty", {"SSL_CTX_set_default_verify_dir"}, {}, {}, {}}, {"ERR_get_error"});
        ca.dir.loadDefault = true;
        ca.apply(reinterpret_cast<SSL_CTX*>(0x08));
    };
    ASSERT_THROW(
        MockActionThrowDetext detect;action(),
        std::runtime_error
    );
}

TEST(ConnectionSSocketUtilTest, CertifcateAuthorityFailedDefaultStore)
{
    MockDefaultThorsSocket      defaultMockedFunctions;
    MOCK_SYS(SSL_CTX_set_default_verify_store,    [](SSL_CTX*)             {return 0;});
    CertifcateAuthorityInfo     ca;

    auto action = [&](){
        MockActionAddObject         checksetCertifcateAuthorityInfo({"CertificateAuthroty", {"SSL_CTX_set_default_verify_store"}, {}, {}, {}}, {"ERR_get_error"});
        ca.store.loadDefault = true;
        ca.apply(reinterpret_cast<SSL_CTX*>(0x08));
    };
    ASSERT_THROW(
        MockActionThrowDetext detect;action(),
        std::runtime_error
    );
}

TEST(ConnectionSSocketUtilTest, CertifcateAuthorityAddFileFail)
{
    MockDefaultThorsSocket      defaultMockedFunctions;
    std::string  file = "Item 1";
    MOCK_SYS(SSL_CTX_load_verify_file,         [](SSL_CTX*, char const*)  {return 0;});
    MOCK_INPUT(SSL_CTX_load_verify_file, reinterpret_cast<SSL_CTX*>(0x08), file);
    CertifcateAuthorityInfo     ca;

    auto action = [&](){
        MockActionAddObject         checksetCertifcateAuthorityInfo({"CertificateAuthroty", {"SSL_CTX_load_verify_file"}, {}, {}, {}}, {"ERR_get_error"});
        ca.file.items.push_back(file);
        ca.apply(reinterpret_cast<SSL_CTX*>(0x08));
    };
    ASSERT_THROW(
        MockActionThrowDetext detect;action(),
        std::runtime_error
    );
}

TEST(ConnectionSSocketUtilTest, CertifcateAuthorityAddDirFail)
{
    MockDefaultThorsSocket      defaultMockedFunctions;
    std::string  file = "Item 1";
    MOCK_SYS(SSL_CTX_load_verify_dir,           [](SSL_CTX*, char const* v){return 0;});
    MOCK_INPUT(SSL_CTX_load_verify_dir, reinterpret_cast<SSL_CTX*>(0x08), file);
    CertifcateAuthorityInfo     ca;

    auto action = [&](){
        MockActionAddObject         checksetCertifcateAuthorityInfo({"CertificateAuthroty", {"SSL_CTX_load_verify_dir"}, {}, {}, {}}, {"ERR_get_error"});
        ca.dir.items.push_back(file);
        ca.apply(reinterpret_cast<SSL_CTX*>(0x08));
    };
    ASSERT_THROW(
        MockActionThrowDetext detect;action(),
        std::runtime_error
    );
}

TEST(ConnectionSSocketUtilTest, CertifcateAuthorityAddStoreFail)
{
    MockDefaultThorsSocket      defaultMockedFunctions;
    std::string  file = "Item 1";
    MOCK_SYS(SSL_CTX_load_verify_store,           [](SSL_CTX*, char const* v){return 0;});
    MOCK_INPUT(SSL_CTX_load_verify_store, reinterpret_cast<SSL_CTX*>(0x08), file);
    CertifcateAuthorityInfo     ca;

    auto action = [&](){
        MockActionAddObject         checksetCertifcateAuthorityInfo({"CertificateAuthroty", {"SSL_CTX_load_verify_store"}, {}, {}, {}}, {"ERR_get_error"});
        ca.store.items.push_back(file);
        ca.apply(reinterpret_cast<SSL_CTX*>(0x08));
    };
    ASSERT_THROW(
        MockActionThrowDetext detect;action(),
        std::runtime_error
    );
}

TEST(ConnectionSSocketUtilTest, ClientCAListInfoCTX)
{
    MockDefaultThorsSocket      defaultMockedFunctions;

    auto action = [](){
        ClientCAListInfo  list;
        list.apply(reinterpret_cast<SSL_CTX*>(0x08));
    };
    ASSERT_NO_THROW(
        MockActionThrowDetext detect;action()
    );
}

TEST(ConnectionSSocketUtilTest, ClientCAListInfoValidateClientCTX)
{
    MockDefaultThorsSocket      defaultMockedFunctions;
    ClientCAListInfo            list;

    auto action = [&](){
        MockActionAddObject         checksetCertifcateAuthorityInfo({"ClientCAList", {"SSL_CTX_set_verify"}, {}, {}, {}});
        list.verifyClientCA = true;
        list.apply(reinterpret_cast<SSL_CTX*>(0x08));
    };
    ASSERT_NO_THROW(
        MockActionThrowDetext detect;action()
    );
}

TEST(ConnectionSSocketUtilTest, ClientCAListInfoAddClientFileCTX)
{
    MockDefaultThorsSocket      defaultMockedFunctions;
    ClientCAListInfo            list;

    auto action = [&](){
        MockActionAddObject         checksetCertifcateAuthorityInfo({"CertificateAuthroty", {"SSL_add_file_cert_subjects_to_stack", "SSL_CTX_set_client_CA_list"}, {}, {"sk_X509_NAME_new_null_wrapper"}, {}});
        list.file.items.push_back("File 1");
        list.apply(reinterpret_cast<SSL_CTX*>(0x08));
    };
    ASSERT_NO_THROW(
        MockActionThrowDetext detect;action()
    );
}

TEST(ConnectionSSocketUtilTest, ClientCAListInfoAddClientDirCTX)
{
    MockDefaultThorsSocket      defaultMockedFunctions;
    ClientCAListInfo            list;

    auto action = [&](){
        MockActionAddObject         checksetCertifcateAuthorityInfo({"CertificateAuthroty", {"SSL_add_dir_cert_subjects_to_stack", "SSL_CTX_set_client_CA_list"}, {}, {"sk_X509_NAME_new_null_wrapper"}, {}});
        list.dir.items.push_back("File 1");
        list.apply(reinterpret_cast<SSL_CTX*>(0x08));
    };
    ASSERT_NO_THROW(
        MockActionThrowDetext detect;action()
    );
}

TEST(ConnectionSSocketUtilTest, ClientCAListInfoAddClientStoreCTX)
{
    MockDefaultThorsSocket      defaultMockedFunctions;
    ClientCAListInfo            list;

    auto action = [&](){
        MockActionAddObject         checksetCertifcateAuthorityInfo({"CertificateAuthroty", {"SSL_add_store_cert_subjects_to_stack", "SSL_CTX_set_client_CA_list"}, {}, {"sk_X509_NAME_new_null_wrapper"}, {}});
        list.store.items.push_back("File 1");
        list.apply(reinterpret_cast<SSL_CTX*>(0x08));
    };
    ASSERT_NO_THROW(
        MockActionThrowDetext detect;action()
    );
}

TEST(ConnectionSSocketUtilTest, ClientCAListInfoValidateClientFailCTX)
{
    MockDefaultThorsSocket      defaultMockedFunctions;
    ClientCAListInfo            list;

    auto action = [&](){
        MockActionAddObject         checksetCertifcateAuthorityInfo({"CertificateAuthroty", {"SSL_CTX_set_verify"}, {}, {}, {}}, {"ERR_get_error"});
        list.verifyClientCA = true;
        list.apply(reinterpret_cast<SSL_CTX*>(0x08));
    };
    ASSERT_NO_THROW(
        MockActionThrowDetext detect;action()
    );
}

TEST(ConnectionSSocketUtilTest, ClientCAListInfoAddClientFileFailCTX)
{
    MockDefaultThorsSocket      defaultMockedFunctions;
    MOCK_SYS(SSL_add_file_cert_subjects_to_stack,   [](STACK_OF(X509_NAME)*, char const*)   {return 0;});
    ClientCAListInfo            list;

    auto action = [&](){
        MockActionAddObject         checksetCertifcateAuthorityInfo({"CertificateAuthroty", {"SSL_add_file_cert_subjects_to_stack"}, {}, {"sk_X509_NAME_new_null_wrapper", "sk_X509_NAME_pop_free_wrapper"}, {}}, {"ERR_get_error"});
        list.file.items.push_back("File 1");
        list.apply(reinterpret_cast<SSL_CTX*>(0x08));
    };
    ASSERT_THROW(
        MockActionThrowDetext detect;action(),
        std::runtime_error
    );
}

TEST(ConnectionSSocketUtilTest, ClientCAListInfoAddClientDirFailCTX)
{
    MockDefaultThorsSocket      defaultMockedFunctions;
    MOCK_SYS(SSL_add_dir_cert_subjects_to_stack,    [](STACK_OF(X509_NAME)*, char const*)   {return 0;});
    ClientCAListInfo            list;

    auto action = [&](){
        MockActionAddObject         checksetCertifcateAuthorityInfo({"CertificateAuthroty", {"SSL_add_dir_cert_subjects_to_stack"}, {}, {"sk_X509_NAME_new_null_wrapper", "sk_X509_NAME_pop_free_wrapper"}, {}}, {"ERR_get_error"});
        list.dir.items.push_back("File 1");
        list.apply(reinterpret_cast<SSL_CTX*>(0x08));
    };
    ASSERT_THROW(
        MockActionThrowDetext detect;action(),
        std::runtime_error
    );
}

TEST(ConnectionSSocketUtilTest, ClientCAListInfoAddClientStoreFailCTX)
{
    MockDefaultThorsSocket      defaultMockedFunctions;
    MOCK_SYS(SSL_add_store_cert_subjects_to_stack,  [](STACK_OF(X509_NAME)*, char const*)   {return 0;});
    ClientCAListInfo            list;

    auto action = [&](){
        MockActionAddObject         checksetCertifcateAuthorityInfo({"CertificateAuthroty", {"SSL_add_store_cert_subjects_to_stack"}, {}, {"sk_X509_NAME_new_null_wrapper", "sk_X509_NAME_pop_free_wrapper"}, {}}, {"ERR_get_error"});
        list.store.items.push_back("File 1");
        list.apply(reinterpret_cast<SSL_CTX*>(0x08));
    };
    ASSERT_THROW(
        MockActionThrowDetext detect;action(),
        std::runtime_error
    );
}

TEST(ConnectionSSocketUtilTest, ClientCAListInfoSSL)
{
    MockDefaultThorsSocket      defaultMockedFunctions;

    auto action = [](){
        ClientCAListInfo  list;
        list.apply(reinterpret_cast<SSL*>(0x08));
    };
    ASSERT_NO_THROW(
        MockActionThrowDetext detect;action()
    );
}

TEST(ConnectionSSocketUtilTest, ClientCAListInfoValidateClientSSL)
{
    MockDefaultThorsSocket      defaultMockedFunctions;
    ClientCAListInfo            list;

    auto action = [&](){
        MockActionAddObject         checksetCertifcateAuthorityInfo({"ClientCAList", {"SSL_set_verify"}, {}, {}, {}});
        list.verifyClientCA = true;
        list.apply(reinterpret_cast<SSL*>(0x08));
    };
    ASSERT_NO_THROW(
        MockActionThrowDetext detect;action()
    );
}

TEST(ConnectionSSocketUtilTest, ClientCAListInfoAddClientFileSSL)
{
    MockDefaultThorsSocket      defaultMockedFunctions;
    ClientCAListInfo            list;

    auto action = [&](){
        MockActionAddObject         checksetCertifcateAuthorityInfo({"CertificateAuthroty", {"SSL_add_file_cert_subjects_to_stack", "SSL_set_client_CA_list"}, {}, {"sk_X509_NAME_new_null_wrapper"}, {}});
        list.file.items.push_back("File 1");
        list.apply(reinterpret_cast<SSL*>(0x08));
    };
    ASSERT_NO_THROW(
        MockActionThrowDetext detect;action()
    );
}

TEST(ConnectionSSocketUtilTest, ClientCAListInfoAddClientDirSSL)
{
    MockDefaultThorsSocket      defaultMockedFunctions;
    ClientCAListInfo            list;

    auto action = [&](){
        MockActionAddObject         checksetCertifcateAuthorityInfo({"CertificateAuthroty", {"SSL_add_dir_cert_subjects_to_stack", "SSL_set_client_CA_list"}, {}, {"sk_X509_NAME_new_null_wrapper"}, {}});
        list.dir.items.push_back("File 1");
        list.apply(reinterpret_cast<SSL*>(0x08));
    };
    ASSERT_NO_THROW(
        MockActionThrowDetext detect;action()
    );
}

TEST(ConnectionSSocketUtilTest, ClientCAListInfoAddClientStoreSSL)
{
    MockDefaultThorsSocket      defaultMockedFunctions;
    ClientCAListInfo            list;

    auto action = [&](){
        MockActionAddObject         checksetCertifcateAuthorityInfo({"CertificateAuthroty", {"SSL_add_store_cert_subjects_to_stack", "SSL_set_client_CA_list"}, {}, {"sk_X509_NAME_new_null_wrapper"}, {}});
        list.store.items.push_back("File 1");
        list.apply(reinterpret_cast<SSL*>(0x08));
    };
    ASSERT_NO_THROW(
        MockActionThrowDetext detect;action()
    );
}

TEST(ConnectionSSocketUtilTest, ClientCAListInfoValidateClientFailSSL)
{
    MockDefaultThorsSocket      defaultMockedFunctions;
    ClientCAListInfo            list;

    auto action = [&](){
        MockActionAddObject         checksetCertifcateAuthorityInfo({"CertificateAuthroty", {"SSL_set_verify"}, {}, {}, {}});
        list.verifyClientCA = true;
        list.apply(reinterpret_cast<SSL*>(0x08));
    };
    ASSERT_NO_THROW(
        MockActionThrowDetext detect;action()
    );
}

TEST(ConnectionSSocketUtilTest, ClientCAListInfoAddClientFileFailSSL)
{
    MockDefaultThorsSocket      defaultMockedFunctions;
    MOCK_SYS(SSL_add_file_cert_subjects_to_stack,   [](STACK_OF(X509_NAME)*, char const*)   {return 0;});
    ClientCAListInfo            list;

    auto action = [&](){
        MockActionAddObject         checksetCertifcateAuthorityInfo({"CertificateAuthroty", {"SSL_add_file_cert_subjects_to_stack"}, {}, {"sk_X509_NAME_new_null_wrapper", "sk_X509_NAME_pop_free_wrapper"}, {}}, {"ERR_get_error"});
        list.file.items.push_back("File 1");
        list.apply(reinterpret_cast<SSL*>(0x08));
    };
    ASSERT_THROW(
        MockActionThrowDetext detect;action(),
        std::runtime_error
    );
}

TEST(ConnectionSSocketUtilTest, ClientCAListInfoAddClientDirFailSSL)
{
    MockDefaultThorsSocket      defaultMockedFunctions;
    MOCK_SYS(SSL_add_dir_cert_subjects_to_stack,    [](STACK_OF(X509_NAME)*, char const*)   {return 0;});
    ClientCAListInfo            list;

    auto action = [&](){
        MockActionAddObject         checksetCertifcateAuthorityInfo({"CertificateAuthroty", {"SSL_add_dir_cert_subjects_to_stack"}, {}, {"sk_X509_NAME_new_null_wrapper", "sk_X509_NAME_pop_free_wrapper"}, {}}, {"ERR_get_error"});
        list.dir.items.push_back("File 1");
        list.apply(reinterpret_cast<SSL*>(0x08));
    };
    ASSERT_THROW(
        MockActionThrowDetext detect;action(),
        std::runtime_error
    );
}

TEST(ConnectionSSocketUtilTest, ClientCAListInfoAddClientStoreFailSSL)
{
    MockDefaultThorsSocket      defaultMockedFunctions;
    MOCK_SYS(SSL_add_store_cert_subjects_to_stack,  [](STACK_OF(X509_NAME)*, char const*)   {return 0;});
    ClientCAListInfo            list;

    auto action = [&](){
        MockActionAddObject         checksetCertifcateAuthorityInfo({"CertificateAuthroty", {"SSL_add_store_cert_subjects_to_stack"}, {}, {"sk_X509_NAME_new_null_wrapper", "sk_X509_NAME_pop_free_wrapper"}, {}}, {"ERR_get_error"});
        list.store.items.push_back("File 1");
        list.apply(reinterpret_cast<SSL*>(0x08));
    };
    ASSERT_THROW(
        MockActionThrowDetext detect;action(),
        std::runtime_error
    );
}

