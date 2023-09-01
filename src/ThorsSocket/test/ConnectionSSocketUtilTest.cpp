#include <gtest/gtest.h>
#include "ConnectionSSocketUtil.h"

using ThorsAnvil::ThorsSocket::ConnectionType::Protocol;
using ThorsAnvil::ThorsSocket::ConnectionType::ProtocolInfo;
using ThorsAnvil::ThorsSocket::ConnectionType::CipherInfo;
using ThorsAnvil::ThorsSocket::ConnectionType::CertificateInfo;
using ThorsAnvil::ThorsSocket::ConnectionType::CertifcateAuthorityInfo;
using ThorsAnvil::ThorsSocket::ConnectionType::ClientCAListInfo;

TEST(ConnectionSSocketUtilTest, DefaultBuildProtocolInfo)
{
    ProtocolInfo    protocol;
}

TEST(ConnectionSSocketUtilTest, BuildProtocolInfo)
{
    ProtocolInfo    protocol(Protocol::TLS_1_0, Protocol::TLS_1_1);
}

TEST(ConnectionSSocketUtilTest, ProtocolInfoSetCTX)
{
    int count =  0;
    int control[] = {0, 0};
    int setting[] = {0, 0};
    MOCK_SYS(SSL_CTX_ctrl,  [&](SSL_CTX*, int v, long m, void*)   {control[count]= v;setting[count] = m;++count;return 1;});

    ProtocolInfo    protocol(Protocol::TLS_1_0, Protocol::TLS_1_1);
    protocol.setProtocolInfo(reinterpret_cast<SSL_CTX*>(0x08));

    ASSERT_EQ(count, 2);
    ASSERT_EQ(control[0], SSL_CTRL_SET_MIN_PROTO_VERSION);
    ASSERT_EQ(setting[0], TLS1_VERSION);

    ASSERT_EQ(control[1], SSL_CTRL_SET_MAX_PROTO_VERSION);
    ASSERT_EQ(setting[1], TLS1_1_VERSION);
}

TEST(ConnectionSSocketUtilTest, ProtocolInfoSetSSL)
{
    int count =  0;
    int control[] = {0, 0};
    int setting[] = {0, 0};
    MOCK_SYS(SSL_ctrl,  [&](SSL*, int v, long m, void*)   {control[count]= v;setting[count] = m;++count;return 1;});

    ProtocolInfo    protocol(Protocol::TLS_1_2, Protocol::TLS_1_3);
    protocol.setProtocolInfo(reinterpret_cast<SSL*>(0x08));

    ASSERT_EQ(count, 2);
    ASSERT_EQ(control[0], SSL_CTRL_SET_MIN_PROTO_VERSION);
    ASSERT_EQ(setting[0], TLS1_2_VERSION);

    ASSERT_EQ(control[1], SSL_CTRL_SET_MAX_PROTO_VERSION);
    ASSERT_EQ(setting[1], TLS1_3_VERSION);
}

TEST(ConnectionSSocketUtilTest, ProtocolInfoSetCTXMinFailed)
{
    MOCK_SYS(SSL_ctrl,  [&](SSL*, int v, long m, void*)   {static int count = 0;++count;return count == 1 ? 1 : 0;});

    auto action = [](){
        ProtocolInfo    protocol(Protocol::TLS_1_2, Protocol::TLS_1_3);
        protocol.setProtocolInfo(reinterpret_cast<SSL*>(0x08));
    };

    ASSERT_THROW(
        action(),
        std::runtime_error
    );
}

TEST(ConnectionSSocketUtilTest, ProtocolInfoSetCTXMaxFailed)
{
    MOCK_SYS(SSL_ctrl,  [&](SSL*, int v, long m, void*)   {static int count = 0;++count;return count == 2 ? 1 : 0;});

    auto action = [](){
        ProtocolInfo    protocol(Protocol::TLS_1_2, Protocol::TLS_1_3);
        protocol.setProtocolInfo(reinterpret_cast<SSL*>(0x08));
    };

    ASSERT_THROW(
        action(),
        std::runtime_error
    );
}

TEST(ConnectionSSocketUtilTest, CipherInfoConstruct)
{
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
}

TEST(ConnectionSSocketUtilTest, CipherInfoConstructWithAlternativeValues)
{
    CipherInfo      cipherInfo{"Value1", "Value2"};;
    ASSERT_EQ(cipherInfo.cipherList, "Value1");
    ASSERT_EQ(cipherInfo.cipherSuite,"Value2");
}

TEST(ConnectionSSocketUtilTest, CipherInfoSetCTX)
{
    std::string const input1 = "List1";
    std::string const input2 = "Suite2";
    char const*  list = nullptr;
    char const*  suite = nullptr;
    MOCK_SYS(SSL_CTX_set_cipher_list,   [&](SSL_CTX*, char const* val)    {list = val;return 1;});
    MOCK_SYS(SSL_CTX_set_ciphersuites,  [&](SSL_CTX*, char const* val)    {suite = val;return 1;});

    CipherInfo      cipherInfo{input1, input2};
    cipherInfo.setCipherInfo(reinterpret_cast<SSL_CTX*>(0x08));

    ASSERT_NE(list, nullptr);
    ASSERT_NE(suite, nullptr);

    ASSERT_EQ(input1, list);
    ASSERT_EQ(input2, suite);
}

TEST(ConnectionSSocketUtilTest, CipherInfoSetSSL)
{
    std::string const input1 = "List1";
    std::string const input2 = "Suite2";
    char const*  list = nullptr;
    char const*  suite = nullptr;
    MOCK_SYS(SSL_set_cipher_list,   [&](SSL*, char const* val)    {list = val;return 1;});
    MOCK_SYS(SSL_set_ciphersuites,  [&](SSL*, char const* val)    {suite = val;return 1;});

    CipherInfo      cipherInfo{input1, input2};
    cipherInfo.setCipherInfo(reinterpret_cast<SSL*>(0x08));

    ASSERT_NE(list, nullptr);
    ASSERT_NE(suite, nullptr);

    ASSERT_EQ(input1, list);
    ASSERT_EQ(input2, suite);
}

TEST(ConnectionSSocketUtilTest, CipherInfoSetCTXListFail)
{
    MOCK_SYS(SSL_CTX_set_cipher_list,   [&](SSL_CTX*, char const* val)    {return 0;});
    MOCK_SYS(SSL_CTX_set_ciphersuites,  [&](SSL_CTX*, char const* val)    {return 1;});

    auto action = []() {
        std::string const input1 = "List1";
        std::string const input2 = "Suite2";
        CipherInfo      cipherInfo{input1, input2};
        cipherInfo.setCipherInfo(reinterpret_cast<SSL_CTX*>(0x08));
    };

    ASSERT_THROW(
        action(),
        std::runtime_error
    );
}

TEST(ConnectionSSocketUtilTest, CipherInfoSetCTXSuiteFail)
{
    MOCK_SYS(SSL_CTX_set_cipher_list,   [&](SSL_CTX*, char const* val)    {return 1;});
    MOCK_SYS(SSL_CTX_set_ciphersuites,  [&](SSL_CTX*, char const* val)    {return 0;});

    auto action = []() {
        std::string const input1 = "List1";
        std::string const input2 = "Suite2";
        CipherInfo      cipherInfo{input1, input2};
        cipherInfo.setCipherInfo(reinterpret_cast<SSL_CTX*>(0x08));
    };

    ASSERT_THROW(
        action(),
        std::runtime_error
    );
}

TEST(ConnectionSSocketUtilTest, CipherInfoSetSSLListFail)
{
    MOCK_SYS(SSL_set_cipher_list,   [&](SSL*, char const* val)    {return 0;});
    MOCK_SYS(SSL_set_ciphersuites,  [&](SSL*, char const* val)    {return 1;});

    auto action = []() {
        std::string const input1 = "List1";
        std::string const input2 = "Suite2";
        CipherInfo      cipherInfo{input1, input2};
        cipherInfo.setCipherInfo(reinterpret_cast<SSL*>(0x08));
    };

    ASSERT_THROW(
        action(),
        std::runtime_error
    );
}

TEST(ConnectionSSocketUtilTest, CipherInfoSetSSLSuiteFail)
{
    MOCK_SYS(SSL_set_cipher_list,   [&](SSL*, char const* val)    {return 1;});
    MOCK_SYS(SSL_set_ciphersuites,  [&](SSL*, char const* val)    {return 0;});

    auto action = []() {
        std::string const input1 = "List1";
        std::string const input2 = "Suite2";
        CipherInfo      cipherInfo{input1, input2};
        cipherInfo.setCipherInfo(reinterpret_cast<SSL*>(0x08));
    };

    ASSERT_THROW(
        action(),
        std::runtime_error
    );
}

TEST(ConnectionSSocketUtilTest, CertificateInfoDefaultConstruct)
{
    CertificateInfo     ca;
}

TEST(ConnectionSSocketUtilTest, CertificateInfoConstruct)
{
    CertificateInfo     ca("File1", "File2", [](int){return "password";});;
}


TEST(ConnectionSSocketUtilTest, CertificateInfoDefaultConstructNoAction)
{
    int calledCount = 0;
    typedef int(*CB)(char*, int, int, void*);

    MOCK_SYS(SSL_CTX_set_default_passwd_cb,             [&](SSL_CTX*, CB)                {++calledCount;return 1;});
    MOCK_SYS(SSL_CTX_set_default_passwd_cb_userdata,    [&](SSL_CTX*, void*)             {++calledCount;return 1;});
    MOCK_SYS(SSL_CTX_use_certificate_file,              [&](SSL_CTX*, char const*, int)  {++calledCount;return 1;});
    MOCK_SYS(SSL_CTX_use_PrivateKey_file,               [&](SSL_CTX*, char const*, int)  {++calledCount;return 1;});
    MOCK_SYS(SSL_CTX_check_private_key,                 [&](SSL_CTX const*)              {++calledCount;return 1;});

    CertificateInfo     ca;
    ca.setCertificateInfo(reinterpret_cast<SSL_CTX*>(0x08));

    ASSERT_EQ(calledCount, 0);
}

TEST(ConnectionSSocketUtilTest, CertificateInfoActionCTXDone)
{
    int passwdFunCalled     = 0;
    int passwdDataCalled    = 0;
    int certificateCalled   = 0;
    int keyCalled           = 0;
    int checkKeyCalled      = 0;
    std::string cerFile;
    std::string keyFile;
    typedef int(*CB)(char*, int, int, void*);

    MOCK_SYS(SSL_CTX_set_default_passwd_cb,             [&](SSL_CTX*, CB)                   {++passwdFunCalled;return 1;});
    MOCK_SYS(SSL_CTX_set_default_passwd_cb_userdata,    [&](SSL_CTX*, void*)                {++passwdDataCalled;return 1;});
    MOCK_SYS(SSL_CTX_use_certificate_file,              [&](SSL_CTX*, char const* v, int)   {cerFile = v;++certificateCalled;return 1;});
    MOCK_SYS(SSL_CTX_use_PrivateKey_file,               [&](SSL_CTX*, char const* v, int)   {keyFile = v;++keyCalled;return 1;});
    MOCK_SYS(SSL_CTX_check_private_key,                 [&](SSL_CTX const*)                 {++checkKeyCalled;return 1;});

    CertificateInfo     ca("File1", "File2", [](int){return "password";});
    ca.setCertificateInfo(reinterpret_cast<SSL_CTX*>(0x08));

    ASSERT_EQ(passwdFunCalled, 1);
    ASSERT_EQ(passwdDataCalled, 1);
    ASSERT_EQ(certificateCalled, 1);
    ASSERT_EQ(keyCalled, 1);
    ASSERT_EQ(checkKeyCalled, 1);
    ASSERT_EQ(cerFile, "File1");
    ASSERT_EQ(keyFile, "File2");
}

TEST(ConnectionSSocketUtilTest, CertificateInfoActionSSLDone)
{
    int passwdFunCalled     = 0;
    int passwdDataCalled    = 0;
    int certificateCalled   = 0;
    int keyCalled           = 0;
    int checkKeyCalled      = 0;
    std::string cerFile;
    std::string keyFile;
    typedef int(*CB)(char*, int, int, void*);

    MOCK_SYS(SSL_set_default_passwd_cb,             [&](SSL*, CB)                   {++passwdFunCalled;return 1;});
    MOCK_SYS(SSL_set_default_passwd_cb_userdata,    [&](SSL*, void*)                {++passwdDataCalled;return 1;});
    MOCK_SYS(SSL_use_certificate_file,              [&](SSL*, char const* v, int)   {cerFile = v;++certificateCalled;return 1;});
    MOCK_SYS(SSL_use_PrivateKey_file,               [&](SSL*, char const* v, int)   {keyFile = v;++keyCalled;return 1;});
    MOCK_SYS(SSL_check_private_key,                 [&](SSL const*)                 {++checkKeyCalled;return 1;});

    CertificateInfo     ca("File1", "File2", [](int){return "password";});
    ca.setCertificateInfo(reinterpret_cast<SSL*>(0x08));

    ASSERT_EQ(passwdFunCalled, 1);
    ASSERT_EQ(passwdDataCalled, 1);
    ASSERT_EQ(certificateCalled, 1);
    ASSERT_EQ(keyCalled, 1);
    ASSERT_EQ(checkKeyCalled, 1);
    ASSERT_EQ(cerFile, "File1");
    ASSERT_EQ(keyFile, "File2");
}

TEST(ConnectionSSocketUtilTest, CertificateInfoConstructionInvalidCert)
{
    auto action = [](){
        CertificateInfo     ca("File1", "");
    };
    ASSERT_THROW(
        action(),
        std::runtime_error
    );
}

TEST(ConnectionSSocketUtilTest, CertificateInfoConstructionInvalidKey)
{
    auto action = [](){
        CertificateInfo     ca("", "File2");
    };
    ASSERT_THROW(
        action(),
        std::runtime_error
    );
}

TEST(ConnectionSSocketUtilTest, CertificateInfoActionCTXInvalidCert)
{
    int passwdFunCalled     = 0;
    int passwdDataCalled    = 0;
    int certificateCalled   = 0;
    int keyCalled           = 0;
    int checkKeyCalled      = 0;
    std::string cerFile;
    std::string keyFile;
    typedef int(*CB)(char*, int, int, void*);

    MOCK_SYS(SSL_CTX_set_default_passwd_cb,             [&](SSL_CTX*, CB)                   {++passwdFunCalled;return 1;});
    MOCK_SYS(SSL_CTX_set_default_passwd_cb_userdata,    [&](SSL_CTX*, void*)                {++passwdDataCalled;return 1;});
    MOCK_SYS(SSL_CTX_use_certificate_file,              [&](SSL_CTX*, char const* v, int)   {cerFile = v;++certificateCalled;return 0;});
    MOCK_SYS(SSL_CTX_use_PrivateKey_file,               [&](SSL_CTX*, char const* v, int)   {keyFile = v;++keyCalled;return 1;});
    MOCK_SYS(SSL_CTX_check_private_key,                 [&](SSL_CTX const*)                 {++checkKeyCalled;return 1;});

    auto action = [](){
        CertificateInfo     ca("File1", "File2", [](int){return "password";});
        ca.setCertificateInfo(reinterpret_cast<SSL_CTX*>(0x08));
    };
    ASSERT_THROW(
        action(),
        std::runtime_error
    );

    ASSERT_EQ(passwdFunCalled, 1);
    ASSERT_EQ(passwdDataCalled, 1);
    ASSERT_EQ(certificateCalled, 1);
    ASSERT_EQ(keyCalled, 0);
    ASSERT_EQ(checkKeyCalled, 0);
    ASSERT_EQ(cerFile, "File1");
    ASSERT_EQ(keyFile, "");
}

TEST(ConnectionSSocketUtilTest, CertificateInfoActionCTXInvalidKey)
{
    int passwdFunCalled     = 0;
    int passwdDataCalled    = 0;
    int certificateCalled   = 0;
    int keyCalled           = 0;
    int checkKeyCalled      = 0;
    std::string cerFile;
    std::string keyFile;
    typedef int(*CB)(char*, int, int, void*);

    MOCK_SYS(SSL_CTX_set_default_passwd_cb,             [&](SSL_CTX*, CB)                   {++passwdFunCalled;return 1;});
    MOCK_SYS(SSL_CTX_set_default_passwd_cb_userdata,    [&](SSL_CTX*, void*)                {++passwdDataCalled;return 1;});
    MOCK_SYS(SSL_CTX_use_certificate_file,              [&](SSL_CTX*, char const* v, int)   {cerFile = v;++certificateCalled;return 1;});
    MOCK_SYS(SSL_CTX_use_PrivateKey_file,               [&](SSL_CTX*, char const* v, int)   {keyFile = v;++keyCalled;return 0;});
    MOCK_SYS(SSL_CTX_check_private_key,                 [&](SSL_CTX const*)                 {++checkKeyCalled;return 1;});

    auto action = [](){
        CertificateInfo     ca("File1", "File2", [](int){return "password";});
        ca.setCertificateInfo(reinterpret_cast<SSL_CTX*>(0x08));
    };
    ASSERT_THROW(
        action(),
        std::runtime_error
    );

    ASSERT_EQ(passwdFunCalled, 1);
    ASSERT_EQ(passwdDataCalled, 1);
    ASSERT_EQ(certificateCalled, 1);
    ASSERT_EQ(keyCalled, 1);
    ASSERT_EQ(checkKeyCalled, 0);
    ASSERT_EQ(cerFile, "File1");
    ASSERT_EQ(keyFile, "File2");
}

TEST(ConnectionSSocketUtilTest, CertificateInfoActionCTXInvalidCheck)
{
    int passwdFunCalled     = 0;
    int passwdDataCalled    = 0;
    int certificateCalled   = 0;
    int keyCalled           = 0;
    int checkKeyCalled      = 0;
    std::string cerFile;
    std::string keyFile;
    typedef int(*CB)(char*, int, int, void*);

    MOCK_SYS(SSL_CTX_set_default_passwd_cb,             [&](SSL_CTX*, CB)                   {++passwdFunCalled;return 1;});
    MOCK_SYS(SSL_CTX_set_default_passwd_cb_userdata,    [&](SSL_CTX*, void*)                {++passwdDataCalled;return 1;});
    MOCK_SYS(SSL_CTX_use_certificate_file,              [&](SSL_CTX*, char const* v, int)   {cerFile = v;++certificateCalled;return 1;});
    MOCK_SYS(SSL_CTX_use_PrivateKey_file,               [&](SSL_CTX*, char const* v, int)   {keyFile = v;++keyCalled;return 1;});
    MOCK_SYS(SSL_CTX_check_private_key,                 [&](SSL_CTX const*)                 {++checkKeyCalled;return 0;});

    auto action = [](){
        CertificateInfo     ca("File1", "File2", [](int){return "password";});
        ca.setCertificateInfo(reinterpret_cast<SSL_CTX*>(0x08));
    };
    ASSERT_THROW(
        action(),
        std::runtime_error
    );

    ASSERT_EQ(passwdFunCalled, 1);
    ASSERT_EQ(passwdDataCalled, 1);
    ASSERT_EQ(certificateCalled, 1);
    ASSERT_EQ(keyCalled, 1);
    ASSERT_EQ(checkKeyCalled, 1);
    ASSERT_EQ(cerFile, "File1");
    ASSERT_EQ(keyFile, "File2");
}

TEST(ConnectionSSocketUtilTest, CertificateInfoActionSSLInvalidCert)
{
    int passwdFunCalled     = 0;
    int passwdDataCalled    = 0;
    int certificateCalled   = 0;
    int keyCalled           = 0;
    int checkKeyCalled      = 0;
    std::string cerFile;
    std::string keyFile;
    typedef int(*CB)(char*, int, int, void*);

    MOCK_SYS(SSL_set_default_passwd_cb,             [&](SSL*, CB)                   {++passwdFunCalled;return 1;});
    MOCK_SYS(SSL_set_default_passwd_cb_userdata,    [&](SSL*, void*)                {++passwdDataCalled;return 1;});
    MOCK_SYS(SSL_use_certificate_file,              [&](SSL*, char const* v, int)   {cerFile = v;++certificateCalled;return 0;});
    MOCK_SYS(SSL_use_PrivateKey_file,               [&](SSL*, char const* v, int)   {keyFile = v;++keyCalled;return 1;});
    MOCK_SYS(SSL_check_private_key,                 [&](SSL const*)                 {++checkKeyCalled;return 1;});

    auto action = [](){
        CertificateInfo     ca("File1", "File2", [](int){return "password";});
        ca.setCertificateInfo(reinterpret_cast<SSL*>(0x08));
    };
    ASSERT_THROW(
        action(),
        std::runtime_error
    );

    ASSERT_EQ(passwdFunCalled, 1);
    ASSERT_EQ(passwdDataCalled, 1);
    ASSERT_EQ(certificateCalled, 1);
    ASSERT_EQ(keyCalled, 0);
    ASSERT_EQ(checkKeyCalled, 0);
    ASSERT_EQ(cerFile, "File1");
    ASSERT_EQ(keyFile, "");
}

TEST(ConnectionSSocketUtilTest, CertificateInfoActionSSLInvalidKey)
{
    int passwdFunCalled     = 0;
    int passwdDataCalled    = 0;
    int certificateCalled   = 0;
    int keyCalled           = 0;
    int checkKeyCalled      = 0;
    std::string cerFile;
    std::string keyFile;
    typedef int(*CB)(char*, int, int, void*);

    MOCK_SYS(SSL_set_default_passwd_cb,             [&](SSL*, CB)                   {++passwdFunCalled;return 1;});
    MOCK_SYS(SSL_set_default_passwd_cb_userdata,    [&](SSL*, void*)                {++passwdDataCalled;return 1;});
    MOCK_SYS(SSL_use_certificate_file,              [&](SSL*, char const* v, int)   {cerFile = v;++certificateCalled;return 1;});
    MOCK_SYS(SSL_use_PrivateKey_file,               [&](SSL*, char const* v, int)   {keyFile = v;++keyCalled;return 0;});
    MOCK_SYS(SSL_check_private_key,                 [&](SSL const*)                 {++checkKeyCalled;return 1;});

    auto action = [](){
        CertificateInfo     ca("File1", "File2", [](int){return "password";});
        ca.setCertificateInfo(reinterpret_cast<SSL*>(0x08));
    };
    ASSERT_THROW(
        action(),
        std::runtime_error
    );

    ASSERT_EQ(passwdFunCalled, 1);
    ASSERT_EQ(passwdDataCalled, 1);
    ASSERT_EQ(certificateCalled, 1);
    ASSERT_EQ(keyCalled, 1);
    ASSERT_EQ(checkKeyCalled, 0);
    ASSERT_EQ(cerFile, "File1");
    ASSERT_EQ(keyFile, "File2");
}

TEST(ConnectionSSocketUtilTest, CertificateInfoActionSSLInvalidCheck)
{
    int passwdFunCalled     = 0;
    int passwdDataCalled    = 0;
    int certificateCalled   = 0;
    int keyCalled           = 0;
    int checkKeyCalled      = 0;
    std::string cerFile;
    std::string keyFile;
    typedef int(*CB)(char*, int, int, void*);

    MOCK_SYS(SSL_set_default_passwd_cb,             [&](SSL*, CB)                   {++passwdFunCalled;return 1;});
    MOCK_SYS(SSL_set_default_passwd_cb_userdata,    [&](SSL*, void*)                {++passwdDataCalled;return 1;});
    MOCK_SYS(SSL_use_certificate_file,              [&](SSL*, char const* v, int)   {cerFile = v;++certificateCalled;return 1;});
    MOCK_SYS(SSL_use_PrivateKey_file,               [&](SSL*, char const* v, int)   {keyFile = v;++keyCalled;return 1;});
    MOCK_SYS(SSL_check_private_key,                 [&](SSL const*)                 {++checkKeyCalled;return 0;});

    auto action = [](){
        CertificateInfo     ca("File1", "File2", [](int){return "password";});
        ca.setCertificateInfo(reinterpret_cast<SSL*>(0x08));
    };
    ASSERT_THROW(
        action(),
        std::runtime_error
    );

    ASSERT_EQ(passwdFunCalled, 1);
    ASSERT_EQ(passwdDataCalled, 1);
    ASSERT_EQ(certificateCalled, 1);
    ASSERT_EQ(keyCalled, 1);
    ASSERT_EQ(checkKeyCalled, 1);
    ASSERT_EQ(cerFile, "File1");
    ASSERT_EQ(keyFile, "File2");
}

TEST(ConnectionSSocketUtilTest, CertifcateAuthorityInfoDefaultConstruct)
{
    int countCalled = 0;

    MOCK_SYS(SSL_CTX_set_default_verify_file,   [&](SSL_CTX*)               {++countCalled;return 1;});
    MOCK_SYS(SSL_CTX_set_default_verify_dir,    [&](SSL_CTX*)               {++countCalled;return 1;});
    MOCK_SYS(SSL_CTX_set_default_verify_store,  [&](SSL_CTX*)               {++countCalled;return 1;});
    MOCK_SYS(SSL_CTX_load_verify_file,          [&](SSL_CTX*, char const*)  {++countCalled;return 1;});
    MOCK_SYS(SSL_CTX_load_verify_dir,           [&](SSL_CTX*, char const*)  {++countCalled;return 1;});
    MOCK_SYS(SSL_CTX_load_verify_store,         [&](SSL_CTX*, char const*)  {++countCalled;return 1;});

    CertifcateAuthorityInfo     ca;
    ca.setCertifcateAuthorityInfo(reinterpret_cast<SSL_CTX*>(0x08));

    ASSERT_EQ(countCalled, 0);
}

TEST(ConnectionSSocketUtilTest, CertifcateAuthoritySetDefaultFile)
{
    int countCalled = 0;
    int expectedCalled = 0;

    MOCK_SYS(SSL_CTX_set_default_verify_file,   [&](SSL_CTX*)               {++expectedCalled;return 1;});
    MOCK_SYS(SSL_CTX_set_default_verify_dir,    [&](SSL_CTX*)               {++countCalled;return 1;});
    MOCK_SYS(SSL_CTX_set_default_verify_store,  [&](SSL_CTX*)               {++countCalled;return 1;});
    MOCK_SYS(SSL_CTX_load_verify_file,          [&](SSL_CTX*, char const*)  {++countCalled;return 1;});
    MOCK_SYS(SSL_CTX_load_verify_dir,           [&](SSL_CTX*, char const*)  {++countCalled;return 1;});
    MOCK_SYS(SSL_CTX_load_verify_store,         [&](SSL_CTX*, char const*)  {++countCalled;return 1;});

    CertifcateAuthorityInfo     ca;
    ca.file.loadDefault = true;
    ca.setCertifcateAuthorityInfo(reinterpret_cast<SSL_CTX*>(0x08));

    ASSERT_EQ(countCalled, 0);
    ASSERT_EQ(expectedCalled, 1);
}


TEST(ConnectionSSocketUtilTest, CertifcateAuthoritySetDefaultDir)
{
    int countCalled = 0;
    int expectedCalled = 0;

    MOCK_SYS(SSL_CTX_set_default_verify_file,   [&](SSL_CTX*)               {++countCalled;return 1;});
    MOCK_SYS(SSL_CTX_set_default_verify_dir,    [&](SSL_CTX*)               {++expectedCalled;return 1;});
    MOCK_SYS(SSL_CTX_set_default_verify_store,  [&](SSL_CTX*)               {++countCalled;return 1;});
    MOCK_SYS(SSL_CTX_load_verify_file,          [&](SSL_CTX*, char const*)  {++countCalled;return 1;});
    MOCK_SYS(SSL_CTX_load_verify_dir,           [&](SSL_CTX*, char const*)  {++countCalled;return 1;});
    MOCK_SYS(SSL_CTX_load_verify_store,         [&](SSL_CTX*, char const*)  {++countCalled;return 1;});

    CertifcateAuthorityInfo     ca;
    ca.dir.loadDefault = true;
    ca.setCertifcateAuthorityInfo(reinterpret_cast<SSL_CTX*>(0x08));

    ASSERT_EQ(countCalled, 0);
    ASSERT_EQ(expectedCalled, 1);
}

TEST(ConnectionSSocketUtilTest, CertifcateAuthoritySetDefaultStore)
{
    int countCalled = 0;
    int expectedCalled = 0;

    MOCK_SYS(SSL_CTX_set_default_verify_file,   [&](SSL_CTX*)               {++countCalled;return 1;});
    MOCK_SYS(SSL_CTX_set_default_verify_dir,    [&](SSL_CTX*)               {++countCalled;return 1;});
    MOCK_SYS(SSL_CTX_set_default_verify_store,  [&](SSL_CTX*)               {++expectedCalled;return 1;});
    MOCK_SYS(SSL_CTX_load_verify_file,          [&](SSL_CTX*, char const*)  {++countCalled;return 1;});
    MOCK_SYS(SSL_CTX_load_verify_dir,           [&](SSL_CTX*, char const*)  {++countCalled;return 1;});
    MOCK_SYS(SSL_CTX_load_verify_store,         [&](SSL_CTX*, char const*)  {++countCalled;return 1;});

    CertifcateAuthorityInfo     ca;
    ca.store.loadDefault = true;
    ca.setCertifcateAuthorityInfo(reinterpret_cast<SSL_CTX*>(0x08));

    ASSERT_EQ(countCalled, 0);
    ASSERT_EQ(expectedCalled, 1);
}

TEST(ConnectionSSocketUtilTest, CertifcateAuthorityAddFile)
{
    int countCalled = 0;
    int expectedCalled = 0;
    std::string expectedItem;

    MOCK_SYS(SSL_CTX_set_default_verify_file,   [&](SSL_CTX*)               {++countCalled;return 1;});
    MOCK_SYS(SSL_CTX_set_default_verify_dir,    [&](SSL_CTX*)               {++countCalled;return 1;});
    MOCK_SYS(SSL_CTX_set_default_verify_store,  [&](SSL_CTX*)               {++countCalled;return 1;});
    MOCK_SYS(SSL_CTX_load_verify_file,          [&](SSL_CTX*, char const* v){expectedItem=v;++expectedCalled;return 1;});
    MOCK_SYS(SSL_CTX_load_verify_dir,           [&](SSL_CTX*, char const*)  {++countCalled;return 1;});
    MOCK_SYS(SSL_CTX_load_verify_store,         [&](SSL_CTX*, char const*)  {++countCalled;return 1;});

    CertifcateAuthorityInfo     ca;
    ca.file.items.push_back("Item 1");
    ca.setCertifcateAuthorityInfo(reinterpret_cast<SSL_CTX*>(0x08));

    ASSERT_EQ(countCalled, 0);
    ASSERT_EQ(expectedCalled, 1);
    ASSERT_EQ(expectedItem, "Item 1");
}

TEST(ConnectionSSocketUtilTest, CertifcateAuthorityAddDir)
{
    int countCalled = 0;
    int expectedCalled = 0;
    std::string expectedItem;

    MOCK_SYS(SSL_CTX_set_default_verify_file,   [&](SSL_CTX*)               {++countCalled;return 1;});
    MOCK_SYS(SSL_CTX_set_default_verify_dir,    [&](SSL_CTX*)               {++countCalled;return 1;});
    MOCK_SYS(SSL_CTX_set_default_verify_store,  [&](SSL_CTX*)               {++countCalled;return 1;});
    MOCK_SYS(SSL_CTX_load_verify_file,          [&](SSL_CTX*, char const*)  {++countCalled;return 1;});
    MOCK_SYS(SSL_CTX_load_verify_dir,           [&](SSL_CTX*, char const* v){expectedItem=v;++expectedCalled;return 1;});
    MOCK_SYS(SSL_CTX_load_verify_store,         [&](SSL_CTX*, char const*)  {++countCalled;return 1;});

    CertifcateAuthorityInfo     ca;
    ca.dir.items.push_back("Item 1");
    ca.setCertifcateAuthorityInfo(reinterpret_cast<SSL_CTX*>(0x08));

    ASSERT_EQ(countCalled, 0);
    ASSERT_EQ(expectedCalled, 1);
    ASSERT_EQ(expectedItem, "Item 1");
}

TEST(ConnectionSSocketUtilTest, CertifcateAuthorityAddStore)
{
    int countCalled = 0;
    int expectedCalled = 0;
    std::string expectedItem;

    MOCK_SYS(SSL_CTX_set_default_verify_file,   [&](SSL_CTX*)               {++countCalled;return 1;});
    MOCK_SYS(SSL_CTX_set_default_verify_dir,    [&](SSL_CTX*)               {++countCalled;return 1;});
    MOCK_SYS(SSL_CTX_set_default_verify_store,  [&](SSL_CTX*)               {++countCalled;return 1;});
    MOCK_SYS(SSL_CTX_load_verify_file,          [&](SSL_CTX*, char const*)  {++countCalled;return 1;});
    MOCK_SYS(SSL_CTX_load_verify_dir,           [&](SSL_CTX*, char const*)  {++countCalled;return 1;});
    MOCK_SYS(SSL_CTX_load_verify_store,         [&](SSL_CTX*, char const* v){expectedItem=v;++expectedCalled;return 1;});

    CertifcateAuthorityInfo     ca;
    ca.store.items.push_back("Item 1");
    ca.setCertifcateAuthorityInfo(reinterpret_cast<SSL_CTX*>(0x08));

    ASSERT_EQ(countCalled, 0);
    ASSERT_EQ(expectedCalled, 1);
    ASSERT_EQ(expectedItem, "Item 1");
}

TEST(ConnectionSSocketUtilTest, CertifcateAuthorityFailedDefaultFile)
{
    int countCalled = 0;
    int expectedCalled = 0;

    MOCK_SYS(SSL_CTX_set_default_verify_file,   [&](SSL_CTX*)               {++expectedCalled;return 0;});
    MOCK_SYS(SSL_CTX_set_default_verify_dir,    [&](SSL_CTX*)               {++countCalled;return 1;});
    MOCK_SYS(SSL_CTX_set_default_verify_store,  [&](SSL_CTX*)               {++countCalled;return 1;});
    MOCK_SYS(SSL_CTX_load_verify_file,          [&](SSL_CTX*, char const*)  {++countCalled;return 1;});
    MOCK_SYS(SSL_CTX_load_verify_dir,           [&](SSL_CTX*, char const*)  {++countCalled;return 1;});
    MOCK_SYS(SSL_CTX_load_verify_store,         [&](SSL_CTX*, char const*)  {++countCalled;return 1;});

    auto action = [](){
        CertifcateAuthorityInfo     ca;
        ca.file.loadDefault = true;
        ca.setCertifcateAuthorityInfo(reinterpret_cast<SSL_CTX*>(0x08));
    };
    ASSERT_THROW(
        action(),
        std::runtime_error
    );

    ASSERT_EQ(countCalled, 0);
    ASSERT_EQ(expectedCalled, 1);
}
TEST(ConnectionSSocketUtilTest, CertifcateAuthorityFailedDefaultDir)
{
    int countCalled = 0;
    int expectedCalled = 0;

    MOCK_SYS(SSL_CTX_set_default_verify_file,   [&](SSL_CTX*)               {++countCalled;return 1;});
    MOCK_SYS(SSL_CTX_set_default_verify_dir,    [&](SSL_CTX*)               {++expectedCalled;return 0;});
    MOCK_SYS(SSL_CTX_set_default_verify_store,  [&](SSL_CTX*)               {++countCalled;return 1;});
    MOCK_SYS(SSL_CTX_load_verify_file,          [&](SSL_CTX*, char const*)  {++countCalled;return 1;});
    MOCK_SYS(SSL_CTX_load_verify_dir,           [&](SSL_CTX*, char const*)  {++countCalled;return 1;});
    MOCK_SYS(SSL_CTX_load_verify_store,         [&](SSL_CTX*, char const*)  {++countCalled;return 1;});

    auto action = [](){
        CertifcateAuthorityInfo     ca;
        ca.dir.loadDefault = true;
        ca.setCertifcateAuthorityInfo(reinterpret_cast<SSL_CTX*>(0x08));
    };
    ASSERT_THROW(
        action(),
        std::runtime_error
    );

    ASSERT_EQ(countCalled, 0);
    ASSERT_EQ(expectedCalled, 1);
}
TEST(ConnectionSSocketUtilTest, CertifcateAuthorityFailedDefaultStore)
{
    int countCalled = 0;
    int expectedCalled = 0;

    MOCK_SYS(SSL_CTX_set_default_verify_file,   [&](SSL_CTX*)               {++countCalled;return 1;});
    MOCK_SYS(SSL_CTX_set_default_verify_dir,    [&](SSL_CTX*)               {++countCalled;return 1;});
    MOCK_SYS(SSL_CTX_set_default_verify_store,  [&](SSL_CTX*)               {++expectedCalled;return 0;});
    MOCK_SYS(SSL_CTX_load_verify_file,          [&](SSL_CTX*, char const*)  {++countCalled;return 1;});
    MOCK_SYS(SSL_CTX_load_verify_dir,           [&](SSL_CTX*, char const*)  {++countCalled;return 1;});
    MOCK_SYS(SSL_CTX_load_verify_store,         [&](SSL_CTX*, char const*)  {++countCalled;return 1;});

    auto action = [](){
        CertifcateAuthorityInfo     ca;
        ca.store.loadDefault = true;
        ca.setCertifcateAuthorityInfo(reinterpret_cast<SSL_CTX*>(0x08));
    };
    ASSERT_THROW(
        action(),
        std::runtime_error
    );

    ASSERT_EQ(countCalled, 0);
    ASSERT_EQ(expectedCalled, 1);
}

TEST(ConnectionSSocketUtilTest, CertifcateAuthorityAddFileFail)
{
    int countCalled = 0;
    int expectedCalled = 0;
    std::string expectedItem;

    MOCK_SYS(SSL_CTX_set_default_verify_file,   [&](SSL_CTX*)               {++countCalled;return 1;});
    MOCK_SYS(SSL_CTX_set_default_verify_dir,    [&](SSL_CTX*)               {++countCalled;return 1;});
    MOCK_SYS(SSL_CTX_set_default_verify_store,  [&](SSL_CTX*)               {++countCalled;return 1;});
    MOCK_SYS(SSL_CTX_load_verify_file,          [&](SSL_CTX*, char const* v){expectedItem=v;++expectedCalled;return 0;});
    MOCK_SYS(SSL_CTX_load_verify_dir,           [&](SSL_CTX*, char const*)  {++countCalled;return 1;});
    MOCK_SYS(SSL_CTX_load_verify_store,         [&](SSL_CTX*, char const*)  {++countCalled;return 0;});

    auto action = [](){
        CertifcateAuthorityInfo     ca;
        ca.file.items.push_back("Item 1");
        ca.setCertifcateAuthorityInfo(reinterpret_cast<SSL_CTX*>(0x08));
    };
    ASSERT_THROW(
        action(),
        std::runtime_error
    );

    ASSERT_EQ(countCalled, 0);
    ASSERT_EQ(expectedCalled, 1);
    ASSERT_EQ(expectedItem, "Item 1");
}

TEST(ConnectionSSocketUtilTest, CertifcateAuthorityAddDirFail)
{
    int countCalled = 0;
    int expectedCalled = 0;
    std::string expectedItem;

    MOCK_SYS(SSL_CTX_set_default_verify_file,   [&](SSL_CTX*)               {++countCalled;return 1;});
    MOCK_SYS(SSL_CTX_set_default_verify_dir,    [&](SSL_CTX*)               {++countCalled;return 1;});
    MOCK_SYS(SSL_CTX_set_default_verify_store,  [&](SSL_CTX*)               {++countCalled;return 1;});
    MOCK_SYS(SSL_CTX_load_verify_file,          [&](SSL_CTX*, char const*)  {++countCalled;return 1;});
    MOCK_SYS(SSL_CTX_load_verify_dir,           [&](SSL_CTX*, char const* v){expectedItem=v;++expectedCalled;return 0;});
    MOCK_SYS(SSL_CTX_load_verify_store,         [&](SSL_CTX*, char const*)  {++countCalled;return 1;});

    auto action = [](){
        CertifcateAuthorityInfo     ca;
        ca.dir.items.push_back("Item 1");
        ca.setCertifcateAuthorityInfo(reinterpret_cast<SSL_CTX*>(0x08));
    };
    ASSERT_THROW(
        action(),
        std::runtime_error
    );

    ASSERT_EQ(countCalled, 0);
    ASSERT_EQ(expectedCalled, 1);
    ASSERT_EQ(expectedItem, "Item 1");
}

TEST(ConnectionSSocketUtilTest, CertifcateAuthorityAddStoreFail)
{
    int countCalled = 0;
    int expectedCalled = 0;
    std::string expectedItem;

    MOCK_SYS(SSL_CTX_set_default_verify_file,   [&](SSL_CTX*)               {++countCalled;return 1;});
    MOCK_SYS(SSL_CTX_set_default_verify_dir,    [&](SSL_CTX*)               {++countCalled;return 1;});
    MOCK_SYS(SSL_CTX_set_default_verify_store,  [&](SSL_CTX*)               {++countCalled;return 1;});
    MOCK_SYS(SSL_CTX_load_verify_file,          [&](SSL_CTX*, char const*)  {++countCalled;return 1;});
    MOCK_SYS(SSL_CTX_load_verify_dir,           [&](SSL_CTX*, char const*)  {++countCalled;return 1;});
    MOCK_SYS(SSL_CTX_load_verify_store,         [&](SSL_CTX*, char const* v){expectedItem=v;++expectedCalled;return 0;});

    auto action = [](){
        CertifcateAuthorityInfo     ca;
        ca.store.items.push_back("Item 1");
        ca.setCertifcateAuthorityInfo(reinterpret_cast<SSL_CTX*>(0x08));
    };
    ASSERT_THROW(
        action(),
        std::runtime_error
    );

    ASSERT_EQ(countCalled, 0);
    ASSERT_EQ(expectedCalled, 1);
    ASSERT_EQ(expectedItem, "Item 1");
}

TEST(ConnectionSSocketUtilTest, ClientCAListInfoCTX)
{
    int countCalled = 0;
    typedef int (*CB)(int, x509_store_ctx_st *);

    MOCK_SYS(SSL_CTX_set_verify,                    [&](SSL_CTX*, int, CB)                   {++countCalled;return 1;});
    MOCK_SYS(sk_X509_NAME_new_null_wrapper,         [&]()                                    {++countCalled;return reinterpret_cast<STACK_OF(X509_NAME)*>(0x08);});
    MOCK_SYS(sk_X509_NAME_free_wrapper,             [&](STACK_OF(X509_NAME)*)                {++countCalled;});
    MOCK_SYS(sk_X509_NAME_pop_free_wrapper,         [&](STACK_OF(X509_NAME)*)                {++countCalled;});
    MOCK_SYS(SSL_add_file_cert_subjects_to_stack,   [&](STACK_OF(X509_NAME)*, char const*)   {++countCalled;return 1;});
    MOCK_SYS(SSL_add_dir_cert_subjects_to_stack,    [&](STACK_OF(X509_NAME)*, char const*)   {++countCalled;return 1;});
    MOCK_SYS(SSL_add_store_cert_subjects_to_stack,  [&](STACK_OF(X509_NAME)*, char const*)   {++countCalled;return 1;});
    MOCK_SYS(SSL_CTX_set_client_CA_list,            [&](SSL_CTX*, STACK_OF(X509_NAME)*)      {++countCalled;return 1;});

    ClientCAListInfo  list;
    list.setCertifcateAuthorityInfo(reinterpret_cast<SSL_CTX*>(0x08));

    ASSERT_EQ(countCalled, 0);
}

TEST(ConnectionSSocketUtilTest, ClientCAListInfoValidateClientCTX)
{
    int countCalled = 0;
    int expectedCalled = 0;
    typedef int (*CB)(int, x509_store_ctx_st *);


    MOCK_SYS(SSL_CTX_set_verify,                    [&](SSL_CTX*, int, CB)                   {++expectedCalled;return 1;});
    MOCK_SYS(sk_X509_NAME_new_null_wrapper,         [&]()                                    {++countCalled;return reinterpret_cast<STACK_OF(X509_NAME)*>(0x08);});
    MOCK_SYS(sk_X509_NAME_free_wrapper,             [&](STACK_OF(X509_NAME)*)                {++countCalled;});
    MOCK_SYS(sk_X509_NAME_pop_free_wrapper,         [&](STACK_OF(X509_NAME)*)                {++countCalled;});
    MOCK_SYS(SSL_add_file_cert_subjects_to_stack,   [&](STACK_OF(X509_NAME)*, char const*)   {++countCalled;return 1;});
    MOCK_SYS(SSL_add_dir_cert_subjects_to_stack,    [&](STACK_OF(X509_NAME)*, char const*)   {++countCalled;return 1;});
    MOCK_SYS(SSL_add_store_cert_subjects_to_stack,  [&](STACK_OF(X509_NAME)*, char const*)   {++countCalled;return 1;});
    MOCK_SYS(SSL_CTX_set_client_CA_list,            [&](SSL_CTX*, STACK_OF(X509_NAME)*)      {++countCalled;return 1;});

    ClientCAListInfo  list;
    list.verifyClientCA = true;
    list.setCertifcateAuthorityInfo(reinterpret_cast<SSL_CTX*>(0x08));

    ASSERT_EQ(countCalled, 0);
    ASSERT_EQ(expectedCalled, 1);
}

TEST(ConnectionSSocketUtilTest, ClientCAListInfoAddClientFileCTX)
{
    int countCalled = 0;
    int expectedCalled = 0;
    typedef int (*CB)(int, x509_store_ctx_st *);


    MOCK_SYS(SSL_CTX_set_verify,                    [&](SSL_CTX*, int, CB)                   {++countCalled;return 1;});
    MOCK_SYS(sk_X509_NAME_new_null_wrapper,         [&]()                                    {++expectedCalled;return reinterpret_cast<STACK_OF(X509_NAME)*>(0x08);});
    MOCK_SYS(sk_X509_NAME_free_wrapper,             [&](STACK_OF(X509_NAME)*)                {++countCalled;});
    MOCK_SYS(sk_X509_NAME_pop_free_wrapper,         [&](STACK_OF(X509_NAME)*)                {++countCalled;});
    MOCK_SYS(SSL_add_file_cert_subjects_to_stack,   [&](STACK_OF(X509_NAME)*, char const*)   {++expectedCalled;return 1;});
    MOCK_SYS(SSL_add_dir_cert_subjects_to_stack,    [&](STACK_OF(X509_NAME)*, char const*)   {++countCalled;return 1;});
    MOCK_SYS(SSL_add_store_cert_subjects_to_stack,  [&](STACK_OF(X509_NAME)*, char const*)   {++countCalled;return 1;});
    MOCK_SYS(SSL_CTX_set_client_CA_list,            [&](SSL_CTX*, STACK_OF(X509_NAME)*)      {++expectedCalled;return 1;});

    ClientCAListInfo  list;
    list.file.items.push_back("File 1");
    list.setCertifcateAuthorityInfo(reinterpret_cast<SSL_CTX*>(0x08));

    ASSERT_EQ(countCalled, 0);
    ASSERT_EQ(expectedCalled, 3);
}

TEST(ConnectionSSocketUtilTest, ClientCAListInfoAddClientDirCTX)
{
    int countCalled = 0;
    int expectedCalled = 0;
    typedef int (*CB)(int, x509_store_ctx_st *);


    MOCK_SYS(SSL_CTX_set_verify,                    [&](SSL_CTX*, int, CB)                   {++countCalled;return 1;});
    MOCK_SYS(sk_X509_NAME_new_null_wrapper,         [&]()                                    {++expectedCalled;return reinterpret_cast<STACK_OF(X509_NAME)*>(0x08);});
    MOCK_SYS(sk_X509_NAME_free_wrapper,             [&](STACK_OF(X509_NAME)*)                {++countCalled;});
    MOCK_SYS(sk_X509_NAME_pop_free_wrapper,         [&](STACK_OF(X509_NAME)*)                {++countCalled;});
    MOCK_SYS(SSL_add_file_cert_subjects_to_stack,   [&](STACK_OF(X509_NAME)*, char const*)   {++countCalled;return 1;});
    MOCK_SYS(SSL_add_dir_cert_subjects_to_stack,    [&](STACK_OF(X509_NAME)*, char const*)   {++expectedCalled;return 1;});
    MOCK_SYS(SSL_add_store_cert_subjects_to_stack,  [&](STACK_OF(X509_NAME)*, char const*)   {++countCalled;return 1;});
    MOCK_SYS(SSL_CTX_set_client_CA_list,            [&](SSL_CTX*, STACK_OF(X509_NAME)*)      {++expectedCalled;return 1;});

    ClientCAListInfo  list;
    list.dir.items.push_back("File 1");
    list.setCertifcateAuthorityInfo(reinterpret_cast<SSL_CTX*>(0x08));

    ASSERT_EQ(countCalled, 0);
    ASSERT_EQ(expectedCalled, 3);
}

TEST(ConnectionSSocketUtilTest, ClientCAListInfoAddClientStoreCTX)
{
    int countCalled = 0;
    int expectedCalled = 0;
    typedef int (*CB)(int, x509_store_ctx_st *);


    MOCK_SYS(SSL_CTX_set_verify,                    [&](SSL_CTX*, int, CB)                   {++countCalled;return 1;});
    MOCK_SYS(sk_X509_NAME_new_null_wrapper,         [&]()                                    {++expectedCalled;return reinterpret_cast<STACK_OF(X509_NAME)*>(0x08);});
    MOCK_SYS(sk_X509_NAME_free_wrapper,             [&](STACK_OF(X509_NAME)*)                {++countCalled;});
    MOCK_SYS(sk_X509_NAME_pop_free_wrapper,         [&](STACK_OF(X509_NAME)*)                {++countCalled;});
    MOCK_SYS(SSL_add_file_cert_subjects_to_stack,   [&](STACK_OF(X509_NAME)*, char const*)   {++countCalled;return 1;});
    MOCK_SYS(SSL_add_dir_cert_subjects_to_stack,    [&](STACK_OF(X509_NAME)*, char const*)   {++countCalled;return 1;});
    MOCK_SYS(SSL_add_store_cert_subjects_to_stack,  [&](STACK_OF(X509_NAME)*, char const*)   {++expectedCalled;return 1;});
    MOCK_SYS(SSL_CTX_set_client_CA_list,            [&](SSL_CTX*, STACK_OF(X509_NAME)*)      {++expectedCalled;return 1;});

    ClientCAListInfo  list;
    list.store.items.push_back("File 1");
    list.setCertifcateAuthorityInfo(reinterpret_cast<SSL_CTX*>(0x08));

    ASSERT_EQ(countCalled, 0);
    ASSERT_EQ(expectedCalled, 3);
}

TEST(ConnectionSSocketUtilTest, ClientCAListInfoValidateClientFailCTX)
{
    int countCalled = 0;
    int expectedCalled = 0;
    typedef int (*CB)(int, x509_store_ctx_st *);


    MOCK_SYS(SSL_CTX_set_verify,                    [&](SSL_CTX*, int, CB)                   {++expectedCalled;return 0;});
    MOCK_SYS(sk_X509_NAME_new_null_wrapper,         [&]()                                    {++countCalled;return reinterpret_cast<STACK_OF(X509_NAME)*>(0x08);});
    MOCK_SYS(sk_X509_NAME_free_wrapper,             [&](STACK_OF(X509_NAME)*)                {++countCalled;});
    MOCK_SYS(sk_X509_NAME_pop_free_wrapper,         [&](STACK_OF(X509_NAME)*)                {++countCalled;});
    MOCK_SYS(SSL_add_file_cert_subjects_to_stack,   [&](STACK_OF(X509_NAME)*, char const*)   {++countCalled;return 1;});
    MOCK_SYS(SSL_add_dir_cert_subjects_to_stack,    [&](STACK_OF(X509_NAME)*, char const*)   {++countCalled;return 1;});
    MOCK_SYS(SSL_add_store_cert_subjects_to_stack,  [&](STACK_OF(X509_NAME)*, char const*)   {++countCalled;return 1;});
    MOCK_SYS(SSL_CTX_set_client_CA_list,            [&](SSL_CTX*, STACK_OF(X509_NAME)*)      {++countCalled;return 1;});

    auto action = [](){
        ClientCAListInfo  list;
        list.verifyClientCA = true;
        list.setCertifcateAuthorityInfo(reinterpret_cast<SSL_CTX*>(0x08));
    };
    ASSERT_NO_THROW(
        action()
    );

    ASSERT_EQ(countCalled, 0);
    ASSERT_EQ(expectedCalled, 1);
}

TEST(ConnectionSSocketUtilTest, ClientCAListInfoAddClientFileFailCTX)
{
    int countCalled = 0;
    int expectedCalled = 0;
    typedef int (*CB)(int, x509_store_ctx_st *);


    MOCK_SYS(SSL_CTX_set_verify,                    [&](SSL_CTX*, int, CB)                   {++countCalled;return 1;});
    MOCK_SYS(sk_X509_NAME_new_null_wrapper,         [&]()                                    {++expectedCalled;return reinterpret_cast<STACK_OF(X509_NAME)*>(0x08);});
    MOCK_SYS(sk_X509_NAME_free_wrapper,             [&](STACK_OF(X509_NAME)*)                {++countCalled;});
    MOCK_SYS(sk_X509_NAME_pop_free_wrapper,         [&](STACK_OF(X509_NAME)*)                {++expectedCalled;});
    MOCK_SYS(SSL_add_file_cert_subjects_to_stack,   [&](STACK_OF(X509_NAME)*, char const*)   {++expectedCalled;return 0;});
    MOCK_SYS(SSL_add_dir_cert_subjects_to_stack,    [&](STACK_OF(X509_NAME)*, char const*)   {++countCalled;return 1;});
    MOCK_SYS(SSL_add_store_cert_subjects_to_stack,  [&](STACK_OF(X509_NAME)*, char const*)   {++countCalled;return 1;});
    MOCK_SYS(SSL_CTX_set_client_CA_list,            [&](SSL_CTX*, STACK_OF(X509_NAME)*)      {++countCalled;return 1;});

    auto action = [](){
        ClientCAListInfo  list;
        list.file.items.push_back("File 1");
        list.setCertifcateAuthorityInfo(reinterpret_cast<SSL_CTX*>(0x08));
    };
    ASSERT_THROW(
        action(),
        std::runtime_error
    );

    ASSERT_EQ(countCalled, 0);
    ASSERT_EQ(expectedCalled, 3);
}

TEST(ConnectionSSocketUtilTest, ClientCAListInfoAddClientDirFailCTX)
{
    int countCalled = 0;
    int expectedCalled = 0;
    typedef int (*CB)(int, x509_store_ctx_st *);


    MOCK_SYS(SSL_CTX_set_verify,                    [&](SSL_CTX*, int, CB)                   {++countCalled;return 1;});
    MOCK_SYS(sk_X509_NAME_new_null_wrapper,         [&]()                                    {++expectedCalled;return reinterpret_cast<STACK_OF(X509_NAME)*>(0x08);});
    MOCK_SYS(sk_X509_NAME_free_wrapper,             [&](STACK_OF(X509_NAME)*)                {++countCalled;});
    MOCK_SYS(sk_X509_NAME_pop_free_wrapper,         [&](STACK_OF(X509_NAME)*)                {++expectedCalled;});
    MOCK_SYS(SSL_add_file_cert_subjects_to_stack,   [&](STACK_OF(X509_NAME)*, char const*)   {++countCalled;return 1;});
    MOCK_SYS(SSL_add_dir_cert_subjects_to_stack,    [&](STACK_OF(X509_NAME)*, char const*)   {++expectedCalled;return 1;});
    MOCK_SYS(SSL_add_store_cert_subjects_to_stack,  [&](STACK_OF(X509_NAME)*, char const*)   {++countCalled;return 1;});
    MOCK_SYS(SSL_CTX_set_client_CA_list,            [&](SSL_CTX*, STACK_OF(X509_NAME)*)      {++countCalled;return 1;});

    auto action = [](){
        ClientCAListInfo  list;
        list.dir.items.push_back("File 1");
        list.setCertifcateAuthorityInfo(reinterpret_cast<SSL_CTX*>(0x08));
    };
    ASSERT_THROW(
        action(),
        std::runtime_error
    );

    ASSERT_EQ(countCalled, 0);
    ASSERT_EQ(expectedCalled, 3);
}

TEST(ConnectionSSocketUtilTest, ClientCAListInfoAddClientStoreFailCTX)
{
    int countCalled = 0;
    int expectedCalled = 0;
    typedef int (*CB)(int, x509_store_ctx_st *);


    MOCK_SYS(SSL_CTX_set_verify,                    [&](SSL_CTX*, int, CB)                   {++countCalled;return 1;});
    MOCK_SYS(sk_X509_NAME_new_null_wrapper,         [&]()                                    {++expectedCalled;return reinterpret_cast<STACK_OF(X509_NAME)*>(0x08);});
    MOCK_SYS(sk_X509_NAME_free_wrapper,             [&](STACK_OF(X509_NAME)*)                {++countCalled;});
    MOCK_SYS(sk_X509_NAME_pop_free_wrapper,         [&](STACK_OF(X509_NAME)*)                {++expectedCalled;});
    MOCK_SYS(SSL_add_file_cert_subjects_to_stack,   [&](STACK_OF(X509_NAME)*, char const*)   {++countCalled;return 1;});
    MOCK_SYS(SSL_add_dir_cert_subjects_to_stack,    [&](STACK_OF(X509_NAME)*, char const*)   {++countCalled;return 1;});
    MOCK_SYS(SSL_add_store_cert_subjects_to_stack,  [&](STACK_OF(X509_NAME)*, char const*)   {++expectedCalled;return 0;});
    MOCK_SYS(SSL_CTX_set_client_CA_list,            [&](SSL_CTX*, STACK_OF(X509_NAME)*)      {++countCalled;return 1;});

    auto action = [](){
        ClientCAListInfo  list;
        list.store.items.push_back("File 1");
        list.setCertifcateAuthorityInfo(reinterpret_cast<SSL_CTX*>(0x08));
    };
    ASSERT_THROW(
        action(),
        std::runtime_error
    );

    ASSERT_EQ(countCalled, 0);
    ASSERT_EQ(expectedCalled, 3);
}

TEST(ConnectionSSocketUtilTest, ClientCAListInfoSSL)
{
    int countCalled = 0;
    typedef int (*CB)(int, x509_store_ctx_st *);

    MOCK_SYS(SSL_set_verify,                    [&](SSL*, int, CB)                   {++countCalled;return 1;});
    MOCK_SYS(sk_X509_NAME_new_null_wrapper,         [&]()                                    {++countCalled;return reinterpret_cast<STACK_OF(X509_NAME)*>(0x08);});
    MOCK_SYS(sk_X509_NAME_free_wrapper,             [&](STACK_OF(X509_NAME)*)                {++countCalled;});
    MOCK_SYS(sk_X509_NAME_pop_free_wrapper,         [&](STACK_OF(X509_NAME)*)                {++countCalled;});
    MOCK_SYS(SSL_add_file_cert_subjects_to_stack,   [&](STACK_OF(X509_NAME)*, char const*)   {++countCalled;return 1;});
    MOCK_SYS(SSL_add_dir_cert_subjects_to_stack,    [&](STACK_OF(X509_NAME)*, char const*)   {++countCalled;return 1;});
    MOCK_SYS(SSL_add_store_cert_subjects_to_stack,  [&](STACK_OF(X509_NAME)*, char const*)   {++countCalled;return 1;});
    MOCK_SYS(SSL_set_client_CA_list,            [&](SSL*, STACK_OF(X509_NAME)*)      {++countCalled;return 1;});

    ClientCAListInfo  list;
    list.setCertifcateAuthorityInfo(reinterpret_cast<SSL*>(0x08));

    ASSERT_EQ(countCalled, 0);
}

TEST(ConnectionSSocketUtilTest, ClientCAListInfoValidateClientSSL)
{
    int countCalled = 0;
    int expectedCalled = 0;
    typedef int (*CB)(int, x509_store_ctx_st *);


    MOCK_SYS(SSL_set_verify,                    [&](SSL*, int, CB)                   {++expectedCalled;return 1;});
    MOCK_SYS(sk_X509_NAME_new_null_wrapper,         [&]()                                    {++countCalled;return reinterpret_cast<STACK_OF(X509_NAME)*>(0x08);});
    MOCK_SYS(sk_X509_NAME_free_wrapper,             [&](STACK_OF(X509_NAME)*)                {++countCalled;});
    MOCK_SYS(sk_X509_NAME_pop_free_wrapper,         [&](STACK_OF(X509_NAME)*)                {++countCalled;});
    MOCK_SYS(SSL_add_file_cert_subjects_to_stack,   [&](STACK_OF(X509_NAME)*, char const*)   {++countCalled;return 1;});
    MOCK_SYS(SSL_add_dir_cert_subjects_to_stack,    [&](STACK_OF(X509_NAME)*, char const*)   {++countCalled;return 1;});
    MOCK_SYS(SSL_add_store_cert_subjects_to_stack,  [&](STACK_OF(X509_NAME)*, char const*)   {++countCalled;return 1;});
    MOCK_SYS(SSL_set_client_CA_list,            [&](SSL*, STACK_OF(X509_NAME)*)      {++countCalled;return 1;});

    ClientCAListInfo  list;
    list.verifyClientCA = true;
    list.setCertifcateAuthorityInfo(reinterpret_cast<SSL*>(0x08));

    ASSERT_EQ(countCalled, 0);
    ASSERT_EQ(expectedCalled, 1);
}

TEST(ConnectionSSocketUtilTest, ClientCAListInfoAddClientFileSSL)
{
    int countCalled = 0;
    int expectedCalled = 0;
    typedef int (*CB)(int, x509_store_ctx_st *);


    MOCK_SYS(SSL_set_verify,                    [&](SSL*, int, CB)                   {++countCalled;return 1;});
    MOCK_SYS(sk_X509_NAME_new_null_wrapper,         [&]()                                    {++expectedCalled;return reinterpret_cast<STACK_OF(X509_NAME)*>(0x08);});
    MOCK_SYS(sk_X509_NAME_free_wrapper,             [&](STACK_OF(X509_NAME)*)                {++countCalled;});
    MOCK_SYS(sk_X509_NAME_pop_free_wrapper,         [&](STACK_OF(X509_NAME)*)                {++countCalled;});
    MOCK_SYS(SSL_add_file_cert_subjects_to_stack,   [&](STACK_OF(X509_NAME)*, char const*)   {++expectedCalled;return 1;});
    MOCK_SYS(SSL_add_dir_cert_subjects_to_stack,    [&](STACK_OF(X509_NAME)*, char const*)   {++countCalled;return 1;});
    MOCK_SYS(SSL_add_store_cert_subjects_to_stack,  [&](STACK_OF(X509_NAME)*, char const*)   {++countCalled;return 1;});
    MOCK_SYS(SSL_set_client_CA_list,            [&](SSL*, STACK_OF(X509_NAME)*)      {++expectedCalled;return 1;});

    ClientCAListInfo  list;
    list.file.items.push_back("File 1");
    list.setCertifcateAuthorityInfo(reinterpret_cast<SSL*>(0x08));

    ASSERT_EQ(countCalled, 0);
    ASSERT_EQ(expectedCalled, 3);
}

TEST(ConnectionSSocketUtilTest, ClientCAListInfoAddClientDirSSL)
{
    int countCalled = 0;
    int expectedCalled = 0;
    typedef int (*CB)(int, x509_store_ctx_st *);


    MOCK_SYS(SSL_set_verify,                    [&](SSL*, int, CB)                   {++countCalled;return 1;});
    MOCK_SYS(sk_X509_NAME_new_null_wrapper,         [&]()                                    {++expectedCalled;return reinterpret_cast<STACK_OF(X509_NAME)*>(0x08);});
    MOCK_SYS(sk_X509_NAME_free_wrapper,             [&](STACK_OF(X509_NAME)*)                {++countCalled;});
    MOCK_SYS(sk_X509_NAME_pop_free_wrapper,         [&](STACK_OF(X509_NAME)*)                {++countCalled;});
    MOCK_SYS(SSL_add_file_cert_subjects_to_stack,   [&](STACK_OF(X509_NAME)*, char const*)   {++countCalled;return 1;});
    MOCK_SYS(SSL_add_dir_cert_subjects_to_stack,    [&](STACK_OF(X509_NAME)*, char const*)   {++expectedCalled;return 1;});
    MOCK_SYS(SSL_add_store_cert_subjects_to_stack,  [&](STACK_OF(X509_NAME)*, char const*)   {++countCalled;return 1;});
    MOCK_SYS(SSL_set_client_CA_list,            [&](SSL*, STACK_OF(X509_NAME)*)      {++expectedCalled;return 1;});

    ClientCAListInfo  list;
    list.dir.items.push_back("File 1");
    list.setCertifcateAuthorityInfo(reinterpret_cast<SSL*>(0x08));

    ASSERT_EQ(countCalled, 0);
    ASSERT_EQ(expectedCalled, 3);
}

TEST(ConnectionSSocketUtilTest, ClientCAListInfoAddClientStoreSSL)
{
    int countCalled = 0;
    int expectedCalled = 0;
    typedef int (*CB)(int, x509_store_ctx_st *);


    MOCK_SYS(SSL_set_verify,                    [&](SSL*, int, CB)                   {++countCalled;return 1;});
    MOCK_SYS(sk_X509_NAME_new_null_wrapper,         [&]()                                    {++expectedCalled;return reinterpret_cast<STACK_OF(X509_NAME)*>(0x08);});
    MOCK_SYS(sk_X509_NAME_free_wrapper,             [&](STACK_OF(X509_NAME)*)                {++countCalled;});
    MOCK_SYS(sk_X509_NAME_pop_free_wrapper,         [&](STACK_OF(X509_NAME)*)                {++countCalled;});
    MOCK_SYS(SSL_add_file_cert_subjects_to_stack,   [&](STACK_OF(X509_NAME)*, char const*)   {++countCalled;return 1;});
    MOCK_SYS(SSL_add_dir_cert_subjects_to_stack,    [&](STACK_OF(X509_NAME)*, char const*)   {++countCalled;return 1;});
    MOCK_SYS(SSL_add_store_cert_subjects_to_stack,  [&](STACK_OF(X509_NAME)*, char const*)   {++expectedCalled;return 1;});
    MOCK_SYS(SSL_set_client_CA_list,            [&](SSL*, STACK_OF(X509_NAME)*)      {++expectedCalled;return 1;});

    ClientCAListInfo  list;
    list.store.items.push_back("File 1");
    list.setCertifcateAuthorityInfo(reinterpret_cast<SSL*>(0x08));

    ASSERT_EQ(countCalled, 0);
    ASSERT_EQ(expectedCalled, 3);
}

TEST(ConnectionSSocketUtilTest, ClientCAListInfoValidateClientFailSSL)
{
    int countCalled = 0;
    int expectedCalled = 0;
    typedef int (*CB)(int, x509_store_ctx_st *);


    MOCK_SYS(SSL_set_verify,                    [&](SSL*, int, CB)                   {++expectedCalled;return 0;});
    MOCK_SYS(sk_X509_NAME_new_null_wrapper,         [&]()                                    {++countCalled;return reinterpret_cast<STACK_OF(X509_NAME)*>(0x08);});
    MOCK_SYS(sk_X509_NAME_free_wrapper,             [&](STACK_OF(X509_NAME)*)                {++countCalled;});
    MOCK_SYS(sk_X509_NAME_pop_free_wrapper,         [&](STACK_OF(X509_NAME)*)                {++countCalled;});
    MOCK_SYS(SSL_add_file_cert_subjects_to_stack,   [&](STACK_OF(X509_NAME)*, char const*)   {++countCalled;return 1;});
    MOCK_SYS(SSL_add_dir_cert_subjects_to_stack,    [&](STACK_OF(X509_NAME)*, char const*)   {++countCalled;return 1;});
    MOCK_SYS(SSL_add_store_cert_subjects_to_stack,  [&](STACK_OF(X509_NAME)*, char const*)   {++countCalled;return 1;});
    MOCK_SYS(SSL_set_client_CA_list,            [&](SSL*, STACK_OF(X509_NAME)*)      {++countCalled;return 1;});

    auto action = [](){
        ClientCAListInfo  list;
        list.verifyClientCA = true;
        list.setCertifcateAuthorityInfo(reinterpret_cast<SSL*>(0x08));
    };
    ASSERT_NO_THROW(
        action()
    );

    ASSERT_EQ(countCalled, 0);
    ASSERT_EQ(expectedCalled, 1);
}

TEST(ConnectionSSocketUtilTest, ClientCAListInfoAddClientFileFailSSL)
{
    int countCalled = 0;
    int expectedCalled = 0;
    typedef int (*CB)(int, x509_store_ctx_st *);


    MOCK_SYS(SSL_set_verify,                    [&](SSL*, int, CB)                   {++countCalled;return 1;});
    MOCK_SYS(sk_X509_NAME_new_null_wrapper,         [&]()                                    {++expectedCalled;return reinterpret_cast<STACK_OF(X509_NAME)*>(0x08);});
    MOCK_SYS(sk_X509_NAME_free_wrapper,             [&](STACK_OF(X509_NAME)*)                {++countCalled;});
    MOCK_SYS(sk_X509_NAME_pop_free_wrapper,         [&](STACK_OF(X509_NAME)*)                {++expectedCalled;});
    MOCK_SYS(SSL_add_file_cert_subjects_to_stack,   [&](STACK_OF(X509_NAME)*, char const*)   {++expectedCalled;return 0;});
    MOCK_SYS(SSL_add_dir_cert_subjects_to_stack,    [&](STACK_OF(X509_NAME)*, char const*)   {++countCalled;return 1;});
    MOCK_SYS(SSL_add_store_cert_subjects_to_stack,  [&](STACK_OF(X509_NAME)*, char const*)   {++countCalled;return 1;});
    MOCK_SYS(SSL_set_client_CA_list,            [&](SSL*, STACK_OF(X509_NAME)*)      {++countCalled;return 1;});

    auto action = [](){
        ClientCAListInfo  list;
        list.file.items.push_back("File 1");
        list.setCertifcateAuthorityInfo(reinterpret_cast<SSL*>(0x08));
    };
    ASSERT_THROW(
        action(),
        std::runtime_error
    );

    ASSERT_EQ(countCalled, 0);
    ASSERT_EQ(expectedCalled, 3);
}

TEST(ConnectionSSocketUtilTest, ClientCAListInfoAddClientDirFailSSL)
{
    int countCalled = 0;
    int expectedCalled = 0;
    typedef int (*CB)(int, x509_store_ctx_st *);


    MOCK_SYS(SSL_set_verify,                    [&](SSL*, int, CB)                   {++countCalled;return 1;});
    MOCK_SYS(sk_X509_NAME_new_null_wrapper,         [&]()                                    {++expectedCalled;return reinterpret_cast<STACK_OF(X509_NAME)*>(0x08);});
    MOCK_SYS(sk_X509_NAME_free_wrapper,             [&](STACK_OF(X509_NAME)*)                {++countCalled;});
    MOCK_SYS(sk_X509_NAME_pop_free_wrapper,         [&](STACK_OF(X509_NAME)*)                {++expectedCalled;});
    MOCK_SYS(SSL_add_file_cert_subjects_to_stack,   [&](STACK_OF(X509_NAME)*, char const*)   {++countCalled;return 1;});
    MOCK_SYS(SSL_add_dir_cert_subjects_to_stack,    [&](STACK_OF(X509_NAME)*, char const*)   {++expectedCalled;return 1;});
    MOCK_SYS(SSL_add_store_cert_subjects_to_stack,  [&](STACK_OF(X509_NAME)*, char const*)   {++countCalled;return 1;});
    MOCK_SYS(SSL_set_client_CA_list,            [&](SSL*, STACK_OF(X509_NAME)*)      {++countCalled;return 1;});

    auto action = [](){
        ClientCAListInfo  list;
        list.dir.items.push_back("File 1");
        list.setCertifcateAuthorityInfo(reinterpret_cast<SSL*>(0x08));
    };
    ASSERT_THROW(
        action(),
        std::runtime_error
    );

    ASSERT_EQ(countCalled, 0);
    ASSERT_EQ(expectedCalled, 3);
}

TEST(ConnectionSSocketUtilTest, ClientCAListInfoAddClientStoreFailSSL)
{
    int countCalled = 0;
    int expectedCalled = 0;
    typedef int (*CB)(int, x509_store_ctx_st *);


    MOCK_SYS(SSL_set_verify,                    [&](SSL*, int, CB)                   {++countCalled;return 1;});
    MOCK_SYS(sk_X509_NAME_new_null_wrapper,         [&]()                                    {++expectedCalled;return reinterpret_cast<STACK_OF(X509_NAME)*>(0x08);});
    MOCK_SYS(sk_X509_NAME_free_wrapper,             [&](STACK_OF(X509_NAME)*)                {++countCalled;});
    MOCK_SYS(sk_X509_NAME_pop_free_wrapper,         [&](STACK_OF(X509_NAME)*)                {++expectedCalled;});
    MOCK_SYS(SSL_add_file_cert_subjects_to_stack,   [&](STACK_OF(X509_NAME)*, char const*)   {++countCalled;return 1;});
    MOCK_SYS(SSL_add_dir_cert_subjects_to_stack,    [&](STACK_OF(X509_NAME)*, char const*)   {++countCalled;return 1;});
    MOCK_SYS(SSL_add_store_cert_subjects_to_stack,  [&](STACK_OF(X509_NAME)*, char const*)   {++expectedCalled;return 0;});
    MOCK_SYS(SSL_set_client_CA_list,            [&](SSL*, STACK_OF(X509_NAME)*)      {++countCalled;return 1;});

    auto action = [](){
        ClientCAListInfo  list;
        list.store.items.push_back("File 1");
        list.setCertifcateAuthorityInfo(reinterpret_cast<SSL*>(0x08));
    };
    ASSERT_THROW(
        action(),
        std::runtime_error
    );

    ASSERT_EQ(countCalled, 0);
    ASSERT_EQ(expectedCalled, 3);
}

