#include <functional>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "envoy/extensions/transport_sockets/tls/v3/tls.pb.h"
#include "envoy/extensions/transport_sockets/tls/v3/tls_spiffe_validator_config.pb.h"
#include "envoy/secret/secret_provider.h"

#include "source/common/buffer/buffer_impl.h"
#include "source/common/common/callback_impl.h"
#include "source/common/event/dispatcher_impl.h"
#include "source/common/network/tcp_listener_impl.h"
#include "source/common/network/transport_socket_options_impl.h"
#include "source/common/singleton/manager_impl.h"
#include "source/common/stream_info/stream_info_impl.h"
#include "source/common/thread_local/thread_local_impl.h"
#include "source/common/tls/client_ssl_socket.h"
#include "source/common/tls/context_config_impl.h"
#include "source/common/tls/context_manager_impl.h"
#include "source/common/tls/server_context_config_impl.h"
#include "source/common/tls/server_ssl_socket.h"
#include "source/common/tls/ssl_handshaker.h"

#include "test/mocks/runtime/mocks.h"
#include "test/mocks/secret/mocks.h"
#include "test/mocks/server/server_factory_context.h"
#include "test/test_common/environment.h"
#include "test/test_common/network_utility.h"
#include "test/test_common/registry.h"
#include "test/test_common/simulated_time_system.h"
#include "test/test_common/thread_factory_for_test.h"
#include "test/test_common/utility.h"

#include "absl/strings/str_cat.h"
#include "absl/synchronization/notification.h"
#include "gtest/gtest.h"
#include "openssl/pem.h"
#include "openssl/x509v3.h"

namespace Envoy {
namespace Extensions {
namespace TransportSockets {
namespace Tls {
namespace {

using ValidationContext =
    envoy::extensions::transport_sockets::tls::v3::CertificateValidationContext;
using CommonTlsContext = envoy::extensions::transport_sockets::tls::v3::CommonTlsContext;
using SPIFFEConfig = envoy::extensions::transport_sockets::tls::v3::SPIFFECertValidatorConfig;
using testing::_;
using testing::Return;
using testing::ReturnRef;
constexpr absl::string_view Svid = "spiffe://example.com/workload";

std::string fixture(absl::string_view name) {
  return TestEnvironment::readFileToStringForTest(
      TestEnvironment::runfilesPath(absl::StrCat("test/common/tls/test_data/", name)));
}

bssl::UniquePtr<EVP_PKEY> signingKey(bool alternate = false) {
  const auto pem = fixture(alternate ? "fake_ca_key.pem" : "ca_key.pem");
  bssl::UniquePtr<BIO> bio(BIO_new_mem_buf(pem.data(), pem.size()));
  return bssl::UniquePtr<EVP_PKEY>(PEM_read_bio_PrivateKey(bio.get(), nullptr, nullptr, nullptr));
}

bssl::UniquePtr<X509> certificate(absl::string_view pem) {
  bssl::UniquePtr<BIO> bio(BIO_new_mem_buf(pem.data(), pem.size()));
  return bssl::UniquePtr<X509>(PEM_read_bio_X509(bio.get(), nullptr, nullptr, nullptr));
}

std::string pemCertificate(X509* cert) {
  bssl::UniquePtr<BIO> bio(BIO_new(BIO_s_mem()));
  EXPECT_EQ(1, PEM_write_bio_X509(bio.get(), cert));
  const uint8_t* data;
  size_t length;
  EXPECT_EQ(1, BIO_mem_contents(bio.get(), &data, &length));
  return std::string(reinterpret_cast<const char*>(data), length);
}

// Mutate only checked-in synthetic fixture certificates. The fixed fixture key is also the key
// installed in the real TLS socket; neither production keys nor a test TLS implementation is used.
std::string leaf(absl::string_view eku = "clientAuth,serverAuth", bool alternate = false) {
  auto cert = certificate(fixture("spiffe_san_cert.pem"));
  auto issuer = certificate(fixture(alternate ? "fake_ca_cert.pem" : "ca_cert.pem"));
  EXPECT_EQ(1, X509_set_issuer_name(cert.get(), X509_get_subject_name(issuer.get())));
  X509V3_CTX ctx;
  X509V3_set_ctx(&ctx, issuer.get(), cert.get(), nullptr, nullptr, 0);
  for (const auto& extension :
       {std::make_pair(NID_ext_key_usage, std::string(eku)),
        std::make_pair(NID_authority_key_identifier, std::string("keyid:always"))}) {
    bssl::UniquePtr<X509_EXTENSION> ext(
        X509V3_EXT_nconf_nid(nullptr, &ctx, extension.first, extension.second.c_str()));
    EXPECT_NE(nullptr, ext);
    const int index = X509_get_ext_by_NID(cert.get(), extension.first, -1);
    if (index >= 0) {
      bssl::UniquePtr<X509_EXTENSION> old(X509_delete_ext(cert.get(), index));
    }
    EXPECT_EQ(1, X509_add_ext(cert.get(), ext.get(), -1));
  }
  auto key = signingKey(alternate);
  EXPECT_GT(X509_sign(cert.get(), key.get(), EVP_sha256()), 0);
  return pemCertificate(cert.get());
}

std::string crl(bool revoked) {
  auto issuer = certificate(fixture("ca_cert.pem"));
  auto cert = certificate(fixture("spiffe_san_cert.pem"));
  bssl::UniquePtr<X509_CRL> list(X509_CRL_new());
  EXPECT_EQ(1, X509_CRL_set_version(list.get(), 1));
  EXPECT_EQ(1, X509_CRL_set_issuer_name(list.get(), X509_get_subject_name(issuer.get())));
  bssl::UniquePtr<ASN1_TIME> start(ASN1_TIME_new()), end(ASN1_TIME_new());
  EXPECT_EQ(1, ASN1_TIME_set_string(start.get(), "20260822000000Z"));
  EXPECT_EQ(1, ASN1_TIME_set_string(end.get(), "20280821000000Z"));
  EXPECT_EQ(1, X509_CRL_set1_lastUpdate(list.get(), start.get()));
  EXPECT_EQ(1, X509_CRL_set1_nextUpdate(list.get(), end.get()));
  if (revoked) {
    bssl::UniquePtr<X509_REVOKED> entry(X509_REVOKED_new());
    EXPECT_EQ(1, X509_REVOKED_set_serialNumber(entry.get(), X509_get_serialNumber(cert.get())));
    EXPECT_EQ(1, X509_REVOKED_set_revocationDate(entry.get(), start.get()));
    EXPECT_EQ(1, X509_CRL_add0_revoked(list.get(), entry.release()));
  }
  EXPECT_EQ(1, X509_CRL_sort(list.get()));
  auto key = signingKey();
  EXPECT_GT(X509_CRL_sign(list.get(), key.get(), EVP_sha256()), 0);
  bssl::UniquePtr<BIO> bio(BIO_new(BIO_s_mem()));
  EXPECT_EQ(1, PEM_write_bio_X509_CRL(bio.get(), list.get()));
  const uint8_t* data;
  size_t length;
  EXPECT_EQ(1, BIO_mem_contents(bio.get(), &data, &length));
  return std::string(reinterpret_cast<const char*>(data), length);
}

ValidationContext mapped(absl::string_view roots, absl::string_view domain = "example.com",
                         absl::string_view expected = "") {
  ValidationContext cvc;
  SPIFFEConfig config;
  // The native protobuf requires at least one typed domain. Keep a local explicit zero-anchor
  // store while adding/removing the foreign peer domain; do not turn removal into invalid config.
  auto* local = config.add_trust_domains();
  local->set_name("local.example");
  local->mutable_trust_bundle()->set_inline_string("");
  if (!domain.empty()) {
    auto* store = config.add_trust_domains();
    store->set_name(std::string(domain));
    store->mutable_trust_bundle()->set_inline_string(std::string(roots));
  }
  auto* validator = cvc.mutable_custom_validator_config();
  validator->set_name("envoy.tls.cert_validator.spiffe");
  EXPECT_TRUE(validator->mutable_typed_config()->PackFrom(config));
  if (!expected.empty()) {
    auto* matcher = cvc.add_match_typed_subject_alt_names();
    matcher->set_san_type(
        envoy::extensions::transport_sockets::tls::v3::SubjectAltNameMatcher::URI);
    matcher->mutable_matcher()->set_exact(std::string(expected));
  }
  return cvc;
}

// Only the secret delivery boundary is synthetic. These callbacks are the native provider API;
// ContextConfigImpl rebuilds the CVC and the actual client/server factory publishes its context.
class UpdatingValidationSecret : public Secret::CertificateValidationContextConfigProvider {
public:
  explicit UpdatingValidationSecret(ValidationContext cvc) : secret_(std::move(cvc)) {}
  const ValidationContext* secret() const override { return &secret_; }
  Envoy::Common::CallbackHandlePtr
  addValidationCallback(std::function<absl::Status(const ValidationContext&)> cb) override {
    return validations_.add(std::move(cb));
  }
  Envoy::Common::CallbackHandlePtr addUpdateCallback(std::function<absl::Status()> cb) override {
    return updates_.add(std::move(cb));
  }
  Envoy::Common::CallbackHandlePtr addRemoveCallback(std::function<absl::Status()> cb) override {
    return removes_.add(std::move(cb));
  }
  void start() override {}
  absl::Status update(const ValidationContext& cvc) {
    RETURN_IF_NOT_OK(validations_.runCallbacks(cvc));
    secret_ = cvc;
    return updates_.runCallbacks();
  }

private:
  ValidationContext secret_;
  Envoy::Common::CallbackManager<absl::Status, const ValidationContext&> validations_;
  Envoy::Common::CallbackManager<absl::Status> updates_, removes_;
};

class AllFalseCustomHandshaker : public HandshakerFactoryImpl {
public:
  std::string name() const override { return "envoy.test.session_custom_handshaker"; }
};

struct Endpoint : public Network::ConnectionCallbacks {
  void onEvent(Network::ConnectionEvent event) override {
    if (event == Network::ConnectionEvent::Connected) {
      ++connected_;
    } else {
      ++closed_;
      if (!closed_event_.HasBeenNotified()) {
        closed_event_.Notify();
      }
    }
    if (!ready_.HasBeenNotified()) {
      ready_.Notify();
    }
    if (event_hook_) {
      event_hook_(event);
    }
  }
  void onAboveWriteBufferHighWatermark() override {}
  void onBelowWriteBufferLowWatermark() override {}
  absl::Notification ready_, closed_event_;
  unsigned connected_{0}, closed_{0};
  std::function<void(Network::ConnectionEvent)> event_hook_;
};

struct Pair {
  explicit Pair(TimeSource& time_source)
      : stream_info_(time_source, nullptr, StreamInfo::FilterState::LifeSpan::Connection) {}
  Endpoint client_events_, server_events_;
  StreamInfo::StreamInfoImpl stream_info_;
  Network::ClientConnectionPtr client_;
  Network::ConnectionPtr server_;
};

struct HandshakeGate {
  absl::Notification reached_, release_;
  bool resumed_{false};
  static int index() {
    static const int value = SSL_get_ex_new_index(0, nullptr, nullptr, nullptr, nullptr);
    return value;
  }
  static void callback(const SSL* ssl, int flags, int) {
    auto* gate = static_cast<HandshakeGate*>(SSL_get_ex_data(ssl, index()));
    if (gate != nullptr && (flags & SSL_CB_HANDSHAKE_DONE) != 0) {
      gate->resumed_ = SSL_session_reused(ssl);
      gate->reached_.Notify();
      gate->release_.WaitForNotification();
    }
  }
  void install(SSL* ssl) {
    SSL_set_ex_data(ssl, index(), this);
    SSL_set_info_callback(ssl, callback);
  }
};

struct ApplicationWrites {
  unsigned records_{0};
  static void callback(int write, int, int type, const void* data, size_t length, SSL*, void* arg) {
    if (write != 0 && type == SSL3_RT_HEADER && length != 0 &&
        static_cast<const uint8_t*>(data)[0] == SSL3_RT_APPLICATION_DATA) {
      ++static_cast<ApplicationWrites*>(arg)->records_;
    }
  }
  void install(SSL* ssl) {
    SSL_set_msg_callback(ssl, callback);
    SSL_set_msg_callback_arg(ssl, this);
  }
};

// The parameter selects which real TLS role consumes updates: true = downstream server verifies
// the client, false = upstream client verifies the server. Both ends always use real TLS/mTLS.
class SessionRevalidationTlsTest : public testing::TestWithParam<bool>,
                                   public Network::TcpListenerCallbacks {
protected:
  SessionRevalidationTlsTest() {
    tls_.registerThread(*main_, true);
    tls_.registerThread(*worker_, false);
    ON_CALL(factory_context_.server_context_, api()).WillByDefault(ReturnRef(*api_));
    ON_CALL(factory_context_.server_context_, timeSource()).WillByDefault(ReturnRef(time_system_));
    ON_CALL(factory_context_.server_context_, singletonManager())
        .WillByDefault(ReturnRef(singletons_));
    ON_CALL(factory_context_.server_context_, threadLocal()).WillByDefault(ReturnRef(tls_));
    ON_CALL(factory_context_.server_context_, mainThreadDispatcher())
        .WillByDefault(ReturnRef(*main_));
    ON_CALL(factory_context_.server_context_, secretManager()).WillByDefault(ReturnRef(secrets_));
    manager_ = std::make_unique<ContextManagerImpl>(factory_context_.server_context_);
    ON_CALL(factory_context_.server_context_, sslContextManager())
        .WillByDefault(ReturnRef(*manager_));
    ON_CALL(secrets_, findOrCreateCertificateValidationContextProvider(_, _, _, _))
        .WillByDefault([this](const auto&, const std::string& name, auto&, auto&) {
          return name == "client" ? client_secret_ : server_secret_;
        });
    thread_ = Thread::threadFactoryForTest().createThread(
        [this] { worker_->run(Event::Dispatcher::RunType::RunUntilExit); });
    onWorker([] {});
  }

  ~SessionRevalidationTlsTest() override {
    tls_.shutdownGlobalThreading();
    onWorker([this] {
      for (auto& pair : pairs_) {
        close(*pair);
      }
      pairs_.clear();
      listener_.reset();
      listen_socket_.reset();
      worker_->clearDeferredDeleteList();
      tls_.shutdownThread();
      worker_->exit();
    });
    thread_->join();
    client_factory_.reset();
    server_factory_.reset();
    tls_.shutdownThread();
  }

  void onWorker(std::function<void()> cb) {
    absl::Notification done;
    worker_->post([cb = std::move(cb), &done] {
      cb();
      done.Notify();
    });
    done.WaitForNotification();
  }

  void whileWorkerPaused(const std::function<void()>& arrange) {
    absl::Notification entered, release;
    worker_->post([&] {
      entered.Notify();
      release.WaitForNotification();
    });
    entered.WaitForNotification();
    arrange();
    release.Notify();
    onWorker([] {});
  }

  void setup(const ValidationContext& selected_cvc = mapped(fixture("ca_cert.pem")),
             absl::string_view peer_eku = "clientAuth,serverAuth", bool custom = false,
             bool alternate_peer = false) {
    const auto default_cvc = mapped(fixture("ca_cert.pem"));
    client_secret_ =
        std::make_shared<UpdatingValidationSecret>(GetParam() ? default_cvc : selected_cvc);
    server_secret_ =
        std::make_shared<UpdatingValidationSecret>(GetParam() ? selected_cvc : default_cvc);
    envoy::extensions::transport_sockets::tls::v3::UpstreamTlsContext client;
    envoy::extensions::transport_sockets::tls::v3::DownstreamTlsContext server;
    // All ordinary cases exercise full handshakes. The dedicated resumption test supplies a
    // real saved session explicitly, rather than relying on the client's automatic session cache.
    client.mutable_max_session_keys()->set_value(0);
    server.mutable_require_client_certificate()->set_value(true);
    configure(*client.mutable_common_tls_context(), "client",
              GetParam() ? leaf(peer_eku, alternate_peer) : leaf(), custom && !GetParam());
    configure(*server.mutable_common_tls_context(), "server",
              GetParam() ? leaf() : leaf(peer_eku, alternate_peer), custom && GetParam());
    auto client_config = THROW_OR_RETURN_VALUE(
        ClientContextConfigImpl::create(client, factory_context_), Ssl::ClientContextConfigPtr);
    EXPECT_EQ(!custom || GetParam(), client_config->usesDefaultHandshaker());
    client_factory_ = THROW_OR_RETURN_VALUE(
        ClientSslSocketFactory::create(std::move(client_config), *manager_, *store_.rootScope()),
        std::unique_ptr<ClientSslSocketFactory>);
    auto server_config =
        THROW_OR_RETURN_VALUE(ServerContextConfigImpl::create(server, factory_context_, {}, false),
                              std::unique_ptr<ServerContextConfigImpl>);
    EXPECT_EQ(!custom || !GetParam(), server_config->usesDefaultHandshaker());
    server_factory_ = THROW_OR_RETURN_VALUE(
        ServerSslSocketFactory::create(std::move(server_config), *manager_, *store_.rootScope()),
        std::unique_ptr<ServerSslSocketFactory>);
    onWorker([this] {
      listen_socket_ = std::make_shared<Network::Test::TcpListenSocketImmediateListen>(
          Network::Test::getCanonicalLoopbackAddress(Network::Address::IpVersion::v4));
      listener_ = std::make_unique<Network::TcpListenerImpl>(
          *worker_, api_->randomGenerator(), runtime_, listen_socket_, *this, true, true, true,
          Network::DefaultMaxConnectionsToAcceptPerSocketEvent, std::nullopt);
    });
  }

  void configure(CommonTlsContext& config, absl::string_view name, const std::string& cert,
                 bool custom) {
    auto* tls_cert = config.add_tls_certificates();
    tls_cert->mutable_certificate_chain()->set_inline_string(cert);
    tls_cert->mutable_private_key()->set_inline_string(fixture("spiffe_san_key.pem"));
    auto* secret = config.mutable_validation_context_sds_secret_config();
    secret->set_name(std::string(name));
    secret->mutable_sds_config()->mutable_ads();
    // TLS 1.2 makes session-ticket availability deterministic at handshake completion.
    auto* params = config.mutable_tls_params();
    params->set_tls_minimum_protocol_version(
        envoy::extensions::transport_sockets::tls::v3::TlsParameters::TLSv1_2);
    params->set_tls_maximum_protocol_version(
        envoy::extensions::transport_sockets::tls::v3::TlsParameters::TLSv1_2);
    if (custom) {
      auto* extension = config.mutable_custom_handshaker();
      extension->set_name(custom_handshaker_.name());
      EXPECT_TRUE(extension->mutable_typed_config()->PackFrom(Protobuf::Struct{}));
    }
  }

  Pair& connect(absl::string_view expected_uri = "", HandshakeGate* gate = nullptr,
                SSL_SESSION* session = nullptr, Network::TransportSocketPtr prepared_socket = {}) {
    pairs_.push_back(std::make_unique<Pair>(time_system_));
    auto& pair = *pairs_.back();
    onWorker([&] {
      pending_ = &pair;
      pending_gate_ = GetParam() ? gate : nullptr;
      if (GetParam()) {
        pending_socket_ = std::move(prepared_socket);
      }
      Network::TransportSocketOptionsConstSharedPtr options;
      if (!expected_uri.empty()) {
        options = std::make_shared<Network::TransportSocketOptionsImpl>(
            "", std::vector<std::string>{std::string(expected_uri)});
      }
      pair.client_ = worker_->createClientConnection(
          listen_socket_->connectionInfoProvider().localAddress(), nullptr,
          prepared_socket ? std::move(prepared_socket)
                          : client_factory_->createTransportSocket(options, nullptr),
          nullptr, nullptr);
      pair.client_->addConnectionCallbacks(pair.client_events_);
      auto* ssl = rawSsl(*pair.client_);
      if (!GetParam() && gate != nullptr) {
        gate->install(ssl);
      }
      if (session != nullptr) {
        EXPECT_EQ(1, SSL_set_session(ssl, session));
      }
      pair.client_->connect();
    });
    return pair;
  }

  void onAccept(Network::ConnectionSocketPtr&& socket) override {
    ASSERT(pending_ != nullptr);
    auto& pair = *pending_;
    pair.server_ = worker_->createServerConnection(
        std::move(socket),
        pending_socket_ ? std::move(pending_socket_)
                        : server_factory_->createDownstreamTransportSocket(),
        pair.stream_info_);
    pair.server_->addConnectionCallbacks(pair.server_events_);
    if (pending_gate_ != nullptr) {
      pending_gate_->install(rawSsl(*pair.server_));
    }
    pending_ = nullptr;
    pending_gate_ = nullptr;
  }
  void onReject(Network::TcpListenerCallbacks::RejectCause) override { ADD_FAILURE(); }
  void recordConnectionsAcceptedOnSocketEvent(uint32_t) override {}

  static SSL* rawSsl(Network::Connection& connection) {
    return dynamic_cast<const SslHandshakerImpl*>(connection.ssl().get())->ssl();
  }
  Endpoint& selectedEvents(Pair& pair) {
    return GetParam() ? pair.server_events_ : pair.client_events_;
  }
  Network::Connection& selectedConnection(Pair& pair) {
    return GetParam() ? *pair.server_ : *pair.client_;
  }
  void waitReady(Pair& pair) {
    pair.client_events_.ready_.WaitForNotification();
    pair.server_events_.ready_.WaitForNotification();
    onWorker([] {});
  }
  void expectConnected(Pair& pair) {
    waitReady(pair);
    onWorker([&] {
      EXPECT_EQ(1, pair.client_events_.connected_);
      EXPECT_EQ(1, pair.server_events_.connected_);
      EXPECT_EQ(Network::Connection::State::Open, pair.client_->state());
      EXPECT_EQ(Network::Connection::State::Open, pair.server_->state());
      EXPECT_TRUE(pair.client_->ssl()->peerCertificateValidated());
      EXPECT_TRUE(pair.server_->ssl()->peerCertificateValidated());
    });
  }
  void expectRefused(Pair& pair) {
    waitReady(pair);
    onWorker([&] { EXPECT_EQ(0, selectedEvents(pair).connected_); });
  }
  void update(const ValidationContext& cvc) {
    EXPECT_TRUE((GetParam() ? server_secret_ : client_secret_)->update(cvc).ok());
  }
  void expectClosed(Pair& pair) {
    selectedEvents(pair).closed_event_.WaitForNotification();
    onWorker([&] {
      EXPECT_EQ(Network::Connection::State::Closed, selectedConnection(pair).state());
      EXPECT_FALSE(selectedConnection(pair).ssl()->peerCertificateValidated());
      EXPECT_NE(std::string::npos,
                selectedConnection(pair).transportFailureReason().find("typed SPIFFE"));
    });
  }
  void close(Pair& pair) {
    if (pair.client_) {
      pair.client_->close(Network::ConnectionCloseType::NoFlush);
    }
    if (pair.server_) {
      pair.server_->close(Network::ConnectionCloseType::NoFlush);
    }
  }

  Event::SimulatedTimeSystem time_system_;
  ThreadLocal::InstanceImpl tls_;
  Stats::TestUtil::TestStore store_;
  Api::ApiPtr api_{Api::createApiForTest(store_, time_system_)};
  Event::DispatcherPtr main_{api_->allocateDispatcher("mapped_tls_main")};
  Event::DispatcherPtr worker_{api_->allocateDispatcher("mapped_tls_worker")};
  Singleton::ManagerImpl singletons_;
  testing::NiceMock<Server::Configuration::MockTransportSocketFactoryContext> factory_context_;
  testing::NiceMock<Secret::MockSecretManager> secrets_;
  testing::NiceMock<Runtime::MockLoader> runtime_;
  AllFalseCustomHandshaker custom_handshaker_;
  Registry::InjectFactory<Ssl::HandshakerFactory> inject_custom_{custom_handshaker_};
  std::unique_ptr<ContextManagerImpl> manager_;
  std::shared_ptr<UpdatingValidationSecret> client_secret_, server_secret_;
  std::unique_ptr<ClientSslSocketFactory> client_factory_;
  std::unique_ptr<ServerSslSocketFactory> server_factory_;
  Thread::ThreadPtr thread_;
  Network::SocketSharedPtr listen_socket_;
  Network::ListenerPtr listener_;
  std::vector<std::unique_ptr<Pair>> pairs_;
  Pair* pending_{nullptr};
  HandshakeGate* pending_gate_{nullptr};
  Network::TransportSocketPtr pending_socket_;
};

TEST_P(SessionRevalidationTlsTest, EmptyMatchersAcceptValidMappedSvid) {
  setup();
  auto& pair = connect();
  expectConnected(pair);
  update(mapped(fixture("ca_cert.pem")));
  onWorker([&] { EXPECT_EQ(0, selectedEvents(pair).closed_); });
}

TEST_P(SessionRevalidationTlsTest, IntendedPeerEkuIsAccepted) {
  setup(mapped(fixture("ca_cert.pem")), GetParam() ? "clientAuth" : "serverAuth");
  auto& pair = connect();
  expectConnected(pair);
  update(mapped(fixture("ca_cert.pem")));
  onWorker([&] { EXPECT_EQ(0, selectedEvents(pair).closed_); });
}

TEST_P(SessionRevalidationTlsTest, WrongPeerEkuIsRefusedDuringHandshake) {
  setup(mapped(fixture("ca_cert.pem")), GetParam() ? "serverAuth" : "clientAuth");
  auto& pair = connect();
  expectRefused(pair);
}

TEST_P(SessionRevalidationTlsTest, ConfiguredIdentityMismatchRefusesHandshake) {
  setup(mapped(fixture("ca_cert.pem"), "example.com", "spiffe://example.com/other"));
  auto& pair = connect(GetParam() ? "" : Svid);
  expectRefused(pair);
}

TEST_P(SessionRevalidationTlsTest, DomainRemovalClosesEstablishedSession) {
  setup();
  auto& pair = connect();
  expectConnected(pair);
  update(mapped("", ""));
  expectClosed(pair);
}

TEST_P(SessionRevalidationTlsTest, RejectedSessionCannotWritePendingDataDuringNoFlushClose) {
  setup();
  auto& pair = connect();
  expectConnected(pair);
  ApplicationWrites writes;
  onWorker([&] { writes.install(rawSsl(selectedConnection(pair))); });
  whileWorkerPaused([&] {
    // Both native posts run before returning to socket I/O: queue application data, then process
    // policy rejection. ConnectionImpl::close(NoFlush) attempts a best-effort doWrite even though
    // it will not wait to flush; the rejected TLS socket must refuse that actual write attempt.
    worker_->post([&] {
      Buffer::OwnedImpl data("application data queued before policy notification");
      selectedConnection(pair).write(data, false);
    });
    update(mapped("", ""));
  });
  expectClosed(pair);
  onWorker([&] {
    EXPECT_EQ(0, writes.records_);
    SSL_set_msg_callback(rawSsl(selectedConnection(pair)), nullptr);
    SSL_set_msg_callback_arg(rawSsl(selectedConnection(pair)), nullptr);
  });
}

TEST_P(SessionRevalidationTlsTest, ExplicitEmptyStoreClosesEstablishedSession) {
  setup();
  auto& pair = connect();
  expectConnected(pair);
  update(mapped(""));
  expectClosed(pair);
}

TEST_P(SessionRevalidationTlsTest, UnknownDomainClosesEstablishedSession) {
  setup();
  auto& pair = connect();
  expectConnected(pair);
  update(mapped(fixture("ca_cert.pem"), "other.example"));
  expectClosed(pair);
}

TEST_P(SessionRevalidationTlsTest, OverlapRotationPreservesThenOldRootRemovalCloses) {
  setup();
  auto& pair = connect();
  expectConnected(pair);
  update(mapped(fixture("ca_cert.pem") + fixture("fake_ca_cert.pem")));
  onWorker([&] { EXPECT_EQ(0, selectedEvents(pair).closed_); });
  update(mapped(fixture("fake_ca_cert.pem")));
  expectClosed(pair);
}

TEST_P(SessionRevalidationTlsTest, NewRootSessionSurvivesOldRootRemoval) {
  setup(mapped(fixture("ca_cert.pem") + fixture("fake_ca_cert.pem")), "clientAuth,serverAuth",
        false, true);
  auto& pair = connect();
  expectConnected(pair);
  update(mapped(fixture("fake_ca_cert.pem")));
  onWorker([&] {
    EXPECT_EQ(0, selectedEvents(pair).closed_);
    EXPECT_TRUE(selectedConnection(pair).ssl()->peerCertificateValidated());
  });
}

TEST_P(SessionRevalidationTlsTest, CurrentConfiguredRestrictionIsEnforced) {
  setup();
  auto& pair = connect(GetParam() ? "" : Svid);
  expectConnected(pair);
  update(mapped(fixture("ca_cert.pem"), "example.com", "spiffe://example.com/other"));
  expectClosed(pair);
}

TEST_P(SessionRevalidationTlsTest, ChangingAwayFromMappedPolicyClosesOldSession) {
  setup();
  auto& pair = connect();
  expectConnected(pair);
  ValidationContext ordinary;
  ordinary.mutable_trusted_ca()->set_inline_string(fixture("ca_cert.pem"));
  update(ordinary);
  expectClosed(pair);
}

TEST_P(SessionRevalidationTlsTest, SelectedStoreCrlUpdateRevokesExistingSession) {
  setup(mapped(fixture("ca_cert.pem") + crl(false)));
  auto& pair = connect();
  expectConnected(pair);
  update(mapped(fixture("ca_cert.pem") + crl(true)));
  expectClosed(pair);
}

TEST_P(SessionRevalidationTlsTest, UpdateDuringNativeHandshakeRefusesBeforeConnected) {
  setup();
  HandshakeGate gate;
  auto& pair = connect("", &gate);
  gate.reached_.WaitForNotification();
  update(mapped("", ""));
  gate.release_.Notify();
  expectRefused(pair);
  onWorker(
      [&] { EXPECT_EQ(Network::Connection::State::Closed, selectedConnection(pair).state()); });
}

TEST_P(SessionRevalidationTlsTest, SocketCapturedBeforeUpdateRegistersAgainstLatestStore) {
  setup();
  Network::TransportSocketPtr old_socket;
  onWorker([&] {
    old_socket = GetParam() ? server_factory_->createDownstreamTransportSocket()
                            : client_factory_->createTransportSocket(nullptr, nullptr);
  });
  // There was no connection/token when the notification was delivered. The socket's captured
  // original SSL context can still complete crypto, but registration must use the current group.
  update(mapped("", ""));
  onWorker([] {});
  auto& pair = connect("", nullptr, nullptr, std::move(old_socket));
  expectRefused(pair);
  onWorker([&] {
    EXPECT_NE(std::string::npos,
              selectedConnection(pair).transportFailureReason().find("typed SPIFFE"));
  });
}

TEST_P(SessionRevalidationTlsTest, QueuedNotificationsAlwaysUseLatestCurrentStore) {
  setup();
  auto& pair = connect();
  expectConnected(pair);
  whileWorkerPaused([&] {
    update(mapped("", ""));
    update(mapped(fixture("ca_cert.pem")));
  });
  onWorker([&] { EXPECT_EQ(0, selectedEvents(pair).closed_); });
  whileWorkerPaused([&] {
    update(mapped(fixture("ca_cert.pem")));
    update(mapped("", ""));
  });
  expectClosed(pair);
}

TEST_P(SessionRevalidationTlsTest, FactoryDestructionBeforeQueuedUpdateDoesNotLoseRemoval) {
  setup();
  auto& pair = connect();
  expectConnected(pair);
  whileWorkerPaused([&] {
    update(mapped("", ""));
    client_factory_.reset();
    server_factory_.reset();
  });
  expectClosed(pair);
}

TEST_P(SessionRevalidationTlsTest, ReentrantCloseDestroysAnotherRegisteredSocket) {
  setup();
  auto& first = connect();
  expectConnected(first);
  auto& second = connect();
  expectConnected(second);
  onWorker([&] {
    selectedEvents(first).event_hook_ = [&](Network::ConnectionEvent event) {
      if (event != Network::ConnectionEvent::Connected) {
        close(second);
        second.client_.reset();
        second.server_.reset();
      }
    };
  });
  update(mapped("", ""));
  expectClosed(first);
  onWorker([&] {
    EXPECT_EQ(nullptr, second.client_);
    EXPECT_EQ(nullptr, second.server_);
  });
}

TEST_P(SessionRevalidationTlsTest, ExplicitCustomHandshakerWithAllFalseCapabilitiesIsExcluded) {
  setup(mapped(fixture("ca_cert.pem")), "clientAuth,serverAuth", true);
  auto& pair = connect();
  expectConnected(pair);
  update(mapped("", ""));
  onWorker([&] { EXPECT_EQ(0, selectedEvents(pair).closed_); });
}

TEST_P(SessionRevalidationTlsTest, OrdinaryDefaultTlsKeepsEstablishedSessions) {
  ValidationContext ordinary;
  ordinary.mutable_trusted_ca()->set_inline_string(fixture("ca_cert.pem"));
  setup(ordinary);
  auto& pair = connect();
  expectConnected(pair);
  ValidationContext new_ordinary;
  new_ordinary.mutable_trusted_ca()->set_inline_string(fixture("fake_ca_cert.pem"));
  update(new_ordinary);
  onWorker([&] { EXPECT_EQ(0, selectedEvents(pair).closed_); });
}

TEST_P(SessionRevalidationTlsTest, MappedResumptionIsActuallyResumedButNeverConnected) {
  setup();
  auto& first = connect();
  expectConnected(first);
  bssl::UniquePtr<SSL_SESSION> session;
  onWorker([&] {
    session.reset(SSL_get1_session(rawSsl(*first.client_)));
    EXPECT_TRUE(SSL_SESSION_is_resumable(session.get()));
    close(first);
  });
  HandshakeGate gate;
  auto& resumed = connect("", &gate, session.get());
  gate.reached_.WaitForNotification();
  EXPECT_TRUE(gate.resumed_);
  gate.release_.Notify();
  expectRefused(resumed);
}

TEST_P(SessionRevalidationTlsTest, OriginalTransportIdentityRestrictionRemainsEnforced) {
  if (GetParam()) {
    // The maintained downstream factory has no transport-options argument. Its original
    // configured matcher restriction is tested for this role in the other parameterized cases.
    setup(mapped(fixture("ca_cert.pem"), "example.com", Svid));
    auto& pair = connect();
    expectConnected(pair);
    update(mapped(fixture("ca_cert.pem")));
    onWorker([&] { EXPECT_EQ(0, selectedEvents(pair).closed_); });
  } else {
    setup();
    auto& pair = connect(Svid);
    expectConnected(pair);
    update(mapped(fixture("ca_cert.pem")));
    onWorker([&] { EXPECT_EQ(0, selectedEvents(pair).closed_); });
    auto& wrong = connect("spiffe://example.com/other");
    expectRefused(wrong);
  }
}

INSTANTIATE_TEST_SUITE_P(PeerRoles, SessionRevalidationTlsTest, testing::Bool());

} // namespace
} // namespace Tls
} // namespace TransportSockets
} // namespace Extensions
} // namespace Envoy
