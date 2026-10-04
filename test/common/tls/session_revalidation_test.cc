#include "source/common/common/thread.h"
#include "source/common/event/dispatcher_impl.h"
#include "source/common/thread_local/thread_local_impl.h"
#include "source/common/tls/session_revalidation.h"

#include "test/mocks/network/mocks.h"
#include "test/mocks/ssl/mocks.h"
#include "test/test_common/simulated_time_system.h"
#include "test/test_common/thread_factory_for_test.h"
#include "test/test_common/utility.h"

#include "absl/synchronization/notification.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"

namespace Envoy {
namespace Extensions {
namespace TransportSockets {
namespace Tls {
namespace {

class SessionRevalidationTest : public testing::Test {
protected:
  SessionRevalidationTest() {
    tls_.registerThread(*main_, true);
    tls_.registerThread(*worker_, false);
    tracker_ = std::make_unique<SessionRevalidation>(tls_);
    thread_ = Thread::threadFactoryForTest().createThread(
        [this] { worker_->run(Event::Dispatcher::RunType::RunUntilExit); });
    onWorker([] {});
  }

  ~SessionRevalidationTest() override {
    if (thread_ != nullptr) {
      if (!tls_.isShutdown()) {
        tls_.shutdownGlobalThreading();
      }
      stopWorker();
    }
    tracker_.reset();
    tls_.shutdownThread();
  }

  void onWorker(std::function<void()> callback) {
    absl::Notification done;
    worker_->post([callback = std::move(callback), &done] {
      callback();
      done.Notify();
    });
    done.WaitForNotification();
  }

  void stopWorker() {
    onWorker([this] {
      registrations_.clear();
      tls_.shutdownThread();
      worker_->exit();
    });
    thread_->join();
    thread_.reset();
  }

  // Hold the real worker queue while arranging delivery order on the main thread. No sleeps,
  // synthetic dispatcher or completion callback is involved.
  void whileWorkerPaused(const std::function<void()>& arrange) {
    absl::Notification entered;
    absl::Notification release;
    absl::Notification finished;
    worker_->post([&] {
      entered.Notify();
      release.WaitForNotification();
      finished.Notify();
    });
    entered.WaitForNotification();
    arrange();
    release.Notify();
    finished.WaitForNotification();
    onWorker([] {});
  }

  Ssl::ContextSharedPtr context() {
    return std::make_shared<testing::StrictMock<Ssl::MockClientContext>>();
  }

  Event::SimulatedTimeSystem time_system_;
  ThreadLocal::InstanceImpl tls_;
  Api::ApiPtr api_{Api::createApiForTest(time_system_)};
  Event::DispatcherPtr main_{api_->allocateDispatcher("session_main")};
  Event::DispatcherPtr worker_{api_->allocateDispatcher("session_worker")};
  std::unique_ptr<SessionRevalidation> tracker_;
  Thread::ThreadPtr thread_;
  std::vector<SessionRevalidation::RegistrationPtr> registrations_;
};

TEST_F(SessionRevalidationTest, CallbackRunsOnlyOnOwningWorker) {
  auto policy = std::make_shared<SessionRevalidation::Policy>(context());
  uint32_t calls = 0;
  EXPECT_EQ(nullptr, tracker_->registerSession(policy, [&] { ADD_FAILURE(); }));
  onWorker([&] {
    registrations_.push_back(tracker_->registerSession(policy, [&] {
      EXPECT_TRUE(worker_->isThreadSafe());
      EXPECT_FALSE(Thread::MainThread::isMainOrTestThread());
      ++calls;
    }));
    EXPECT_NE(nullptr, registrations_.back());
  });
  EXPECT_TRUE(tracker_->publish(policy, context()));
  onWorker([] {});
  EXPECT_EQ(1, calls);
}

TEST_F(SessionRevalidationTest, TokenDestroyedBeforeQueuedDelivery) {
  auto policy = std::make_shared<SessionRevalidation::Policy>(context());
  uint32_t calls = 0;
  onWorker([&] { registrations_.push_back(tracker_->registerSession(policy, [&] { ++calls; })); });
  whileWorkerPaused([&] {
    worker_->post([&] { registrations_.clear(); });
    EXPECT_TRUE(tracker_->publish(policy, context()));
  });
  EXPECT_EQ(0, calls);
}

TEST_F(SessionRevalidationTest, ReentrantCloseCancelsSelfAndNextRegistration) {
  auto policy = std::make_shared<SessionRevalidation::Policy>(context());
  uint32_t calls = 0;
  testing::StrictMock<Network::MockConnection> connection;
  EXPECT_CALL(connection, close(Network::ConnectionCloseType::NoFlush)).WillOnce([&] {
    registrations_.clear();
  });
  onWorker([&] {
    registrations_.push_back(tracker_->registerSession(policy, [&] {
      ++calls;
      connection.close(Network::ConnectionCloseType::NoFlush);
    }));
    registrations_.push_back(tracker_->registerSession(policy, [&] { ADD_FAILURE(); }));
  });
  EXPECT_TRUE(tracker_->publish(policy, context()));
  onWorker([] {});
  EXPECT_EQ(1, calls);
  EXPECT_TRUE(tracker_->publish(policy, context()));
  onWorker([] {});
  EXPECT_EQ(1, calls);
}

TEST_F(SessionRevalidationTest, UnregisteredThreadCannotRegisterSocket) {
  auto policy = std::make_shared<SessionRevalidation::Policy>(context());
  auto thread = Thread::threadFactoryForTest().createThread(
      [&] { EXPECT_EQ(nullptr, tracker_->registerSession(policy, [&] { ADD_FAILURE(); })); });
  thread->join();
}

TEST_F(SessionRevalidationTest, ReentrantRegistrationDoesNotInvalidateIteration) {
  auto policy = std::make_shared<SessionRevalidation::Policy>(context());
  uint32_t added_calls = 0;
  onWorker([&] {
    registrations_.push_back(tracker_->registerSession(policy, [&] {
      registrations_.push_back(tracker_->registerSession(policy, [&] { ++added_calls; }));
      registrations_.front().reset();
    }));
  });
  EXPECT_TRUE(tracker_->publish(policy, context()));
  onWorker([] {});
  EXPECT_EQ(0, added_calls);
  EXPECT_TRUE(tracker_->publish(policy, context()));
  onWorker([] {});
  EXPECT_EQ(1, added_calls);
}

TEST_F(SessionRevalidationTest, QueuedDeliverySurvivesFactoryPolicyRelease) {
  auto policy = std::make_shared<SessionRevalidation::Policy>(context());
  const auto replacement = context();
  uint32_t calls = 0;
  onWorker([&] {
    registrations_.push_back(tracker_->registerSession(policy, [&] {
      EXPECT_EQ(replacement, registrations_.front()->currentPolicy().context_);
      ++calls;
    }));
  });
  whileWorkerPaused([&] {
    EXPECT_TRUE(tracker_->publish(policy, replacement));
    policy.reset();
  });
  EXPECT_EQ(1, calls);
}

TEST_F(SessionRevalidationTest, DestroyedTrackerCancelsQueuedDelivery) {
  auto policy = std::make_shared<SessionRevalidation::Policy>(context());
  uint32_t calls = 0;
  onWorker([&] { registrations_.push_back(tracker_->registerSession(policy, [&] { ++calls; })); });
  whileWorkerPaused([&] {
    EXPECT_TRUE(tracker_->publish(policy, context()));
    tracker_.reset();
  });
  EXPECT_EQ(0, calls);
}

TEST_F(SessionRevalidationTest, DestroyedTrackerCancelsQueuedInitialization) {
  whileWorkerPaused([&] {
    auto tracker = std::make_unique<SessionRevalidation>(tls_);
    tracker.reset();
  });
}

TEST_F(SessionRevalidationTest, LateRegistrationValidatesCurrentContext) {
  const auto original = context();
  const auto replacement = context();
  auto policy = std::make_shared<SessionRevalidation::Policy>(original);
  EXPECT_TRUE(tracker_->publish(policy, replacement));
  onWorker([&] {
    registrations_.push_back(tracker_->registerSession(policy, [] {}));
    EXPECT_TRUE(registrations_.front()->withCurrentPolicy([&](const auto& current) {
      EXPECT_NE(original, current.context_);
      return current.context_ == replacement;
    }));
  });
}

TEST_F(SessionRevalidationTest, QueuedUpdatesAlwaysUseLatestContext) {
  auto policy = std::make_shared<SessionRevalidation::Policy>(context());
  const auto intermediate = context();
  const auto latest = context();
  std::vector<SessionRevalidation::Snapshot> observed;
  onWorker([&] {
    registrations_.push_back(tracker_->registerSession(
        policy, [&] { observed.push_back(registrations_.front()->currentPolicy()); }));
  });
  whileWorkerPaused([&] {
    EXPECT_TRUE(tracker_->publish(policy, intermediate));
    EXPECT_TRUE(tracker_->publish(policy, latest));
  });
  ASSERT_EQ(2, observed.size());
  EXPECT_EQ(latest, observed[0].context_);
  EXPECT_EQ(latest, observed[1].context_);
  EXPECT_EQ(observed[0].generation_, observed[1].generation_);
}

TEST_F(SessionRevalidationTest, PolicyGroupsDoNotNotifyOtherSockets) {
  auto selected = std::make_shared<SessionRevalidation::Policy>(context());
  auto other = std::make_shared<SessionRevalidation::Policy>(context());
  uint32_t calls = 0;
  onWorker([&] {
    registrations_.push_back(tracker_->registerSession(selected, [&] { ++calls; }));
    registrations_.push_back(tracker_->registerSession(other, [&] { ADD_FAILURE(); }));
  });
  EXPECT_TRUE(tracker_->publish(selected, context()));
  onWorker([] {});
  EXPECT_EQ(1, calls);
}

TEST_F(SessionRevalidationTest, ShutdownRefusesPublishAndRegistration) {
  auto policy = std::make_shared<SessionRevalidation::Policy>(context());
  const auto original = context();
  EXPECT_TRUE(tracker_->publish(policy, original));
  onWorker(
      [&] { registrations_.push_back(tracker_->registerSession(policy, [&] { ADD_FAILURE(); })); });
  tls_.shutdownGlobalThreading();
  EXPECT_FALSE(tracker_->publish(policy, context()));
  onWorker([&] {
    EXPECT_EQ(original, registrations_.front()->currentPolicy().context_);
    EXPECT_EQ(nullptr, tracker_->registerSession(policy, [&] { ADD_FAILURE(); }));
  });
  stopWorker();
  // The worker dispatcher has exited. Native publication must not post through it.
  EXPECT_FALSE(tracker_->publish(policy, context()));
}

} // namespace
} // namespace Tls
} // namespace TransportSockets
} // namespace Extensions
} // namespace Envoy
