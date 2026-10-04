#include "source/common/tls/session_revalidation.h"

#include "source/common/common/thread.h"

namespace Envoy {
namespace Extensions {
namespace TransportSockets {
namespace Tls {

SessionRevalidation::SessionRevalidation(ThreadLocal::Instance& tls) : workers_(tls) {
  workers_.set([](Event::Dispatcher&) {
    return std::make_shared<Worker>(!Thread::MainThread::isMainOrTestThread());
  });
}

SessionRevalidation::Registration::~Registration() {
  state_->callback_ = nullptr;
  if (const auto worker = worker_.lock(); worker != nullptr) {
    worker->registrations_.erase(entry_);
  }
}

SessionRevalidation::Snapshot SessionRevalidation::Registration::currentPolicy() const {
  absl::ReaderMutexLock lock(&state_->policy_->mutex_);
  return state_->policy_->current_;
}

bool SessionRevalidation::Registration::withCurrentPolicy(
    const std::function<bool(const Snapshot&)>& validate) const {
  absl::ReaderMutexLock lock(&state_->policy_->mutex_);
  return validate(state_->policy_->current_);
}

SessionRevalidation::RegistrationPtr
SessionRevalidation::registerSession(const PolicySharedPtr& policy,
                                     std::function<void()> callback) {
  if (workers_.isShutdown() || !workers_.currentThreadRegistered()) {
    return nullptr;
  }
  const auto worker = workers_.get();
  if (!worker.has_value() || !worker->enabled_) {
    return nullptr;
  }
  auto state = std::make_shared<RegistrationState>(RegistrationState{policy, std::move(callback)});
  const auto entry = worker->registrations_.emplace(worker->registrations_.end(), state);
  return RegistrationPtr(new Registration(std::move(state), worker->weak_from_this(), entry));
}

bool SessionRevalidation::publish(const PolicySharedPtr& policy, Ssl::ContextSharedPtr context) {
  ASSERT_IS_MAIN_OR_TEST_THREAD();
  if (workers_.isShutdown()) {
    return false;
  }
  {
    absl::WriterMutexLock lock(&policy->mutex_);
    policy->current_ = {std::move(context), policy->current_.generation_ + 1};
  }
  // The native slot guards queued delivery. Only the shared policy is retained, never the slot,
  // tracker, factory, socket or dispatcher. Main-thread delivery has no socket registrations.
  workers_.runOnAllThreads([policy](OptRef<Worker> worker) {
    if (worker.has_value() && worker->enabled_) {
      worker->notify(policy);
    }
  });
  return true;
}

void SessionRevalidation::Worker::notify(const PolicySharedPtr& policy) {
  // A callback may close its socket, cancel another token or register a new socket. Traverse a
  // snapshot of weak registrations, checking liveness again before each invocation.
  const std::vector<std::weak_ptr<RegistrationState>> registrations(registrations_.begin(),
                                                                    registrations_.end());
  for (const auto& weak : registrations) {
    const auto state = weak.lock();
    if (state != nullptr && state->policy_ == policy && state->callback_) {
      auto callback = state->callback_;
      callback();
    }
  }
}

} // namespace Tls
} // namespace TransportSockets
} // namespace Extensions
} // namespace Envoy
