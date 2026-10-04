#pragma once

#include <cstdint>
#include <functional>
#include <list>
#include <memory>
#include <vector>

#include "envoy/singleton/instance.h"
#include "envoy/ssl/context.h"
#include "envoy/thread_local/thread_local.h"

#include "absl/synchronization/mutex.h"

namespace Envoy {
namespace Extensions {
namespace TransportSockets {
namespace Tls {

/** Worker-local session registrations sharing a factory's current validation context. */
class SessionRevalidation : public Singleton::Instance {
  struct RegistrationState;
  struct Worker;
  using RegistrationList = std::list<std::weak_ptr<RegistrationState>>;

public:
  class Registration;

  struct Snapshot {
    Ssl::ContextSharedPtr context_;
    uint64_t generation_;
  };

  class Policy {
  public:
    explicit Policy(Ssl::ContextSharedPtr context) : current_{std::move(context), 1} {}

  private:
    friend class SessionRevalidation;
    friend class Registration;
    mutable absl::Mutex mutex_;
    Snapshot current_ ABSL_GUARDED_BY(mutex_);
  };
  using PolicySharedPtr = std::shared_ptr<Policy>;

  // Created, used and destroyed on the socket's worker. Destruction cancels the callback even
  // when a notification temporarily retains RegistrationState during a reentrant socket close.
  class Registration {
  public:
    Registration(const Registration&) = delete;
    Registration& operator=(const Registration&) = delete;
    ~Registration();
    Snapshot currentPolicy() const;

    // The function must only perform synchronous validation. It must not invoke connection
    // callbacks or publish policy while the reader lock is held.
    bool withCurrentPolicy(const std::function<bool(const Snapshot&)>& validate) const;

  private:
    friend class SessionRevalidation;
    Registration(std::shared_ptr<RegistrationState> state, std::weak_ptr<Worker> worker,
                 RegistrationList::iterator entry)
        : state_(std::move(state)), worker_(std::move(worker)), entry_(entry) {}
    const std::shared_ptr<RegistrationState> state_;
    const std::weak_ptr<Worker> worker_;
    const RegistrationList::iterator entry_;
  };
  using RegistrationPtr = std::unique_ptr<Registration>;

  explicit SessionRevalidation(ThreadLocal::Instance& tls);

  // Returns null on the main thread, unregistered threads or after global threading shutdown.
  RegistrationPtr registerSession(const PolicySharedPtr& policy, std::function<void()> callback);

  // Main thread only. After shutdown, refuses both publication and worker notification.
  bool publish(const PolicySharedPtr& policy, Ssl::ContextSharedPtr context);

private:
  struct RegistrationState {
    const PolicySharedPtr policy_;
    std::function<void()> callback_;
  };

  struct Worker : public ThreadLocal::ThreadLocalObject,
                  public std::enable_shared_from_this<Worker> {
    explicit Worker(bool enabled) : enabled_(enabled) {}
    void notify(const PolicySharedPtr& policy);
    const bool enabled_;
    RegistrationList registrations_;
  };

  ThreadLocal::TypedSlot<Worker> workers_;
};

} // namespace Tls
} // namespace TransportSockets
} // namespace Extensions
} // namespace Envoy
