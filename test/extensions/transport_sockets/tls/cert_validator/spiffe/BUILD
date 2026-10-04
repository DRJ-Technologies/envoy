load(
    "//bazel:envoy_build_system.bzl",
    "envoy_cc_test_library",
    "envoy_package",
)
load(
    "//test/extensions:extensions_build_system.bzl",
    "envoy_extension_cc_test",
)

licenses(["notice"])  # Apache 2

filegroup(
    name = "test_data",
    srcs = glob(["test_data/*"]),
)

envoy_package()

envoy_extension_cc_test(
    name = "session_revalidation_tls_test",
    srcs = ["session_revalidation_tls_test.cc"],
    data = ["//test/common/tls/test_data:certs"],
    extension_names = ["envoy.tls.cert_validator.spiffe"],
    external_deps = ["ssl"],
    deps = [
        "//envoy/secret:secret_provider_interface",
        "//source/common/api:api_lib",
        "//source/common/buffer:buffer_lib",
        "//source/common/common:callback_impl_lib",
        "//source/common/event:dispatcher_lib",
        "//source/common/network:listen_socket_lib",
        "//source/common/network:listener_lib",
        "//source/common/network:transport_socket_options_lib",
        "//source/common/singleton:manager_impl_lib",
        "//source/common/stream_info:stream_info_lib",
        "//source/common/thread_local:thread_local_lib",
        "//source/common/tls:context_config_lib",
        "//source/common/tls:context_lib",
        "//source/common/tls:server_context_config_lib",
        "//source/common/tls:ssl_handshaker_lib",
        "//source/common/tls:ssl_socket_lib",
        "//source/extensions/transport_sockets/tls/cert_validator/spiffe:config",
        "//test/mocks/runtime:runtime_mocks",
        "//test/mocks/secret:secret_mocks",
        "//test/mocks/server:server_factory_context_mocks",
        "//test/test_common:environment_lib",
        "//test/test_common:network_utility_lib",
        "//test/test_common:registry_lib",
        "//test/test_common:simulated_time_system_lib",
        "//test/test_common:thread_factory_for_test_lib",
        "//test/test_common:utility_lib",
        "@abseil-cpp//absl/strings",
        "@abseil-cpp//absl/synchronization",
        "@envoy_api//envoy/extensions/transport_sockets/tls/v3:pkg_cc_proto",
    ],
)

envoy_extension_cc_test(
    name = "spiffe_validator_test",
    srcs = [
        "spiffe_validator_test.cc",
    ],
    data = [
        "//test/common/tls/test_data:certs",
        "//test/extensions/transport_sockets/tls/cert_validator/spiffe:test_data",
    ],
    extension_names = ["envoy.tls.cert_validator.spiffe"],
    rbe_pool = "6gig",
    deps = [
        "//source/common/network:transport_socket_options_lib",
        "//source/common/router:string_accessor_lib",
        "//source/common/stream_info:filter_state_lib",
        "//source/extensions/transport_sockets/tls/cert_validator/spiffe:config",
        "//test/common/tls:ssl_test_utils",
        "//test/common/tls/cert_validator:test_common",
        "//test/common/tls/test_data:cert_infos",
        "//test/mocks/network:network_mocks",
        "//test/mocks/server:server_factory_context_mocks",
        "//test/test_common:environment_lib",
        "//test/test_common:simulated_time_system_lib",
        "//test/test_common:status_utility_lib",
        "//test/test_common:test_runtime_lib",
        "//test/test_common:utility_lib",
    ],
)

envoy_cc_test_library(
    name = "spiffe_validator_integration_test_lib",
    hdrs = ["spiffe_validator_integration_test.h"],
)

envoy_extension_cc_test(
    name = "spiffe_validator_integration_test",
    size = "large",
    srcs = ["spiffe_validator_integration_test.cc"],
    data = [
        "//test/common/tls/test_data:certs",
        "//test/config/integration/certs",
    ],
    extension_names = [
        "envoy.filters.listener.set_filter_state",
        "envoy.tls.cert_validator.spiffe",
    ],
    rbe_pool = "6gig",
    # Broken until bazel 5.0.0 fix to shorten resulting paths for SymInitialize() failure
    tags = ["skip_on_windows"],
    deps = [
        ":spiffe_validator_integration_test_lib",
        "//source/common/network:transport_socket_options_lib",
        "//source/common/router:string_accessor_lib",
        "//source/common/stream_info:filter_state_lib",
        "//source/extensions/filters/listener/set_filter_state:config",
        "//source/extensions/transport_sockets/tls/cert_validator/spiffe:config",
        "//test/integration:http_integration_lib",
        "//test/test_common:utility_lib",
    ],
)
