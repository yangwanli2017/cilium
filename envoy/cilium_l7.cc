#include <string>

#include "cilium_l7.h"

#include "envoy/registry/registry.h"

#include "common/common/enum_to_int.h"

#include "server/config/network/http_connection_manager.h"

namespace Envoy {
namespace Cilium {

class ConfigFactory : public Server::Configuration::NamedHttpFilterConfigFactory {
public:
  Server::Configuration::HttpFilterFactoryCb createFilterFactory(const Json::Object& json, const std::string&,
                                          Server::Configuration::FactoryContext& context) override {
    Cilium::ConfigSharedPtr config(new Cilium::Config(json, context.scope()));
    return [config](Http::FilterChainFactoryCallbacks& callbacks) mutable -> void {
      callbacks.addStreamFilter(std::make_shared<Cilium::AccessFilter>(config));
    };
  }
  std::string name() override { return "cilium_l7"; }
  Server::Configuration::HttpFilterType type() override { return Server::Configuration::HttpFilterType::Both; }
};

/**
 * Static registration for this sample filter. @see RegisterFactory.
 */
static Registry::RegisterFactory<ConfigFactory, Server::Configuration::NamedHttpFilterConfigFactory>
    register_;

Config::Config(const Json::Object& config, Stats::Scope& scope)
  : stats_{ALL_CILIUM_STATS(POOL_COUNTER_PREFIX(scope, "cilium"))},
    access_log_(config.getString("access_log_path")),
    listener_id_(config.getString("listener_id")) {}

void AccessFilter::onDestroy() {}

Http::FilterHeadersStatus AccessFilter::decodeHeaders(Http::HeaderMap& headers, bool) {
  // Cilium configures security policy on route entries, whitelisting
  // allowed traffic. Return 403 if no route is found.
  auto route = request_callbacks_->route();
  if (!route) {
    denied_ = true;
    config_->stats_.access_denied_.inc();
    ENVOY_STREAM_LOG(debug, "access denied for URL '{}'", *request_callbacks_,
                     headers.Path()->value().c_str());

    config_->access_log_.Log(config_->listener_id_, ::pb::cilium::EntryType::Denied, request_callbacks_->connection(), headers, request_callbacks_->requestInfo(), nullptr);
      
    // Add new ResponseFlag for "adminitratively denied"?
    Http::HeaderMapPtr response_headers{new Http::HeaderMapImpl{
        {Http::Headers::get().Status, std::to_string(enumToInt(Http::Code::Forbidden))}}};
    request_callbacks_->encodeHeaders(std::move(response_headers), true);

    return Http::FilterHeadersStatus::StopIteration;
  }

  config_->access_log_.Log(config_->listener_id_, ::pb::cilium::EntryType::Request, request_callbacks_->connection(), headers, request_callbacks_->requestInfo(), route->routeEntry());

  return Http::FilterHeadersStatus::Continue;
}

Http::FilterHeadersStatus AccessFilter::encodeHeaders(Http::HeaderMap& headers, bool) {
  // Denied requests have already been logged
  if (!denied_) {
    auto route = request_callbacks_->route();
    auto routeEntry = route ? route->routeEntry() : nullptr;
  
    config_->access_log_.Log(config_->listener_id_, ::pb::cilium::EntryType::Response, request_callbacks_->connection(), headers, request_callbacks_->requestInfo(), routeEntry);
  }
  return Http::FilterHeadersStatus::Continue;
}

} // Cilium
} // Envoy
