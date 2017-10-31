#pragma once

#include <string>
#include <mutex>

#include "accesslog.pb.h"

#include "envoy/network/connection.h"
#include "envoy/http/access_log.h"
#include "envoy/http/header_map.h"
#include "envoy/router/router.h"
#include "common/common/logger.h"

namespace Envoy {
namespace Cilium {

  class AccessLog : Logger::Loggable<Logger::Id::router> {
  public:
    AccessLog(std::string path);
    ~AccessLog();

    void Log(std::string listener_id, ::pb::cilium::EntryType, const Network::Connection*, const Http::HeaderMap&, const Http::AccessLog::RequestInfo&, const Router::RouteEntry*);

  private:
    bool Connect();
    void Close();

    const std::string path_;
    std::mutex fd_mutex_;
    int fd_;
  };

  } // Cilium
} // Envoy
