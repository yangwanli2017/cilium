#include "accesslog.h"

#include <sys/socket.h>
#include <sys/un.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>

#include "common/common/utility.h"

namespace Envoy {
namespace Cilium {

  AccessLog::AccessLog(std::string path) : path_(path), fd_(-1) {}

  AccessLog::~AccessLog() {
    Close();
  }

  void AccessLog::Log(std::string listener_id, ::pb::cilium::EntryType entryType, const Network::Connection* conn, const Http::HeaderMap& headers, const Http::AccessLog::RequestInfo& info, const Router::RouteEntry* route) {
    ::pb::cilium::HttpLogEntry httpLogEntry{};

    auto time = info.startTime();
    if (entryType == ::pb::cilium::EntryType::Response) {
      time += info.duration();
    }
    httpLogEntry.set_timestamp(std::chrono::duration_cast<std::chrono::nanoseconds>(time.time_since_epoch()).count());

    ::pb::cilium::Protocol proto;
    switch (info.protocol()) {
    case Http::Protocol::Http10:
      proto = ::pb::cilium::Protocol::HTTP10;
      break;
    case Http::Protocol::Http11:
    default: // Just to make compiler happy
      proto = ::pb::cilium::Protocol::HTTP11;
      break;
    case Http::Protocol::Http2:
      proto = ::pb::cilium::Protocol::HTTP2;
      break;
    }
    httpLogEntry.set_http_protocol(proto);

    httpLogEntry.set_entry_type(entryType);

    httpLogEntry.set_cilium_resource_name(listener_id);

    // Get rule reference from the opaque config of the route entry
    if (route) {
      auto ocmap = route->opaqueConfig();
      auto it = ocmap.find("cilium_rule_ref");
      if (it != ocmap.end()) {
	httpLogEntry.set_cilium_rule_ref(it->second);
      }
    }

    if (conn) {
      httpLogEntry.set_source_security_id(conn->socketMark() & 0xffff);
      httpLogEntry.set_source_address(conn->remoteAddress().asString());
      httpLogEntry.set_destination_address(conn->localAddress().asString());
    }

    auto rc = info.responseCode();
    if (rc.valid()) {
      httpLogEntry.set_response_code(rc.value());
    }

    // headers
    headers.iterate([] (const Http::HeaderEntry& header, void* entry_) -> void {
	::pb::cilium::KeyValue* kv = static_cast<::pb::cilium::HttpLogEntry*>(entry_)->add_headers();
	kv->set_key(header.key().c_str());
	kv->set_value(header.value().c_str());
      }, &httpLogEntry);

    if (Connect()) {
      // encode protobuf
      std::string msg;
      httpLogEntry.SerializeToString(&msg);
      ssize_t length = msg.length();
      ssize_t sent = ::send(fd_, msg.data(), length, MSG_DONTWAIT | MSG_EOR | MSG_NOSIGNAL);
      if (sent == length) {
	ENVOY_LOG(debug, "Cilium access msg sent: {}", httpLogEntry.DebugString());
	return;
      }
      if (sent == -1) {
	ENVOY_LOG(warn, "Cilium access log send failed: {}", strerror(errno));
      } else {
	ENVOY_LOG(warn, "Cilium access log send truncated by {} bytes.", length - sent);
      }
    }
    // Log the message in Envoy logs if it could not be sent to Cilium
    ENVOY_LOG(debug, "Cilium access log msg: {}", httpLogEntry.DebugString());
  }

  void AccessLog::Close() {
    std::lock_guard<std::mutex> guard(fd_mutex_);
    if (fd_ != -1) {
      ::close(fd_);
      fd_ = -1;
    }
  }

  bool AccessLog::Connect() {
    if (fd_ != -1) {
      return true;
    }
    if (path_.length() == 0) {
      return false;
    }
    std::lock_guard<std::mutex> guard(fd_mutex_);
    
    fd_ = ::socket(AF_UNIX, SOCK_SEQPACKET, 0);
    if (fd_ == -1) {
      ENVOY_LOG(warn, "Can't create socket: {}", strerror(errno));
      return false;
    }
    
    struct sockaddr_un addr = { .sun_family = AF_UNIX, .sun_path = {} };
    strncpy(addr.sun_path, path_.c_str(), sizeof(addr.sun_path) - 1);
    if (::connect(fd_, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) == -1) {
      ENVOY_LOG(warn, "Connect to {} failed: {}", path_, strerror(errno));
      ::close(fd_);
      fd_ = -1;
      return false;
    }

    return true;
  }
  
  } // Cilium
} // Envoy
