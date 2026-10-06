// vim:ts=4:sw=4:et
#pragma once

#include <cstddef>
#include <string>
#include <vector>

namespace ei {

// Duplicate a stream buffer to all destination FDs.
// Returns false on hard failure and sets error.
bool tee_buffer_to_many(const char* data,
                        size_t len,
                        const std::vector<int>& dst_fds,
                        std::string& error);

// Read from src_fd until EOF and fan out to all dst_fds.
// Prefers Linux tee/splice when available, and falls back to read/write fan-out.
bool tee_fanout_fd(int src_fd,
                   const std::vector<int>& dst_fds,
                   std::string& error,
                   size_t chunk_size = 65536);

} // namespace ei
