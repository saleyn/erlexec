#pragma once
#include "graph_tee.hpp"
#include "fd_raii.hpp"

#include <cerrno>
#include <cstring>
#include <unistd.h>

#ifdef __linux__
#include <fcntl.h>
#endif

namespace ei {

static bool write_all(int fd, const char* data, size_t len, std::string& error)
{
  size_t pos = 0;
  while (pos < len) {
    ssize_t n = ::write(fd, data + pos, len - pos);
    if (n > 0) {
      pos += static_cast<size_t>(n);
      continue;
    }
    if (n < 0 && errno == EINTR)
      continue;
    error = std::string("tee write failed: ") + std::strerror(errno);
    return false;
  }
  return true;
}

bool tee_buffer_to_many(
  const char*             data,
  size_t                  len,
  const std::vector<int>& dst_fds,
  std::string&            error)
{
  for (int fd : dst_fds) {
    if (fd < 0)
      continue;
    if (!write_all(fd, data, len, error))
      return false;
  }
  return true;
}

#ifdef __linux__
static bool tee_linux_splice(
  int                     src_fd,
  const std::vector<int>& dst_fds,
  std::string&            error,
  size_t                  chunk_size)
{
  if (dst_fds.empty())
    return true;

  Pipe staging;
  if (!staging.valid()) {
    error = std::string("tee staging pipe failed: ") + std::strerror(errno);
    return false;
  }

  while (true) {
    // Move from source into staging pipe.
    ssize_t moved = ::splice(src_fd, nullptr, staging.write_fd(), nullptr, chunk_size, 0);
    if (moved == 0) {
      break; // EOF
    }
    if (moved < 0) {
      if (errno == EINTR)
        continue;
      error = std::string("splice from source failed: ") + std::strerror(errno);
      return false;
    }

    // Clone payload to all but last destination using tee(2).
    for (size_t i = 0; i + 1 < dst_fds.size(); ++i) {
      int dfd = dst_fds[i];
      if (dfd < 0)
        continue;

      size_t left = static_cast<size_t>(moved);
      while (left > 0) {
        ssize_t t = ::tee(staging.read_fd(), dfd, left, 0);
        if (t > 0) {
          left -= static_cast<size_t>(t);
          continue;
        }
        if (t < 0 && errno == EINTR)
          continue;
        error = std::string("tee to destination failed: ") + std::strerror(errno);
        return false;
      }
    }

    // Drain the original bytes to the last destination.
    int last_fd = dst_fds.back();
    if (last_fd >= 0) {
      size_t left = static_cast<size_t>(moved);
      while (left > 0) {
        ssize_t s = ::splice(staging.read_fd(), nullptr, last_fd, nullptr, left, 0);
        if (s > 0) {
          left -= static_cast<size_t>(s);
          continue;
        }
        if (s < 0 && errno == EINTR)
          continue;
        error = std::string("splice to destination failed: ") + std::strerror(errno);
        return false;
      }
    }
  }
  return true;
}
#endif

bool tee_fanout_fd(
  int                     src_fd,
  const std::vector<int>& dst_fds,
  std::string&            error,
  size_t                  chunk_size)
{
  if (src_fd < 0) {
    error = "tee source fd is invalid";
    return false;
  }

  if (dst_fds.empty()) {
    // Nothing to fan out to, drain input.
    char discard[8192];
    while (true) {
      ssize_t n = ::read(src_fd, discard, sizeof(discard));
      if (n > 0)
        continue;
      if (n == 0)
        return true;
      if (errno == EINTR)
        continue;
      error = std::string("tee drain read failed: ") + std::strerror(errno);
      return false;
    }
  }

#ifdef __linux__
  if (tee_linux_splice(src_fd, dst_fds, error, chunk_size))
    return true;
  // fall through to portable fallback on any runtime failure
#endif

  std::vector<char> buf(chunk_size > 0 ? chunk_size : 65536);
  while (true) {
    ssize_t n = ::read(src_fd, buf.data(), buf.size());
    if (n > 0) {
      if (!tee_buffer_to_many(buf.data(), static_cast<size_t>(n), dst_fds, error))
        return false;
      continue;
    }
    if (n == 0)
      return true;
    if (errno == EINTR)
      continue;
    error = std::string("tee read failed: ") + std::strerror(errno);
    return false;
  }
}

} // namespace ei
