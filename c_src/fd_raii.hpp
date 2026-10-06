// vim:ts=4:sw=4:et
#pragma once

#include <fcntl.h>
#include <sys/types.h>
#include <unistd.h>

#include <string>

namespace ei {

inline void close_fd_if_open(int& fd) noexcept
{
    if (fd >= 0) {
        ::close(fd);
        fd = -1;
    }
}

struct FileDescriptor {
    FileDescriptor() noexcept : m_fd(-1) {}

    FileDescriptor(const std::string& path, int flags, mode_t mode = 0) noexcept
      : m_fd(::open(path.c_str(), flags, mode)) {}

    FileDescriptor(const char* path, int flags, mode_t mode = 0) noexcept
      : m_fd(path ? ::open(path, flags, mode) : -1) {}

    ~FileDescriptor()
    {
        close_fd_if_open(m_fd);
    }

    FileDescriptor(const FileDescriptor&) = delete;
    FileDescriptor& operator=(const FileDescriptor&) = delete;

    FileDescriptor(FileDescriptor&& other) noexcept : m_fd(other.m_fd)
    {
        other.m_fd = -1;
    }

    FileDescriptor& operator=(FileDescriptor&& other) noexcept
    {
        if (this != &other) {
            close_fd_if_open(m_fd);
            m_fd = other.m_fd;
            other.m_fd = -1;
        }
        return *this;
    }

    int get() const noexcept { return m_fd; }
    explicit operator bool() const noexcept { return m_fd >= 0; }

    int release() noexcept
    {
        int fd = m_fd;
        m_fd = -1;
        return fd;
    }

private:
    int m_fd;
};

struct Pipe {
    Pipe() noexcept : m_read_fd(-1), m_write_fd(-1)
    {
        int fds[2] = {-1, -1};
        if (::pipe(fds) == 0) {
            m_read_fd = fds[0];
            m_write_fd = fds[1];
        }
    }

    ~Pipe()
    {
        close_fd_if_open(m_read_fd);
        close_fd_if_open(m_write_fd);
    }

    Pipe(const Pipe&)            = delete;
    Pipe& operator=(const Pipe&) = delete;

    Pipe(Pipe&& other) noexcept
    : m_read_fd(other.m_read_fd)
    , m_write_fd(other.m_write_fd)
    {
        other.m_read_fd  = -1;
        other.m_write_fd = -1;
    }

    Pipe& operator=(Pipe&& other) noexcept
    {
        if (this != &other) {
            close_fd_if_open(m_read_fd);
            close_fd_if_open(m_write_fd);
            m_read_fd        = other.m_read_fd;
            m_write_fd       = other.m_write_fd;
            other.m_read_fd  = -1;
            other.m_write_fd = -1;
        }
        return *this;
    }

    int  read_fd()  const noexcept { return m_read_fd; }
    int  write_fd() const noexcept { return m_write_fd; }
    bool valid()    const noexcept { return m_read_fd >= 0 && m_write_fd >= 0; }
private:
    int m_read_fd;
    int m_write_fd;
};

} // namespace ei
