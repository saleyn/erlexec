// vim:ts=4:sw=4:et
/*
Author: Christian Taedcke
Date:   2020-01-06
*/
#pragma once

#include "ei++.hpp"

struct SelectHandler {
    SelectHandler() : maxfd{0}, command_fd{-1}, sigchild_fd{-1} {
        FD_ZERO(&writefds);
        FD_ZERO(&readfds);
        FD_ZERO(&errfds);
    }
    
    void clear() { new (this) SelectHandler(); }
    
    void append_read_fd(int fd, FdType type = FdType::CHILD_PROC, bool _error = false) {
        FD_SET(fd, &readfds);
        if (fd > maxfd)
            maxfd = fd;
        switch (type) {
            case FdType::COMMAND:
                FD_SET(fd, &errfds);
                command_fd = fd;
                break;
            case FdType::SIGCHILD:
                sigchild_fd = fd;
                break;
            case FdType::CHILD_PROC:
                break;
        }
    }
    
    void append_write_fd(int fd) {
        FD_SET(fd, &writefds);
        if (fd > maxfd)
            maxfd = fd;
    }
    
    int wait_for_event(ei::TimeVal &timeout) {
        return select(maxfd+1, &readfds, &writefds, &errfds, &timeout);
    }
    
    bool is_readable(FdType type, int fd = -1) {
        switch (type) {
            case FdType::CHILD_PROC: return is_readable(fd);
            case FdType::COMMAND:    return is_readable(command_fd);
            case FdType::SIGCHILD:   return is_readable(sigchild_fd);
            default:                 return false;
        }
    }
    
    bool is_error(FdType type, int fd = -1) {
        switch (type) {
            case FdType::CHILD_PROC: return is_error(fd);
            case FdType::COMMAND:    return is_error(command_fd);
            case FdType::SIGCHILD:   return is_error(sigchild_fd);
            default:                 return false;
        }
    }
    
    bool is_readable(int fd) { return fd >= 0 && FD_ISSET(fd, &readfds);  }
    bool is_writable(int fd) { return fd >= 0 && FD_ISSET(fd, &writefds); }
    bool is_error   (int fd) { return fd >= 0 && FD_ISSET(fd, &errfds);   }
    
    int  size() const { return maxfd; }
    
private:
    fd_set readfds, writefds, errfds;
    int maxfd;
    int command_fd;
    int sigchild_fd;
};

using FdHandler = SelectHandler;
