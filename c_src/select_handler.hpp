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
    };
    
    void clear_fds() {
        FD_ZERO(&writefds);
        FD_ZERO(&readfds);
        FD_ZERO(&errfds);
        maxfd = 0;
        command_fd = -1;
        sigchild_fd = -1;
    }
    
    void append_read_fd(int fd, FdType type = FdType::CHILD_PROC, bool _error = false) {
        FD_SET(fd, &readfds);
        if (fd > maxfd) {
            maxfd = fd;
        }
        switch (type) {
        case FdType::COMMAND:
            FD_SET(fd, &errfds);
            command_fd = fd;
            break;
        case FdType::SIGCHILD:
            sigchild_fd = fd;
            break;
        case FdType::CHILD_PROC: break;
        }
    }
    
    void append_write_fd(int fd) {
        FD_SET(fd, &writefds);
        if (fd > maxfd) {
            maxfd = fd;
        }
    }
    
    int wait_for_event(ei::TimeVal &timeout) {
        return select(maxfd+1, &readfds, &writefds, &errfds, &timeout);
    }
    
    bool is_readable(FdType type, int fd = -1) {
        if ((type == FdType::CHILD_PROC) && (fd >= 0)) {
            return FD_ISSET(fd, &readfds);
        }
        
        if ((type == FdType::COMMAND) && (command_fd >= 0)) {
            return FD_ISSET(command_fd, &readfds);
        }
        
        if ((type == FdType::SIGCHILD) && (sigchild_fd >= 0)) {
            return FD_ISSET(sigchild_fd, &readfds);;
        }
        
        return false;
    }
    
    bool is_error(FdType type, int fd = -1) {
        if ((type == FdType::CHILD_PROC) && (fd >= 0)) {
            return FD_ISSET(fd, &errfds);;
        }
        
        if ((type == FdType::COMMAND) && (command_fd >= 0)) {
            return FD_ISSET(command_fd, &errfds);
        }
        
        if ((type == FdType::SIGCHILD) && (sigchild_fd >= 0)) {
            return FD_ISSET(sigchild_fd, &errfds);;
        }
        
        return false;
    }
    
    bool is_writable(int fd) {
        if (fd < 0) {
            return false;
        }
        return FD_ISSET(fd, &writefds);
    }
    
    int size() const {
        return maxfd;
    }
    
private:
    fd_set readfds, writefds, errfds;
    int maxfd;
    int command_fd;
    int sigchild_fd;
};

using FdHandler = SelectHandler;
