// vim:ts=4:sw=4:et
/*
Author: Christian Taedcke
Date:   2020-01-06
*/
#pragma once

#include <sys/poll.h>
#include <vector>

#include "ei++.hpp"

struct PollHandler {
    PollHandler() : command_index{-1}, sigchild_index{-1} {};
  
    void append_read_fd(int fd, FdType type = FdType::CHILD_PROC, bool error = false) {
        fds.push_back(pollfd{fd, (short) (error ? (POLLIN | POLLERR) : POLLIN), 0});
        switch (type) {
        case FdType::COMMAND:
            command_index = fds.size() - 1;
            break;
        case FdType::SIGCHILD:
            sigchild_index = fds.size() - 1;
            break;
        case FdType::CHILD_PROC: break;
        }
    }
    
    void append_write_fd(int fd) {
        fds.push_back(pollfd{fd, POLLOUT, 0});
    }
    
    void clear_fds() {
        fds.clear();
        command_index = -1;
        sigchild_index = -1;
    }
    
    size_t size() {
        return fds.size();
    }
    
    int wait_for_event(const ei::TimeVal &timeout) {
        return poll(&fds[0], fds.size(), timeout.millisec());
    }
    
    bool is_readable(FdType type, int index = -1) {
        if ((type == FdType::CHILD_PROC) && (index >= 0)) {
            return fds[index].revents & (POLLIN|POLLHUP);
        }
        
        if ((type == FdType::COMMAND) && (command_index >= 0)) {
            return fds[command_index].revents & (POLLIN|POLLHUP);
        }
        
        if ((type == FdType::SIGCHILD) && (sigchild_index >= 0)) {
            return fds[sigchild_index].revents & (POLLIN|POLLHUP);
        }
        
        return false;
    }
    
    bool is_error(FdType type, int index = -1) {
        if ((type == FdType::CHILD_PROC) && (index >= 0)) {
            return fds[index].revents & POLLHUP;
        }
        
        if ((type == FdType::COMMAND) && (command_index >= 0)) {
            return fds[command_index].revents & POLLHUP;
        }
        
        if ((type == FdType::SIGCHILD) && (sigchild_index >= 0)) {
            return fds[sigchild_index].revents & POLLHUP;
        }
        
        return false;
    }
    
    bool is_writable(int index) {
        assert(index < int(fds.size()));
        return fds[index].revents & POLLOUT;
    }
    
private:
    std::vector<pollfd> fds;
    ssize_t command_index;
    ssize_t sigchild_index;
};

using FdHandler = PollHandler;
