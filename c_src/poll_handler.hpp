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
    PollHandler() : command_index{-1}, sigchild_index{-1} {}
  
    void append_read_fd(int fd, FdType type = FdType::CHILD_PROC, bool error = false) {
        fds.push_back(pollfd{fd, (short) (error ? (POLLIN | POLLERR) : POLLIN), 0});
        switch (type) {
            case FdType::COMMAND:
                command_index = fds.size() - 1;
                break;
            case FdType::SIGCHILD:
                sigchild_index = fds.size() - 1;
                break;
            case FdType::CHILD_PROC:
                break;
        }
    }
    
    void append_write_fd(int fd) {
        fds.push_back(pollfd{fd, POLLOUT, 0});
    }
    
    void clear() {
        fds.clear();
        command_index  = -1;
        sigchild_index = -1;
    }
    
    size_t size() { return fds.size(); }
    
    int wait_for_event(const ei::TimeVal &timeout) {
        assert(!fds.empty());
        return poll(&fds.front(), fds.size(), timeout.millisec());
    }
    
    bool is_readable(FdType type, int index = -1) {
        switch (type) {
            case FdType::CHILD_PROC: return is_readable(index);
            case FdType::COMMAND:    return is_readable(command_index);
            case FdType::SIGCHILD:   return is_readable(sigchild_index);
            default:                 return false;
        }
    }
    
    bool is_error(FdType type, int index = -1) {
        switch (type) {
            case FdType::CHILD_PROC: return is_error(index);
            case FdType::COMMAND:    return is_error(command_index);
            case FdType::SIGCHILD:   return is_error(sigchild_index);
            default:                 return false;
        }
    }
   
    bool is_readable(int index) {
        assert(index < int(fds.size()));
        return index >= 0 && (fds[index].revents & (POLLIN|POLLHUP));
    }
    bool is_writable(int index) {
        assert(index < int(fds.size()));
        return index >= 0 && (fds[index].revents & POLLOUT);
    }
    bool is_error(int index) {
        assert(index < int(fds.size()));
        return index >= 0 && (fds[index].revents & POLLHUP);
    }
    
private:
    std::vector<pollfd> fds;
    ssize_t command_index;
    ssize_t sigchild_index;
};

using FdHandler = PollHandler;
