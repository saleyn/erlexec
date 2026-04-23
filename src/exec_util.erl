-module(exec_util).
-export([
    capability_to_index/1, index_to_capability/1, index_to_capability/2,
    is_capability_set/2, validate_capabilities/1
]).

-doc "Map capability names to their bit indices".
%% Based on /usr/include/linux/capability.h
%% sed -n 's/^#define \(CAP_.*\) .*/\1/p' /usr/include/linux/capability.h | tr A-Z a-z | sed 's/cap_//'

capability_to_index(chown)            -> 0;
capability_to_index(dac_override)     -> 1;
capability_to_index(dac_read_search)  -> 2;
capability_to_index(fowner)           -> 3;
capability_to_index(fsetid)           -> 4;
capability_to_index(kill)             -> 5;
capability_to_index(setgid)           -> 6;
capability_to_index(setuid)           -> 7;
capability_to_index(setpcap)          -> 8;
capability_to_index(linux_immutable)  -> 9;
capability_to_index(net_bind_service) -> 10;
capability_to_index(net_broadcast)    -> 11;
capability_to_index(net_admin)        -> 12;
capability_to_index(net_raw)          -> 13;
capability_to_index(ipc_lock)         -> 14;
capability_to_index(ipc_owner)        -> 15;
capability_to_index(sys_module)       -> 16;
capability_to_index(sys_rawio)        -> 17;
capability_to_index(sys_chroot)       -> 18;
capability_to_index(sys_ptrace)       -> 19;
capability_to_index(sys_pacct)        -> 20;
capability_to_index(sys_admin)        -> 21;
capability_to_index(sys_boot)         -> 22;
capability_to_index(sys_nice)         -> 23;
capability_to_index(sys_resource)     -> 24;
capability_to_index(sys_time)         -> 25;
capability_to_index(sys_tty_config)   -> 26;
capability_to_index(mknod)            -> 27;
capability_to_index(lease)            -> 28;
capability_to_index(audit_write)      -> 29;
capability_to_index(audit_control)    -> 30;
capability_to_index(setfcap)          -> 31;
capability_to_index(mac_override)     -> 32;
capability_to_index(mac_admin)        -> 33;
capability_to_index(syslog)           -> 34;
capability_to_index(wake_alarm)       -> 35;
capability_to_index(block_suspend)    -> 36;
capability_to_index(_)                -> -1.

-doc "Map bit indices back to capability names (with customizable default".
index_to_capability(0,  _) -> chown;
index_to_capability(1,  _) -> dac_override;
index_to_capability(2,  _) -> dac_read_search;
index_to_capability(3,  _) -> fowner;
index_to_capability(4,  _) -> fsetid;
index_to_capability(5,  _) -> kill;
index_to_capability(6,  _) -> setgid;
index_to_capability(7,  _) -> setuid;
index_to_capability(8,  _) -> setpcap;
index_to_capability(9,  _) -> linux_immutable;
index_to_capability(10, _) -> net_bind_service;
index_to_capability(11, _) -> net_broadcast;
index_to_capability(12, _) -> net_admin;
index_to_capability(13, _) -> net_raw;
index_to_capability(14, _) -> ipc_lock;
index_to_capability(15, _) -> ipc_owner;
index_to_capability(16, _) -> sys_module;
index_to_capability(17, _) -> sys_rawio;
index_to_capability(18, _) -> sys_chroot;
index_to_capability(19, _) -> sys_ptrace;
index_to_capability(20, _) -> sys_pacct;
index_to_capability(21, _) -> sys_admin;
index_to_capability(22, _) -> sys_boot;
index_to_capability(23, _) -> sys_nice;
index_to_capability(24, _) -> sys_resource;
index_to_capability(25, _) -> sys_time;
index_to_capability(26, _) -> sys_tty_config;
index_to_capability(27, _) -> mknod;
index_to_capability(28, _) -> lease;
index_to_capability(29, _) -> audit_write;
index_to_capability(30, _) -> audit_control;
index_to_capability(31, _) -> setfcap;
index_to_capability(32, _) -> mac_override;
index_to_capability(33, _) -> mac_admin;
index_to_capability(34, _) -> syslog;
index_to_capability(35, _) -> wake_alarm;
index_to_capability(36, _) -> block_suspend;
index_to_capability(_, Def)  -> Def.

-doc "Map bit indices back to capability names".
index_to_capability(I) -> index_to_capability(I, undefined).

-doc """
Check if a capability bit is set in hex value.

Hex value is a string like "0000003fffffffff" (read right to left, LSB first)

%% Example usage:
    is_capability_set("0000003fffffffff", kill) -> true
    is_capability_set("0000003fffffffff", sys_admin) -> false
""".
is_capability_set(Hex, CapName) when (is_list(Hex) orelse is_binary(Hex)), is_atom(CapName) ->
    case capability_to_index(CapName) of
        BitIndex when BitIndex < 0 ->
            false;
        BitIndex ->
            % Convert hex string to integer (handle as 64-bit number)
            % Reverse the string because the kernel shows them in a specific format
            HexInt = erlang:list_to_integer(Hex, 16),
            % Check if the bit at BitIndex is set
            (HexInt band (1 bsl BitIndex)) =/= 0
    end.

-doc """
Validate capability names and convert to proper format (cap_ prefix).

%% Example usage:
    validate_capabilities([cap_kill, cap_sys_admin]) -> [kill, sys_admin]
    validate_capabilities([kill, sys_admin]) -> [kill, sys_admin]
    validate_capabilities([invalid]) -> error({invalid_capability, invalid})
""".
validate_capabilities(CapList) when is_list(CapList) ->
    lists:map(fun(C) ->
        Cap =
            case atom_to_list(C) of
                "cap_" ++ Name -> Name;
                Other          -> Other
            end,
        maybe 
            {ok, ACap} ?= catch {ok, erlang:list_to_existing_atom(Cap)},
            Index = capability_to_index(ACap),
            true ?= (Index >= 0)
        else
            _ -> error({invalid_capability, C})
        end
    end, CapList).
