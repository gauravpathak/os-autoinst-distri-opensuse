# SUSE's openQA tests
#
# Copyright 2023-2026 SUSE LLC
# SPDX-License-Identifier: FSFAP
#
# Summary: Multimachine IPsec test verifying connectivity, routing,
#          tunnel/transport mode operation, and PMTUD across a
#          three-host IPv4 or IPv6 topology.
#
# Maintainer: Kernel QE <kernel-qa@suse.de>

package ipsec3hosts;
use Mojo::Base 'opensusebasetest';
use testapi;
use serial_terminal 'select_serial_terminal';
use utils;
use lockapi;
use network_utils;
use package_utils 'install_package';
use Utils::Logging 'export_logs';
use Kernel::net_tests qw(
  add_ip_addr
  add_ip_route
  check_ip_addr
  get_net_prefix_len
  config_ipsec
  dump_ipsec_debug
  validate_tcpdump
  start_packet_capture
  stop_packet_capture
  read_packet_capture
);

# Packets the middle/router has to show per test phase: the ESP traffic
# between left and right, and the PMTUD replies it generates itself.
use constant CAPTURE_FILTER => 'esp or icmp or icmp6';
# Headers are enough for the ESP SPI and the PMTUD wording, so keep the
# pcap small enough to decode over the serial console
use constant CAPTURE_SNAPLEN => 128;

=head2 phase_pcap

 my $pcap = phase_pcap('test04', $dev);

Path of the pcap file of one test phase on one interface.

=cut

sub phase_pcap {
    my ($phase, $dev) = @_;
    return "/tmp/ipsec-$phase-$dev.pcap";
}

=head2 start_phase_capture

 start_phase_capture('test04', $dev0, $dev1);

Start a background tcpdump per interface for one test phase. Call this
B<before> the barrier that lets the endpoints generate the traffic of
the phase, and C<stop_phase_capture> after the barrier they reach when
that traffic is over. The capture then provably spans the whole phase,
unlike a fixed C<capture_tcpdump> duration that may start late, end
early or reach into the next phase.

=cut

sub start_phase_capture {
    my ($phase, @devs) = @_;
    my $pcaps = join(' ', map { phase_pcap($phase, $_) } @devs);
    my $logs = join(' ', map { phase_pcap($phase, $_) . '.log' } @devs);

    script_run("rm -f $pcaps $logs");
    start_packet_capture($_, phase_pcap($phase, $_), CAPTURE_FILTER, snaplen => CAPTURE_SNAPLEN) for @devs;
    # tcpdump needs a moment to open the devices, do not race the barrier
    # that releases the traffic of the phase
    sleep 2;
    record_info("capture $phase", script_output("ps -ef | grep -e '[t]cpdump'; head -v -n 5 $logs", proceed_on_failure => 1));
}

=head2 stop_phase_capture

 stop_phase_capture('test04', dev => $dev0, check => ['esp', 'pmtud'], ...);

Stop the captures started by C<start_phase_capture> and validate the
capture of one interface. The remaining arguments are passed to
C<validate_tcpdump>.

=cut

sub stop_phase_capture {
    my ($phase, %args) = @_;

    stop_packet_capture;
    return validate_phase_capture($phase, %args);
}

=head2 validate_phase_capture

 validate_phase_capture('test04', dev => $dev1, check => ['esp'], ...);

Decode the pcap of one interface of an already stopped phase capture and
run C<validate_tcpdump> on it.

=cut

sub validate_phase_capture {
    my ($phase, %args) = @_;

    validate_tcpdump(dump => read_packet_capture(phase_pcap($phase, $args{dev})), %args);
}

sub run_left {
    my ($self, $setup) = @_;
    my $ip_version = $setup->{ip_version};

    # hash for the ipsec config
    my $ipsec_setting_left = {
        local_ip => $setup->{left_ip},
        remote_ip => $setup->{right_ip},
        new_local_net => $setup->{left_net},
        new_remote_net => $setup->{right_net},
    };

    add_ip_addr(
        ip_version => $ip_version,
        ip => $setup->{left_ip},
        plen => get_net_prefix_len(net => $setup->{left_net})
    );
    check_ip_addr(ip_version => $ip_version);

    barrier_wait('IPSEC_IP_SETUP_DONE');

    # first traffic test/check. At this point it should be possible to
    # ping the middle. So ping the middle router interface on the same subnet
    record_info("Test01: connectivity", "Ping router/middle host");
    script_retry("ping -c 1 $setup->{middle_ip_01}", retry => 5);
    record_info('IP NEIGHBOR', script_output('ip neighbor show'));

    add_ip_route(
        ip_version => $ip_version,
        dst => $setup->{right_ip},
        via => $setup->{middle_ip_01}
    );

    barrier_wait('IPSEC_ROUTE_SETUP_DONE');

    record_info('IP ADDRESS', script_output('ip a'));
    record_info('IP ROUTE', script_output($setup->{route_cmd}));

    # second test/check. Routs added, at this point it should be possible to
    # ping the right and the net interface in the middle from the other subnet
    record_info("Test02: connectivity", "Ping router/middle host and right host");
    script_retry("ping -c 1 $setup->{middle_ip_01}", retry => 5);
    script_retry("ping -c 1 $setup->{right_ip}", retry => 5);

    barrier_wait('IPSEC_ROUTE_SETUP_CHECK_DONE');

    # apply ipsec configs
    config_ipsec(%$ipsec_setting_left);

    barrier_wait('IPSEC_TUNNEL_MODE_SETUP_DONE');
    dump_ipsec_debug(ip_version => $ip_version);

    # third tests using ipsec. Basic check to see if it's possible to
    # ping the right using ipsec encryption. Default MTU-size packages as well
    # as 1300 MTU size
    record_info("Test03: mode tunnel", "Ping over ipsec");
    assert_script_run("ping -c 8 $setup->{right_ip}");
    assert_script_run("$setup->{mtu_ping_cmd} -s 1300 -c 8 $setup->{right_ip}");

    # tell the middle that the tunnel mode traffic is over, so that it can
    # evaluate its capture and only then lower the MTU
    barrier_wait('IPSEC_TUNNEL_MODE_TRAFFIC_DONE');
    barrier_wait('IPSEC_SET_MTU_DONE');

    # fourth test/check. Here the middle/router lowers the MTU to 1300. The left host
    # still sends packets using the default MTU, so oversized packets should trigger
    # Path MTU Discovery (PMTUD). The test verifies that ICMP(v6) Packet-Too-Big /
    # Fragmentation-Needed messages are handled correctly and the sender adjusts
    # to the lower MTU.
    # Only the first oversized packet probes the path, see mtu_ping_cmd below,
    # so the router answers exactly once per phase
    record_info("Test04: MTU", "MTU size in the middle decreased");
    assert_script_run("$setup->{ping_cmd} -c 8 $setup->{right_ip}");
    assert_script_run("$setup->{mtu_ping_cmd} -s 1300 -c 20 $setup->{right_ip}");

    barrier_wait('IPSEC_TUNNEL_MODE_CHECK_DONE');

    # mode changed from tunnel to transport
    config_ipsec(%$ipsec_setting_left, mode => 'transport');

    barrier_wait('IPSEC_TRANSPORT_MODE_SETUP_DONE');
    #dump the xfrm to see if correct mode is there
    dump_ipsec_debug(ip_version => $ip_version);

    # fifth test. Corresponding test as the 04 however the transport mode
    # is being used
    record_info("Test05: mode transport", "Use transport mode of ipsec");
    assert_script_run("$setup->{ping_cmd} -c 8 $setup->{right_ip}");
    assert_script_run("$setup->{mtu_ping_cmd} -s 1300 -c 8 $setup->{right_ip}");

    barrier_wait('IPSEC_TRANSPORT_MODE_CHECK_DONE');
}

sub run_middle {
    my ($self, $setup) = @_;
    my $ip_version = $setup->{ip_version};

    my ($dev0, $dev1) = split("\n", iface(2));

    assert_script_run("sysctl $setup->{forward_sysctl}");
    assert_script_run("ip link set $dev0 up");
    assert_script_run("ip link set $dev1 up");

    add_ip_addr(
        ip_version => $ip_version,
        ip => $setup->{middle_ip_01},
        dev => $dev0,
        plen => get_net_prefix_len(net => $setup->{middle_net_01})
    );

    add_ip_addr(
        ip_version => $ip_version,
        ip => $setup->{middle_ip_02},
        dev => $dev1,
        plen => get_net_prefix_len(net => $setup->{middle_net_02})
    );

    check_ip_addr(ip_version => $ip_version);

    # basic connectivity checks. At this point it should be possible
    # to ping left and right from the the middle
    script_retry("ping -c 1 $setup->{left_ip}", retry => 5);
    script_retry("ping -c 1 $setup->{right_ip}", retry => 5);

    record_info('IP NEIGHBOR', script_output('ip neighbor show'));

    barrier_wait('IPSEC_IP_SETUP_DONE');
    barrier_wait('IPSEC_ROUTE_SETUP_DONE');

    record_info('IP ADDRESS', script_output('ip a'));
    record_info('IP ROUTE', script_output($setup->{route_cmd}));

    barrier_wait('IPSEC_ROUTE_SETUP_CHECK_DONE');

    # The capture has to be running before the endpoints are released into
    # the test phase, and it is evaluated only after they report the phase
    # traffic as finished
    start_phase_capture('test03', $dev0, $dev1);

    barrier_wait('IPSEC_TUNNEL_MODE_SETUP_DONE');
    barrier_wait('IPSEC_TUNNEL_MODE_TRAFFIC_DONE');

    # Test03
    record_info("Test03: mode tunnel", "Ping over ipsec");
    # We expect here (at least):
    # ESP
    # spi 0x26c44388

    # validate first net device
    stop_phase_capture('test03', check => ['esp'], spi => "0x26c44388", dev => $dev0, ip_version => $ip_version,);

    # validate second net device
    validate_phase_capture('test03', check => ['esp'], spi => "0x26c44388", dev => $dev1, ip_version => $ip_version,);

    assert_script_run("ip link set mtu 1300 dev $dev1");

    start_phase_capture('test04', $dev0, $dev1);

    barrier_wait('IPSEC_SET_MTU_DONE');
    barrier_wait('IPSEC_TUNNEL_MODE_CHECK_DONE');

    # Test04
    record_info("Test04: MTU", "MTU size in the middle decreased");
    # We expect here (at least):
    # ESP
    # spi 0x26c44388
    # packet too big / fragmentation needed
    # ICMP6 Packet Too Big (ipv6) or ICMP need-to-frag (ipv4)
    #
    # The PMTUD reply is a single packet, emitted when left sends its first
    # oversized packet. Only a capture that spans the whole phase is
    # guaranteed to contain it.

    # validate first net device; here we check for pmtud
    stop_phase_capture('test04', check => ['esp', 'pmtud'], spi => "0x26c44388", mtu => 1300, dev => $dev0, ip_version => $ip_version,);

    # validate second net device; here pmtud won't be present
    validate_phase_capture('test04', check => ['esp'], spi => "0x26c44388", dev => $dev1, ip_version => $ip_version,);

    # TODO:
    # The same IPs are currently used as both tunnel endpoints and
    # communicating hosts. Because the outer IP header is identical
    # in both modes, tcpdump cannot distinguish tunnel from transport
    # mode. To validate this properly, the topology must use:
    #
    #   - host IPs inside each subnet (e.g. ::A, ::B for ipv6, .A, .B for ipv4)
    #   - tunnel endpoint IPs used only for XFRM src/dst
    #
    # With subnet-based selectors, tunnel-mode packets would originate
    # from the tunnel endpoints, while transport-mode packets would come
    # from host IPs. Only then can tcpdump validation differentiate modes.

    start_phase_capture('test05', $dev0, $dev1);

    barrier_wait('IPSEC_TRANSPORT_MODE_SETUP_DONE');
    barrier_wait('IPSEC_TRANSPORT_MODE_CHECK_DONE');

    # Test05
    record_info("Test05: mode transport", "Use transport mode of ipsec");
    # We expect here (for now):
    # ESP
    # spi 0x26c44388

    # validate first net device
    stop_phase_capture('test05', check => ['esp'], spi => "0x26c44388", dev => $dev0, ip_version => $ip_version,);

    # validate second net device
    validate_phase_capture('test05', check => ['esp'], spi => "0x26c44388", dev => $dev1, ip_version => $ip_version,);
}

sub run_right {
    my ($self, $setup) = @_;
    my $ip_version = $setup->{ip_version};

    # hash for the ipsec config
    my $ipsec_setting_right = {
        local_ip => $setup->{right_ip},
        remote_ip => $setup->{left_ip},
        new_local_net => $setup->{right_net},
        new_remote_net => $setup->{left_net},
    };

    my $dev0 = iface();

    add_ip_addr(
        ip_version => $ip_version,
        ip => $setup->{right_ip},
        plen => get_net_prefix_len(net => $setup->{right_net})
    );

    check_ip_addr(ip_version => $ip_version);
    barrier_wait('IPSEC_IP_SETUP_DONE');

    # basic connectivity check. Here it should be possible to ping
    # middle, the network interface from the same subnet as the right one
    script_retry("ping -c 1 $setup->{middle_ip_02}", retry => 5);

    record_info('IP NEIGHBOR', script_output('ip neighbor show'));

    add_ip_route(
        ip_version => $ip_version,
        dst => $setup->{left_ip},
        via => $setup->{middle_ip_02}
    );

    barrier_wait('IPSEC_ROUTE_SETUP_DONE');

    record_info('IP ADDRESS', script_output('ip a'));
    record_info('IP ROUTE', script_output($setup->{route_cmd}));

    # basic connectivity check. Routes are set, so it should be possible
    # to ping middle network interface from the other subnet as well as
    # the left one
    script_retry("ping -c 1 $setup->{middle_ip_02}", retry => 5);
    script_retry("ping -c 1 $setup->{left_ip}", retry => 5);

    barrier_wait('IPSEC_ROUTE_SETUP_CHECK_DONE');

    # applying ipsec config
    config_ipsec(%$ipsec_setting_right);

    barrier_wait('IPSEC_TUNNEL_MODE_SETUP_DONE');

    script_run("timeout 20 tcpdump -i $dev0");

    barrier_wait('IPSEC_TUNNEL_MODE_TRAFFIC_DONE');
    barrier_wait('IPSEC_SET_MTU_DONE');

    script_run("timeout 20 tcpdump -i $dev0");

    barrier_wait('IPSEC_TUNNEL_MODE_CHECK_DONE');

    # switching the ipsec mode to transport
    config_ipsec(%$ipsec_setting_right, mode => 'transport');

    barrier_wait('IPSEC_TRANSPORT_MODE_SETUP_DONE');

    script_run("timeout 20 tcpdump -i $dev0");

    barrier_wait('IPSEC_TRANSPORT_MODE_CHECK_DONE');
}

sub run {
    my ($self) = @_;

    my $role = get_var('IPSEC_SETUP');
    my $ip_version = lc(get_var('IPSEC_IP_VERSION', 'ipv6'));
    select_serial_terminal;

    my %setups = (
        ipv6 => {
            left_ip => "2001:1:1:1::2",
            right_ip => "2002:1:1:1::2",
            left_net => "2001:1:1:1::/64",
            right_net => "2002:1:1:1::/64",
            middle_ip_01 => "2001:1:1:1::1",
            middle_ip_02 => "2002:1:1:1::1",
            middle_net_01 => "2001:1:1:1::/64",
            middle_net_02 => "2002:1:1:1::/64",
            route_cmd => 'ip -6 route',
            ping_cmd => 'ping6',
            mtu_ping_cmd => 'ping6',
            forward_sysctl => 'net.ipv6.conf.all.forwarding=1',
        },
        ipv4 => {
            # Kept outside l2tp3hosts.pm's 10.1.x.x ranges: both test modules
            # run back-to-back in the same multimachine schedule
            # (schedule/ipsec/multi_machine_ipsec_3hosts.yaml) on the same
            # NICs, so the subnets must not collide.
            left_ip => "10.10.1.2",
            right_ip => "10.10.2.2",
            left_net => "10.10.1.0/24",
            right_net => "10.10.2.0/24",
            middle_ip_01 => "10.10.1.1",
            middle_ip_02 => "10.10.2.1",
            middle_net_01 => "10.10.1.0/24",
            middle_net_02 => "10.10.2.0/24",
            route_cmd => 'ip -4 route',
            ping_cmd => 'ping',
            # IP_PMTUDISC_WANT: the first oversized packet goes out with DF
            # and makes the router answer with Fragmentation Needed, the rest
            # are fragmented locally once the PMTU exception is cached. -M do
            # would not probe more often, it only turns the later packets into
            # a local EMSGSIZE, which would make assert_script_run fail.
            mtu_ping_cmd => 'ping -M want',
            forward_sysctl => 'net.ipv4.ip_forward=1',
        },
    );

    unless (exists $setups{$ip_version}) {
        record_info('IPSEC_IP_VERSION', "Unknown value '$ip_version', defaulting to ipv6");
        $ip_version = 'ipv6';
    }

    my $setup = $setups{$ip_version};
    $setup->{ip_version} = $ip_version;

    record_info('IPSEC_SETUP', $role);
    record_info('IPSEC_IP_VERSION', $ip_version);

    record_info('nmcli connect status', script_output('nmcli c'));
    record_info('nmcli device status', script_output('nmcli device s'));
    record_info('ip status', script_output('ip a'));
    record_info('INTF STATUS', script_output('ip -s link show', proceed_on_failure => 1));

    if ($role eq 'left') { $self->run_left($setup); }
    if ($role eq 'middle') { $self->run_middle($setup); }
    if ($role eq 'right') { $self->run_right($setup); }
}

sub pre_run_hook {
    my ($self) = @_;
    mutex_wait 'support_server_ready';
    select_serial_terminal;
    record_info('/etc/machine-id', script_output('cat /etc/machine-id'));
    record_info('nmcli connect status', script_output('nmcli c'));
    record_info('nmcli device status', script_output('nmcli device s'));
    record_info('ip status', script_output('ip a'));
    quit_packagekit();
    ensure_service_disabled('apparmor');
    ensure_service_disabled($self->firewall);
    set_hostname(get_var('HOSTNAME', 'susetest'), restart_network => 1);

    install_package('tcpdump', trup_apply => 1);
}

sub post_fail_hook {
    my ($self) = @_;
    export_logs();
    record_info('INTF STATUS', script_output('ip -s link show', proceed_on_failure => 1));
    # keep the phase captures of the middle/router for offline analysis, the
    # decoded text in the test details only shows the filtered packets
    stop_packet_capture;
    my @pcaps = grep { m{^/tmp/ipsec-} } split(/\s+/, script_output('ls /tmp/ipsec-*.pcap 2>/dev/null', proceed_on_failure => 1));
    upload_logs($_, failok => 1) foreach @pcaps;
}

1;

=head1 Description

ipsec3hosts - Multimachine IPsec test validating routing, ESP traffic,
PMTUD, and tunnel/transport mode operation across a three-host topology,
over either IPv6 (default) or IPv4.

This module implements a full three-host IPsec test environment. The
address family is selected with the C<IPSEC_IP_VERSION> openQA variable
(C<ipv6>, the default, or C<ipv4>); C<IPSEC_SETUP> (C<left>/C<middle>/
C<right>) still selects the role, as before.

IPv6 topology (C<IPSEC_IP_VERSION=ipv6>, default):

    LEFT HOST  <---------->  MIDDLE/ROUTER  <----------->  RIGHT HOST

   2001:1:1:1::2            2001:1:1:1::1                 2002:1:1:1::2
                            2002:1:1:1::1

IPv4 topology (C<IPSEC_IP_VERSION=ipv4>):

    LEFT HOST  <---------->  MIDDLE/ROUTER  <----------->  RIGHT HOST

   10.10.1.2                10.10.1.1                     10.10.2.2
                            10.10.2.1

The IPv4 subnets are deliberately kept outside the C<10.1.x.x> ranges used
by C<l2tp3hosts.pm>, since both modules run back-to-back on the same NICs
in C<schedule/ipsec/multi_machine_ipsec_3hosts.yaml>.

It is scheduled as part of a multimachine openQA scenario. The test configures
networking, routing, and IPsec on all three hosts and then exercises
encrypted communication in both tunnel and transport modes.

The overall test flow and thus specific tests are:

Test01:
    Basic L2/L3 connectivity. Each endpoint must be able to ping the middle
    router on its local subnet. Verifies addressing, link status, and neighbor
    discovery.

Test02:
    Verify routing configuration. After static routes are added, both endpoints
    must reach each other through the middle router (no IPsec yet). Ensures
    routing is functional.

Test03:
    IPsec tunnel mode enabled. Traffic from left to right must be encapsulated
    as ESP. tcpdump on the middle router must show ESP packets on both
    interfaces. Basic encrypted communication and MTU-sized packets are tested.

Test04:
    PMTUD with tunnel mode. The middle router reduces MTU to 1300 on one link.
    Oversized packets must trigger ICMPv6 Packet-Too-Big (or, for IPv4, ICMP
    Fragmentation-Needed) messages, visible on the incoming interface. The
    sender must adjust its path MTU and traffic must continue to flow.

    The IPv4 probe is C<ping -M want>, not C<ping -M do>. Both of them make
    the router answer only once: the left host sets DF until the ICMP
    arrives, then caches the PMTU exception for the destination. C<-M want>
    then fragments the following packets locally, which keeps the ping
    successful and the test assertable, while C<-M do> would turn them into
    a local EMSGSIZE and report 100% loss. A single answer per phase is also
    why the middle captures across the whole phase instead of for a fixed
    number of seconds, see C<start_phase_capture>.

Test05:
    IPsec transport mode. After switching both endpoints from tunnel to
    transport mode, encrypted communication must continue. Only ESP validation
    is performed; PMTUD is not expected here.

=cut
