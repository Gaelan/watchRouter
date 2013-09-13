#!/usr/bin/ruby -w

# Todo:
# - Clean up / switch DNS code (lots of messages currently).
# - Deal with DNS failures
# - Clean up SNMP code. Deal with errors and timeouts.
# - Deal with change-in-process IP address (i.e., 0.0.0.1 etc.).
# - Parse HTTP (update) messages.
# - Diagnose reasons for changes (e.g. router down, etc).
# - Deal with incomplete update (do DNS lookup on each host).
# - Be less verbose on changes.
# - See if we can find the return values (e.g. body?) HE sends some for sure.
# - Parse HE response.body.
# - Log DNS propagation / test changes.
# - Notify special people.
# - More testing.
# - Escalate log levels / notifications on frequent updates / failures.
# - Change everything to URI parse model like IWMN.
# - Process command line arguements.
# - Do something smart with passwords.
# - Command line args: force update, force particular provider.

def silence_warnings(&block)
	warn_level = $VERBOSE
	$VERBOSE = nil
	result = block.call
	$VERBOSE = warn_level
	result
end

silence_warnings do
	require 'rubygems'
	require 'snmp'
	#require 'net/http'
	require 'net/https'
	require 'uri'
	require 'syslog'
	require 'dnsruby'
	begin
		require 'colorize'
	rescue LoadError
		$stderr.puts("Install the colorize gem for colored logging to stderr.") if ($stderr.tty?)
	end
end

include Dnsruby

# Configuration

$stdout.sync = true

load '/etc/watchRouter.secrets'

secrets = get_secrets()

BRpw        = secrets[:enom][:pw]
HEuser      = secrets[:he][:user]
HEpw        = secrets[:he][:pw]
HEtid       = secrets[:he][:tid]
IWNMuser    = secrets[:iwmn][:user]
IWNMpw      = secrets[:iwmn][:pw]
IWMNns      = "ns1.iwantmyname.net"
NSenom      = "dns1.name-services.com"
NSgoogle    = "8.8.8.8"
RouterIP    = "10.0.1.1"
SNMPpw      = secrets[:snmp][:pw]
Wait_Between_Checks = 60 # Seconds between checks.
Watchdog_Interval   = 15 # Heartbeat, log every N checks.

$my_name = File.basename($0)

# Driver for dynamic DNS updates. Code to manage the updates with specific
# service providers follows.

def ddns_update(ip)
  ddns_update_he(HEuser, HEpw, HEtid, ip)
  {
    "canishe.com"        => [ "mail", "www", "@", "*" ],
    "gaelan.me"          => [ "www", "@" ],
    "psd-chinese.net"    => [ "www", "@" ],
  }.each do |zone, hosts|
    hosts.each do |host|
      ddns_update_iwmn(host, zone, ip, IWMNuser, IWMNpw)
    end
  end
	{
    "marimbaboise.com"   => [ "www", "@" ],
  }.each do |zone, hosts|
    hosts.each do |host|
      ddns_update_enom(host, zone, ip, BRpw)
    end
  end
end

# Update IPv4 endpoint of Hurricane Electric IPv6 tunnel.

def ddns_update_he(user, pw, tid, ip)
  uri = URI.parse("https://ipv4.tunnelbroker.net/nic/update?username=#{user}&password=#{pw}&hostname=#{tid}&myip=#{ip}")
  http = Net::HTTP.new(uri.host, uri.port)
  http.use_ssl = true
	http.verify_mode = OpenSSL::SSL::VERIFY_NONE

  request = Net::HTTP::Get.new(uri.request_uri)

  response = http.request(request)

	body = parse_response_he(response.body)

  log(:info,
		"ddns_update_he(#{tid}, #{ip}) returned \"#{body} (#{response.code})\"")
end

def parse_response_he(body)
	return body.chomp
end

# Update dynamic DNS at iwantmyname.

def ddns_update_iwmn(host, zone, ip, user, pw)
	if (host == "@") then
		fqdn = "#{zone}"
	else
		fqdn = "#{host}.#{zone}"
	end
  uri = URI.parse("https://iwantmyname.com/basicauth/ddns?hostname=#{fqdn}")
  http = Net::HTTP.new(uri.host, uri.port)
	http.use_ssl = true
	http.verify_mode = OpenSSL::SSL::VERIFY_NONE

  request = Net::HTTP::Get.new(uri.request_uri)
	request.basic_auth(user, pw)

  response = http.request(request)

  log(:info,
		"ddns_update_iwmn(#{host}.#{zone}) returned \"#{response.body} (#{response.code})\"")
end

# Update dynamic DNS at BulkRegister (aka eNOM).

def ddns_update_enom(host, zone, ip, pw)
  http = Net::HTTP.new("reseller.enom.com", 443)
  http.use_ssl = true
	http.verify_mode = OpenSSL::SSL::VERIFY_NONE

  tail = "interface.asp?command=setdnshost&hostname=#{host}&zone=#{zone}&domainpassword=#{pw}&address=#{ip}" 

  request = Net::HTTP::Get.new(tail)
  response = http.request(request)

	pr = parse_response_enom(response.body)

  log(:info,
		"ddns_update_enom(#{host}.#{zone}) returned \"#{pr['Command']} to #{pr['IP']} at #{pr['Server']} (#{response.code})\"")
end

def parse_response_enom(body)
	response = {}
	body.each do |line|
		value = line.chomp.split('=')
		response[value[0]] = value[1]
	end
	return response
end

# Check our address in DNS

def get_dns_ipaddr(host)
  dns = Dnsruby::DNS.new({
    :nameserver => [ IWMNns ],
    :search     => [ 'canishe.com' ],
    :ndots      => 1
  })

  answer = dns.getaddress(host)

  return answer.to_s
end

# Check the WAN IP address on our router.
#
# XXX need to handle timeouts and do error checking.

def get_router_ipaddr()
  SNMP::Manager.open(
    :Host => RouterIP,
    :Community => SNMPpw,
    :Timeout => 60,
    :Retries => 5
 ) do |manager|
    # XXX Timeout on the next line (or the one below) will kick us out.
    response = manager.get(["ip.21.1.7.0.0.0.0"])
    response.each_varbind do |vb|
      default_route = "#{vb.value.to_s}"
      # puts "ip.21.1.7.#{default_route}"
      response = manager.get(["ip.21.1.7.#{default_route}"])
      response.each_varbind do |vb|
        my_ipaddr = "#{vb.value.to_s}"
        # puts my_ipaddr
        return my_ipaddr
      end
    end
  end
end

# Message logging - syslog() plus console if it is there.

def log(priority, message)

  priorities = {
    :emergency => Syslog::LOG_EMERG,
    :alert     => Syslog::LOG_ALERT,
    :critical  => Syslog::LOG_CRIT,
    :error     => Syslog::LOG_ERR,
    :warning   => Syslog::LOG_WARNING,
    :notice    => Syslog::LOG_NOTICE,
    :info      => Syslog::LOG_INFO,
    :debug     => Syslog::LOG_DEBUG
  }
  colors = {
    :emergency => :red,
    :alert     => :red,
    :critical  => :red,
    :error     => :red,
    :warning   => :yellow,
    :notice    => :blue,
    :info      => :green,
    :debug     => :green
  }
  unless (priorities.has_key? priority)
    backtrace = caller(1).join("\n")
    log(:error, "Invalid priority #{priority} passed to log. Backtrace: \n #{backtrace}")
    priority = :info
  end

  Syslog::log(priorities[priority], message)
  
  # Also log to stderr
  prefix = priority.to_s
  if ($stderr.tty?) then
    prefix = prefix.send colors[priority] if (prefix.respond_to? colors[priority])
  end
  timestamp = Time.now.strftime("%b %d %H:%M:%S")
  $stderr.puts("#{timestamp}: #{prefix}: #{message}")
end

####
#
# Mainline code starts here.
#
####

Syslog.open($my_name, nil, Syslog::LOG_DAEMON)

Signal.trap(:QUIT) do
  log(:notice, "Caught SIGQUIT, terminating")
  exit
end

Signal.trap(:INT) do
  log(:notice, "Caught SIGINT, terminating")
  exit
end

Signal.trap(:EXIT) do
  Syslog::close
end

# Toggle debugging.

debug = false
force = false
waiting = false

Signal.trap(:USR1) do
  debug = !debug
  log(:notice, "Debugging " + (debug ? "on" : "off"))
end

loops = 0
prev_IP_addr = "0.0.0.0"
prev_IP_addr = get_dns_ipaddr("www.canishe.com")
log(:info, "Start up. Got #{prev_IP_addr} from DNS. Checking every #{Wait_Between_Checks} seconds.")

loop do
  current_IP_addr = get_router_ipaddr()
	if (current_IP_addr == "noSuchInstance") then
		log(:notice, "Waiting for link to come up...")
		if (!waiting) then
			old_Wait = Wait_Between_Checks
			old_Watchdog = Watchdog_Interval
			Wait_Between_Checks = 15
			Watchdog_Interval = 8
			waiting = true
		end
  elsif (current_IP_addr != prev_IP_addr || force) then
		if (waiting) then
			Wait_Between_Checks = old_Wait
			Watchdog_Interval = old_Watchdog
			waiting = false
		end
		if (force) then
			log(:notice, "Manually forced update, current IP address is #{current_IP_addr} ...")
    elsif (prev_IP_addr == "0.0.0.0") then
      log(:notice, "Forced update to #{current_IP_addr} ...")
    else
      log(:notice, "Router IP address changed from #{prev_IP_addr} to #{current_IP_addr} ...")
    end
    ddns_update(current_IP_addr) # XXX need to make sure it worked!
    log(:info, "Ran ddns_update() - but no error checking yet.")
    prev_IP_addr = current_IP_addr
  end
  loops += 1
  if (loops % Watchdog_Interval == 0) then log(:info, current_IP_addr) end
  sleep Wait_Between_Checks
end
