# General Purpose
import os
import argparse
import random
import socket
import threading
import time
import yaml
import contextlib

# DNS Query
import dns.message
import dns.query
import dns.rdatatype
import dns.rcode
import dns.exception

# NTP Sync
import ntplib

# LDAP Query
import ldap3
from ldap3.core.exceptions import LDAPExceptionError

# SMB
from impacket.smbconnection import SMBConnection

WORKSTATION_IPS = [
	"192.168.10.12",
	"192.168.10.13",
	"192.168.10.14",
	"192.168.10.15",
	"192.168.10.16"
]

DC_IP = "192.168.20.20"

DNS_QUERY_NAMES = [
	"dc01.lab.local",
	"fileshare.lab.local",
	"_ldab._tcp.dc._msdcs.lab.local",
	"wpad.lab.local"
]

### ----- Per-protocol actions ----- ###

def dns_query(src_ip:str,dc_ip:str,timeout:float=2.0):
	"""bind to src_ip, send one SRV/A record lookup to the DC."""
	qname=random.choice(DNS_QUERY_NAMES)
	rdtype = "SRV" if qname.startswith("_") else "A"

	query = dns.message.make_query(qname, rdtype)
	try:
		response=dns.query.udp(
			query,
			where=dc_ip,
			timeout=timeout,
			source=src_ip,
			port=53
		)
		print(f"[{src_ip}] DNS {rdtype} {qname} -> rcode={dns.rcode.to_text(response.rcode())}")
	except dns.exception.Timeout:
		print(f"[{src_ip}] DNS {rdtype} {qname} -> TIMEOUT (no reply from {dc_ip})")
	except OSError as e:
		print(f"[{src_ip}] DNS query failed to send: {e}")

KRB_AS_REQ_SIZE_RANGE=(200,350)

def kerberos_exchange(src_ip:str,dc_ip:str,timeout:float=2.0):
	"""simulate AS_REQ/AS-REP + TGS-REQ/TGS-REP timing (impacket)."""
	sock=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
	sock.bind((src_ip,0))
	sock.settimeout(timeout)

	try:
		size=random.randint(*KRB_AS_REQ_SIZE_RANGE)
		payload=os.urandom(size)
		sock.sendto(payload,(dc_ip,88))
		data,_=sock.recvfrom(2048)
		print(f"[{src_ip}] Kerberos AS-REQ (shape-only, {size}B) -> "
			f"reply {len(data)}B from {dc_ip}")

	except socket.timeout:
		print(f"[{src_ip}] Kerberos -> TIMEOUT (no reply from {dc_ip})")
	except OSError as e:
		print(f"[{src_ip}] Kerberos failed to send: {e}")
	finally:
		sock.close()

@contextlib.contextmanager
def _bound_source(src_ip:str):
	"""temp patch socket.socket to bind sock to src_ip b4 conn."""
	original_socket_cls=socket.socket

	class _BoundSocket(original_socket_cls):
		def connect(self,address):
			try:
				self.bind((src_ip,0))
			except OSError:
				pass

			return super().connect(address)

	socket.socket=_BoundSocket
	try:
		yield
	finally:
		socket.socket=original_socket_cls

def ldap_query(src_ip:str,dc_ip:str,timeout:float=3.0):
	"""simulate a GPO/user lookup bind+search (ldap3)."""
	conn=None

	try:
		with _bound_source(src_ip):
			server=ldap3.Server(dc_ip,port=389,get_info=None,connect_timeout=timeout)
			conn=ldap3.Connection(server,auto_bind=True,receive_timeout=int(timeout))

			conn.search(
				search_base="dc=lab,dc=local",
				search_filter="(objectClass=*)",
				search_scope=ldap3.BASE,
				attributes=["*"]
			)

			print(f"[{src_ip}] LDAP search -> {len(conn.entries)} entries",
				f"reult={conn.result.get('description')}")

	except LDAPExceptionError as e:
		print(f"[{src_ip}] LDAP protocol error: {e}")
	except OSError as e:
		print(f"[{src_ip}] LDAP failed to send: {e}")
	finally:
		if conn is not None:
			try:
				conn.unbind()
			except LDAPExceptionError:
				pass

def smb_touch(src_ip:str,dc_ip:str,timeout:float=5.0):
	"""simulate a SYSVOL/share touch (impacket smb or smbclient)."""
	try:
		with _bound_source(src_ip):
			conn=SMBConnection(dc_ip,dc_ip,sess_port=445,timeout=timeout)
			conn.login("","")
			shares=conn.listShares()
			share_names=[s["shi1_netname"][:-1]for s in shares]
			print(f"[{src_ip}] SMB connected to {dc_ip} -> shares={share_names}")
			conn.logoff()
	except OSError as e:
		print(f"[{src_ip}] SMB failed to connect: {e}")
	except Exception as e:
		print(f"[{src_ip}] SMB session/auth error: {e}")

def ntp_sync(src_ip:str,dc_ip:str, timeout:float=2.0):
	"""lightweight NTP request (ntplib), connectionless, cheap."""
	sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	sock.bind((src_ip,0))
	sock.settimeout(timeout)

	try:
		query=ntplib.NTPPacket(mode=3,version=3) #mode is number of clients
		send_time=time.time()
		sock.sendto(query.to_data(),(dc_ip,123))

		data,_=sock.recvfrom(1024)
		recv_time=time.time()

		response=ntplib.NTPPacket()
		response.from_data(data)
		offset=((response.recv_timestamp-send_time)+(response.tx_timestamp-recv_time))/2

		print(f"[{src_ip}] NTP sync with {dc_ip} -> offset={offset:.4f}s")
	except socket.timeout:
		print(f"[{src_ip}] NTP sync -> TIMEOUT (no reply from {dc_ip})")
	except OSError as e:
		print(f"[{src_ip}] NTP sync failed to send: {e}")
	finally:
		sock.close()

ACTIONS = [dns_query,kerberos_exchange,ldap_query,smb_touch,ntp_sync]

### ----- Per-Workstation behaviour loop ----- ###

def workstation_loop(src_ip:str,profile:dict,stop_event:threading.Event):
	"""
	profile keys (from manifest):
		action_interval_range: [min_s,max_s] - gap between actions
		action_weights: dict of action_name -> probability weight
		jitter : float - +/- fractional jitter on interval
	"""

	interval_min, interval_max = profile["action_interval_range"]
	while not stop_event.is_set():
		action = random.choices(
			ACTIONS,
			weights=profile.get("action_weights", [1] * len(ACTIONS)),
			k=1,
		)[0]
		try: 
			action(src_ip, DC_IP)
		except Exception as e:
			print(f"[{src_ip}] action {action.__name__} failed: {e}")

		base = random.uniform(interval_min, interval_max)
		jitter = base*profile.get("jitter",0.1)
		time.sleep(max(0.0, base+random.uniform(-jitter, jitter)))

### ----- Profile definitions ----- ###

PROFILES = {
	"quiet" : {
		"active_workstations":1,
		"action_interval_range":[60,120],
		"jitter":0.2,
		"action_weights":[1,0,0,0,0]
	},
	"light" : {
		"active_workstations":3,
		"action_interval_range":[10,30],
		"jitter":0.3,
		"action_weights":[45,25,15,10,5]
	},
	"moderate" : {
		"active_workstations":5,
		"action_interval_range":[5,20],
		"jitter":0.4,
		"action_weights":[45,25,15,10,5]
	},
	"bursty" : {
		"active_workstations":5,
		"action_interval_range":[0.5,2],
		"jitter":0.1,
		"logon_storm":True,
		"action_weights":[30,25,25,15,5]
	},
	"mixed" : {
		"sequence":[
			("light",300),
			("bursty",60),
			("moderate",300)
		]
	}
}

def run_profile(name:str,duration_s:int,stop_event:threading.Event):
	profile = PROFILES[name]

	if name == "mixed":
		for sub_name, sub_duration in profile["sequence"]:
			run_profile(sub_name,sub_duration,stop_event)
		return

	threads = []
	n_active = profile.get("active_workstations",5)
	active_ips=WORKSTATION_IPS[:n_active]

	if profile.get("logon_storm"):
		start_delays=[0]*len(active_ips)
	else:
		start_delays=[random.uniform(0,5) for _ in active_ips]

	for ip, delay in zip(active_ips, start_delays):
		time.sleep(delay)
		t=threading.Thread(target=workstation_loop,args=(ip,profile,stop_event))
		t.daemon=True
		t.start()
		threads.append(t)

	time.sleep(duration_s)
	stop_event.set()
	for t in threads:
		t.join(timeout=2)

def main():
	parser = argparse.ArgumentParser()
	parser.add_argument("--profile", choices=PROFILES.keys(),required=True)
	parser.add_argument("--duration",type=int,default=300,help="seconds")
	parser.add_argument("--seed",type=int,default=None)
	parser.add_argument("--manifest",type=str,help="optional YAML manifest override")
	args=parser.parse_args()

	if args.seed is not None:
		random.seed(args.seed)

	if args.manifest:
		with open(args.manifest) as f:
			override=yaml.safe_load(f)
			PROFILES.update(override.get("profiles",{}))

	stop_event=threading.Event()
	run_profile(args.profile,args.duration,stop_event)

if __name__ == "__main__":
	main()
