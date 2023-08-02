import time
import base64
from scapy.all import *
from concurrent.futures import ThreadPoolExecutor, as_completed
import json
import dns.query
import dns.message

index = 1


def get_index():
    global index
    index += 1
    return index - 1


str_set = set()
all_chars = "abcdefghijklmnopqrstuvwxyz1234567890"


def getRandomStr():
    global str_set, all_chars
    while True:
        rand_len = random.randint(8, 12)
        chars = []
        for _ in range(rand_len):
            chars.append(random.choice(all_chars))
        result_ = "".join(chars)
        if result_ not in str_set:
            str_set.add(result_)
            return result_


ROOTS = ["198.41.0.4",
         "199.9.14.201",
         "192.33.4.12",
         "199.7.91.13",
         "192.203.230.10",
         "192.5.5.241",
         "192.112.36.4",
         "198.97.190.53",
         "192.36.148.17",
         "192.58.128.30",
         "193.0.14.129",
         "199.7.83.42",
         "202.12.27.33"]


def IP2root(root_ip):
    return "abcdefghijklm"[ROOTS.index(root_ip)]


def dns_query(mid: str,
              mtype: int,
              target: str,
              target_label: str,
              query_name: str,
              query_type: int,
              query_class: int,
              want_dnssec=False,
              rd: int = 0,
              want_nsid=False):
    ts = int(time.time() * 1000)

    try:
        start_time = time.time()
        if not want_nsid:
            udp_result = dns.query.udp(
                dns.message.make_query(query_name, query_type, query_class,
                                       use_edns=0 if want_dnssec else None,
                                       want_dnssec=want_dnssec,
                                       flags=0 if rd == 0 else dns.flags.RD),
                target,
                timeout=1.5
            )
        else:
            query_msg = dns.message.make_query(query_name, 1, 1, use_edns=True, flags=0)
            query_msg.use_edns(
                payload=4096,
                options=[dns.edns.GenericOption(dns.edns.NSID, b'')])
            udp_result = dns.query.udp(
                query_msg,
                target,
                timeout=2,
            )

        end_time = time.time()
        cost_time = end_time - start_time
        timeout = 0
    except Exception as ex:
        cost_time = None
        timeout = 1
    return {
        "ts": ts,
        "mid": mid,
        "mtype": mtype,
        "target": target,
        "target_label": target_label,
        "qname": query_name,
        "qtype": query_type,
        "qclass": query_class,
        "timeout": timeout,
        "rtt": cost_time,
        "answer": {
            "rcode": udp_result.rcode(),
            "flags": int(udp_result.flags),
            "ancount": sum(len(rr_set) for rr_set in udp_result.answer),
            "nscount": sum(len(rr_set) for rr_set in udp_result.authority),
            "arcount": sum(len(rr_set) for rr_set in udp_result.additional)
        } if timeout == 0 else None,
        "raw_query": None,
        "raw_answer": base64.b64encode(udp_result.to_wire()).decode()
        if timeout == 0 else None
    }


def dns_trace(
        mid: str,
        target: str,
        target_label: str,
):
    ts = int(time.time() * 1000)
    QueryName = "a3b4c5.baidu.com"

    def make_dns_packet(ttl):
        a = IP(id=RandShort(), dst=target, ttl=ttl)
        b = UDP(sport=RandShort(), dport=53)
        c = DNS(id=RandShort(), rd=1, qd=DNSQR(qname=QueryName))
        p = a / b / c
        return p

    ip_list, rtt_list = [], []
    for ttl in range(1, 32):
        dns_packet = make_dns_packet(ttl)
        start_time = time.time()
        one_result = sr1(dns_packet, verbose=0, timeout=1.5)
        end_time = time.time()
        if one_result is None:
            ip_list.append(None)
            rtt_list.append(None)
        else:
            ip_list.append(one_result.src)
            rtt_list.append(end_time - start_time)
            if one_result.src == target:
                break

    return {
        "ts": ts,
        "mid": mid,
        "mtype": 1001,
        "target": target,
        "target_label": target_label,
        "qname": QueryName,
        "qtype": 1,
        "qclass": 1,
        "route": ip_list,
        "rtt": rtt_list
    }


ts = int(time.time() * 1000)

query_result = {
    'ts': ts,
    "measurements": []
}

traceroute_result = {
    'ts': ts,
    "measurements": []
}


# Algorithm 3: request resolving [nonce].censored-domain.com;
for _ in range(5):
    for root in ROOTS:
        query_tasks.append(
            [
                "1_{}".format(get_index()), 1,
                root, "root-{}".format(IP2root(root)),
                getRandomStr() + ".youtube.com",
                1, 1,
                False, 0, False
            ],
        )

# Section 5.4: measure the RTT of a root server
for _ in range(5):
    for root in ROOTS:
        query_tasks.append(
            [
                "2_{}".format(get_index()), 2,
                root, "root-{}".format(IP2root(root)),
                getRandomStr() + ".baidu.com",
                1, 1,
                False, 0, False
            ]
        )

# Algorithm 2: requests server identifiers;
for root in ROOTS:
    query_tasks.append(
        [
            "6_{}".format(get_index()), 6,
            root, "root-{}".format(IP2root(root)),
            "version.bind",
            16, 3,
            False, 0, False
        ]
    )
    query_tasks.append(
        [
            "7_{}".format(get_index()), 7,
            root, "root-{}".format(IP2root(root)),
            "id.server",
            16, 3,
            False, 0, False
        ]
    )
    query_tasks.append(
        [
            "8_{}".format(get_index()), 8,
            root, "root-{}".format(IP2root(root)),
            ".",
            1, 1,
            False, 0, True
        ]
    )

# Algorithm 2: checks the integrity of the zone file
for root in ROOTS:
    for kind_ in ["com", "net", "org", "top", "us", "uk", "cn", "ru"]:
        query_tasks.append(
            [
                "3_{}".format(get_index()), 3,
                root, "root-{}".format(IP2root(root)),
                kind_,
                1, 1,
                False, 0, False
            ]
        )

# Algorithm 2: checks the timeliness of the zone file;
for root in ROOTS:
    query_tasks.append(
        [
            "4_{}".format(get_index()), 4,
            root, "root-{}".format(IP2root(root)),
            getRandomStr() + ".examplenxtld00",
            1, 1,
            False, 0, False
        ]
    )

# Algorithm 2: checks availability of DNSSEC validation;
# Note that dig repeats the query 3 times when does not receive the result.
for root in ROOTS:
    query_tasks.append(
        [
            "5_{}".format(get_index()), 5,
            root, "root-{}".format(IP2root(root)),
            ".",
            1, 1,
            True, 0, False
        ]
    )

# Algorithm 2: performs DNS traceroute;
traceroute_tasks = []
for root in ROOTS:
    for _ in range(5):
        traceroute_tasks.append(
            [
                "1001_{}".format(get_index()),
                root, "root-{}".format(IP2root(root)),
            ]
        )

executor = ThreadPoolExecutor(max_workers=20)
all_task = [executor.submit(dns_query, *query_task)
            for query_task in query_tasks]
query_result["measurements"] = [future.result()
                                for future in as_completed(all_task)]

executor = ThreadPoolExecutor(max_workers=40)
all_task = [executor.submit(dns_trace, *traceroute_task)
            for traceroute_task in traceroute_tasks]
traceroute_result["measurements"] = [future.result()
                                     for future in as_completed(all_task)]

with open("result.json", "w", encoding="utf-8") as f:
    json.dump([query_result, traceroute_result], f)
