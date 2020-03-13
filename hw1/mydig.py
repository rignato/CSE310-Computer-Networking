#!/bin/python

import sys, time, datetime, socket
from dns import query, message, rdataclass, rdatatype, name

USAGE = "\nUSAGE:\n\nmydig <DOMAIN>\n"

ROOT_SERVERS = [
    "198.41.0.4", 
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
    "202.12.27.33"
]

def get_tld(domain):
    for ns in ROOT_SERVERS:
        try:
            res = query.udp(message.make_query(domain, rdatatype.NS), ns)
            return get_next_ns(res)
        except query.BadResponse:
            if ns == ROOT_SERVERS[-1]:
                print("Something has gone horribly wrong, all root DNS servers are down.")
                exit(1)
            continue
    print("Cannot get TLD of %s" % domain)
    return None

def get_next_ns(res):
    rrset = res.get_rrset(
            message.ADDITIONAL, 
            name.from_text(res.additional[0].name.to_text()), 
            rdataclass.IN, 
            rdatatype.A
            )
    if not rrset:
        return None
    return rrset[0].to_text()

def get_authority(res, domain):
    rrset = res.get_rrset(
                message.AUTHORITY, 
                name.from_text(domain), 
                rdataclass.IN, 
                rdatatype.NS
            )
    if not rrset:
        return None
    return rrset[0].to_text()

def get_cname(res, domain):
    rrset =  res.get_rrset(
                message.ANSWER,
                name.from_text(domain),
                rdataclass.IN,
                rdatatype.CNAME   
            )
    if not rrset:
        return None
    return rrset[0].to_text()

def recursive_query(domain, ns):
    res = query.udp(message.make_query(domain, rdatatype.A), ns)
    answers = []
    if res.answer:
        answers.append(res.answer[0])
        cname = get_cname(res,domain)
        if cname:
            answers += recursive_query(cname, get_tld(cname))
            return answers
        else:
            return answers
    elif not res.additional:
        authority = get_authority(res, domain)
        if authority:
            ns = recursive_query(authority, get_tld(authority))
            if ns:
                return recursive_query(domain, ns[0][0].to_text())
        answers.append(res.answer[0])
        return answers
    else:
        return recursive_query(domain, get_next_ns(res))
    
if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(USAGE)
        exit(1)
    domain = sys.argv[1]
    question = message.make_query(domain, rdatatype.A).question[0]
    when = datetime.datetime.now().ctime()
    start = time.time()
    answers  = recursive_query(domain, get_tld(domain))
    end = time.time()
    query_time = (end-start)*1000
    print("\nQUESTION SECTION:")
    print(question)
    print("\nANSWER SECTION:")
    for a in answers:
        print(a)
    print("\nQuery time: %.2fms" % query_time)
    print("WHEN: %s\n" % when)
    
    
    


