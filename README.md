# Investigating Deployment Issues of DNS Root Server Instances from a China wide View
This repository provides the artifacts about the paper:

## All measurement datas
- Avaliable at: https://drive.google.com/file/d/12PM8Kk7Grk34svMG9MbveTna9DOtFkPb/view?usp=sharing
- We organized all data into a csv file by using Python Pandas.
- Each colnum represents:
    - proxy_ip_address: the IP address of our vantage point
    - ASN: the ASN of our vantage point
    - ISP: the ISP address of our vantage point (T: Telecom, U: Unicom, M: Mobile, E: Tencent, A: Alibaba, C: CERNET)
    - target: the target in which we sent this query 
    - query: the query we sent
    - consumed_time: the consumed time we measured from the vantage point
    - answer: the answer we received
    - province: the province of our vantage point
    - city: the city of our vantage point

## Source codes of our measurment
- We established our measurement platform manually. For example, installing operating system and installing VPN software on each machine. Almost no coding in this process.
- We provided our codes of conducting measurement tasks, which are avaliable at: `source/`.
- The way to run this code
```
pip install -r requirements.txt
python3 main.py
```
- Each field in the result represents:
```
| field        | type           | meaning                                                      |
| ------------ | -------------- | ------------------------------------------------------------ |
| ts           | BIGINT         | timestamp                                                    |
| mid          | STRING         | measurement id, unique for every query                       |
| mtype        | INT            | type id to distinguish different types of queries            |
| target       | STRING         | IP address of the target                                     |
| target_label | STRING         | root-a/root-b/.../root-m                                     |
| qname        | STRING         | DNS query name field                                         |
| qtype        | INT            | DNS query type field                                         |
| qclass       | INT            | DNS query class field                                        |
| timeout      | INT            | whether the query is timeout (1-yes / 0-no)                  |
| rtt          | FLOAT          | Round trip time                                              |
| answer       | STRUCT<...>    | answer from the root                                         |
| raw_query    | STRING         | preserved                                                    |
| raw_answer   | STRING         | raw answer from the root                                     |
| pdate        | STRING         | the date of the measurement                                  |
| route        | ARRAY\<STRING> | IP list of the path to a  root (only for traceroute)         |
| rtt          | ARRAY\<FLOAT>  | RTT list in traceroute                                       |
```


## A technical report of our analysis on four mainstream recursive DNS software
- Avaliable at: `software_analysis.pdf`
- Including: the pseudo-code and detailed explanations of all root selection algorithms