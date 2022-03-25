
-- {"hostname":"slingshot0.eait.uq.edu.au","start":"2022-03-16 22:36:53.718","end":"2022-03-16 22:36:57.745","action":"drop","dir":"in","vnetid":871,"ipv":6,"saddr":"fe80::759b:db56:6098:5c76","daddr":"ff02::2","ipproto":58,"sport":133,"dport":0,"key":0,"packets":3,"bytes":144,"syns":0,"fins":0,"rsts":0}


CREATE TABLE pflog
(
    `begin_at` DateTime64(3) CODEC(DoubleDelta),
    `end_at` DateTime64(3) CODEC(DoubleDelta),
    `hostname` LowCardinality(String),
    `action` Enum('other' = 0, 'pass' = 1, 'drop' = 2, 'match' = 3),
    `dir` Enum('out' = 0, 'in' = 1),
    `vnetid` Int32 CODEC(Gorilla),
    `ipv` UInt8 CODEC(NONE),
    `ipproto` UInt8 CODEC(NONE),
    `saddr` IPv6 CODEC(ZSTD(3)),
    `daddr` IPv6 CODEC(ZSTD(3)),
    `sport` UInt16 CODEC(NONE),
    `dport` UInt16 CODEC(NONE),
    `gre_key` UInt32 CODEC(Gorilla),
    `packets` UInt64 CODEC(Gorilla),
    `bytes` UInt64 CODEC(Gorilla),
    `syns` UInt32 CODEC(Gorilla),
    `fins` UInt32 CODEC(Gorilla),
    `rsts` UInt32 CODEC(Gorilla),
    INDEX begin_at_idx begin_at TYPE minmax GRANULARITY 2048,
    INDEX end_at_idx end_at TYPE minmax GRANULARITY 2048
)
ENGINE = SummingMergeTree()
PARTITION BY toStartOfDay(begin_at)
ORDER BY (action, saddr, daddr, ipv, ipproto, sport, dport, vnetid, gre_key, dir, hostname, begin_at, end_at)


