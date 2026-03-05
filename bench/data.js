window.BENCHMARK_DATA = {
  "lastUpdate": 1772678290287,
  "repoUrl": "https://github.com/dihmeetree/umbra",
  "entries": {
    "Benchmark": [
      {
        "commit": {
          "author": {
            "email": "dihmeetree@users.noreply.github.com",
            "name": "Dmitry",
            "username": "dihmeetree"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "dfbbc88eef95d1218a9fcac0fe744e060b56dfd8",
          "message": "Add criterion benchmarks, rayon parallelization, and CI regression detection (#32)",
          "timestamp": "2026-03-04T17:18:57-08:00",
          "tree_id": "da7bc12e3dbf43fa4064e2563776d996ae444fd4",
          "url": "https://github.com/dihmeetree/umbra/commit/dfbbc88eef95d1218a9fcac0fe744e060b56dfd8"
        },
        "date": 1772678290024,
        "tool": "cargo",
        "benches": [
          {
            "name": "dilithium5_sign",
            "value": 515545999,
            "range": "± 2937136",
            "unit": "ns/iter"
          },
          {
            "name": "dilithium5_verify",
            "value": 983024,
            "range": "± 8607",
            "unit": "ns/iter"
          },
          {
            "name": "blake3_hash_domain",
            "value": 490,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "blake3_hash_concat",
            "value": 334,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "rescue_prime_commitment",
            "value": 8882,
            "range": "± 169",
            "unit": "ns/iter"
          },
          {
            "name": "vrf_evaluate",
            "value": 515486569,
            "range": "± 1247948",
            "unit": "ns/iter"
          },
          {
            "name": "dag_insert/10",
            "value": 6002,
            "range": "± 13422",
            "unit": "ns/iter"
          },
          {
            "name": "dag_insert/100",
            "value": 16056,
            "range": "± 15487",
            "unit": "ns/iter"
          },
          {
            "name": "dag_insert/1000",
            "value": 129748,
            "range": "± 13152",
            "unit": "ns/iter"
          },
          {
            "name": "finalized_order/10",
            "value": 1714,
            "range": "± 9",
            "unit": "ns/iter"
          },
          {
            "name": "finalized_order/100",
            "value": 18452,
            "range": "± 293",
            "unit": "ns/iter"
          },
          {
            "name": "finalized_order/1000",
            "value": 215027,
            "range": "± 2084",
            "unit": "ns/iter"
          },
          {
            "name": "dag_prune/100",
            "value": 31304,
            "range": "± 11032",
            "unit": "ns/iter"
          },
          {
            "name": "dag_prune/1000",
            "value": 303901,
            "range": "± 10447",
            "unit": "ns/iter"
          },
          {
            "name": "prove_balance",
            "value": 82775317,
            "range": "± 77986",
            "unit": "ns/iter"
          },
          {
            "name": "prove_spend",
            "value": 182996041,
            "range": "± 356479",
            "unit": "ns/iter"
          },
          {
            "name": "verify_balance_proof",
            "value": 10612552,
            "range": "± 10970",
            "unit": "ns/iter"
          },
          {
            "name": "verify_spend_proof",
            "value": 9505925,
            "range": "± 47136",
            "unit": "ns/iter"
          },
          {
            "name": "prove_spend_sequential/2",
            "value": 369080776,
            "range": "± 4334920",
            "unit": "ns/iter"
          },
          {
            "name": "prove_spend_sequential/4",
            "value": 738261804,
            "range": "± 481056",
            "unit": "ns/iter"
          },
          {
            "name": "build_tx_parallel/2",
            "value": 291470775,
            "range": "± 12707031",
            "unit": "ns/iter"
          },
          {
            "name": "build_tx_parallel/4",
            "value": 524275473,
            "range": "± 21783247",
            "unit": "ns/iter"
          },
          {
            "name": "serialize_tx",
            "value": 62265,
            "range": "± 104",
            "unit": "ns/iter"
          },
          {
            "name": "deserialize_tx",
            "value": 90714,
            "range": "± 122",
            "unit": "ns/iter"
          }
        ]
      }
    ]
  }
}