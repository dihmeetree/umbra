window.BENCHMARK_DATA = {
  "lastUpdate": 1772685727500,
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
      },
      {
        "commit": {
          "author": {
            "email": "dmitry@snoculars.com",
            "name": "root"
          },
          "committer": {
            "email": "20114263+dihmeetree@users.noreply.github.com",
            "name": "Dmitry",
            "username": "dihmeetree"
          },
          "distinct": true,
          "id": "3323d600fe8cce9b70bdff1706adc5c3b098b9d7",
          "message": "Address PR review: wire compat, per-endpoint rate limits, stem tracking, test coverage\n\n- Move StemTransaction to end of Message enum to preserve wire\n  discriminants; bump PROTOCOL_VERSION 3 → 4\n- Per-endpoint rate limiter keys (IpAddr, endpoint) so /tx and\n  /commitment-proof counters are independent\n- Tighten rate limiter cap enforcement (>= instead of >, evict +1)\n- Add pending_stem_fluffs to NodeState so RPC-submitted stems get\n  timeout-based fluff fallback via flush_dandelion_stems\n- Clear stem_txs on NewTransaction receipt to prevent re-fluff\n- Add mark_seen in StemTransaction handler for consistent dedup\n- Use constants::MAX_NETWORK_MESSAGE_BYTES in deserialize with_limit\n- Add 5 tests: 4 StemTransaction handler branches + 1 deserialize\n  with_limit internal-length guard\n- Fix docs: parameterize Dandelion++ probability, add \"up to\"\n  qualifier, correct stem delay bound\n\nCo-Authored-By: Claude Opus 4.6 <noreply@anthropic.com>",
          "timestamp": "2026-03-04T20:17:28-08:00",
          "tree_id": "09f62e0e100a46cbf68e6bd26cd7b64ddccb6962",
          "url": "https://github.com/dihmeetree/umbra/commit/3323d600fe8cce9b70bdff1706adc5c3b098b9d7"
        },
        "date": 1772684822398,
        "tool": "cargo",
        "benches": [
          {
            "name": "dilithium5_sign",
            "value": 470034663,
            "range": "± 1904593",
            "unit": "ns/iter"
          },
          {
            "name": "dilithium5_verify",
            "value": 913337,
            "range": "± 3165",
            "unit": "ns/iter"
          },
          {
            "name": "blake3_hash_domain",
            "value": 295,
            "range": "± 9",
            "unit": "ns/iter"
          },
          {
            "name": "blake3_hash_concat",
            "value": 217,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "rescue_prime_commitment",
            "value": 7527,
            "range": "± 22",
            "unit": "ns/iter"
          },
          {
            "name": "vrf_evaluate",
            "value": 470145997,
            "range": "± 1553404",
            "unit": "ns/iter"
          },
          {
            "name": "dag_insert/10",
            "value": 4376,
            "range": "± 8682",
            "unit": "ns/iter"
          },
          {
            "name": "dag_insert/100",
            "value": 15245,
            "range": "± 5273",
            "unit": "ns/iter"
          },
          {
            "name": "dag_insert/1000",
            "value": 128975,
            "range": "± 14268",
            "unit": "ns/iter"
          },
          {
            "name": "finalized_order/10",
            "value": 1643,
            "range": "± 11",
            "unit": "ns/iter"
          },
          {
            "name": "finalized_order/100",
            "value": 17130,
            "range": "± 121",
            "unit": "ns/iter"
          },
          {
            "name": "finalized_order/1000",
            "value": 195583,
            "range": "± 1177",
            "unit": "ns/iter"
          },
          {
            "name": "dag_prune/100",
            "value": 29215,
            "range": "± 5783",
            "unit": "ns/iter"
          },
          {
            "name": "dag_prune/1000",
            "value": 323403,
            "range": "± 22584",
            "unit": "ns/iter"
          },
          {
            "name": "prove_balance",
            "value": 70777907,
            "range": "± 67250",
            "unit": "ns/iter"
          },
          {
            "name": "prove_spend",
            "value": 156771172,
            "range": "± 86499",
            "unit": "ns/iter"
          },
          {
            "name": "verify_balance_proof",
            "value": 9058577,
            "range": "± 24695",
            "unit": "ns/iter"
          },
          {
            "name": "verify_spend_proof",
            "value": 8136448,
            "range": "± 4367",
            "unit": "ns/iter"
          },
          {
            "name": "prove_spend_sequential/2",
            "value": 315807469,
            "range": "± 806230",
            "unit": "ns/iter"
          },
          {
            "name": "prove_spend_sequential/4",
            "value": 631413612,
            "range": "± 294450",
            "unit": "ns/iter"
          },
          {
            "name": "build_tx_parallel/2",
            "value": 245550183,
            "range": "± 9237816",
            "unit": "ns/iter"
          },
          {
            "name": "build_tx_parallel/4",
            "value": 484517672,
            "range": "± 11055388",
            "unit": "ns/iter"
          },
          {
            "name": "serialize_tx",
            "value": 62908,
            "range": "± 20",
            "unit": "ns/iter"
          },
          {
            "name": "deserialize_tx",
            "value": 110681,
            "range": "± 124",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "dmitry@snoculars.com",
            "name": "root"
          },
          "committer": {
            "email": "dmitry@snoculars.com",
            "name": "root"
          },
          "distinct": true,
          "id": "5032379dc7e43132f9778c8d3a396f3ed552b45e",
          "message": "Raise benchmark regression threshold from 15% to 25%\n\nThe with_limit() guard on bincode deserialization (defense-in-depth\nagainst allocation DoS from crafted internal length fields) adds ~22%\noverhead to deserialize_tx. This is an acceptable security trade-off.\n\nAlso add git workflow convention to CLAUDE.md.\n\nCo-Authored-By: Claude Opus 4.6 <noreply@anthropic.com>",
          "timestamp": "2026-03-05T04:32:29Z",
          "tree_id": "65729b7f70547dcfb9e045938ecb59c3f6e948e4",
          "url": "https://github.com/dihmeetree/umbra/commit/5032379dc7e43132f9778c8d3a396f3ed552b45e"
        },
        "date": 1772685727112,
        "tool": "cargo",
        "benches": [
          {
            "name": "dilithium5_sign",
            "value": 470519682,
            "range": "± 2028732",
            "unit": "ns/iter"
          },
          {
            "name": "dilithium5_verify",
            "value": 913777,
            "range": "± 2831",
            "unit": "ns/iter"
          },
          {
            "name": "blake3_hash_domain",
            "value": 295,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "blake3_hash_concat",
            "value": 216,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "rescue_prime_commitment",
            "value": 7530,
            "range": "± 25",
            "unit": "ns/iter"
          },
          {
            "name": "vrf_evaluate",
            "value": 470484059,
            "range": "± 1688856",
            "unit": "ns/iter"
          },
          {
            "name": "dag_insert/10",
            "value": 4278,
            "range": "± 270",
            "unit": "ns/iter"
          },
          {
            "name": "dag_insert/100",
            "value": 14976,
            "range": "± 1518",
            "unit": "ns/iter"
          },
          {
            "name": "dag_insert/1000",
            "value": 134516,
            "range": "± 18253",
            "unit": "ns/iter"
          },
          {
            "name": "finalized_order/10",
            "value": 1608,
            "range": "± 10",
            "unit": "ns/iter"
          },
          {
            "name": "finalized_order/100",
            "value": 17130,
            "range": "± 129",
            "unit": "ns/iter"
          },
          {
            "name": "finalized_order/1000",
            "value": 196183,
            "range": "± 3253",
            "unit": "ns/iter"
          },
          {
            "name": "dag_prune/100",
            "value": 30917,
            "range": "± 6336",
            "unit": "ns/iter"
          },
          {
            "name": "dag_prune/1000",
            "value": 393504,
            "range": "± 32836",
            "unit": "ns/iter"
          },
          {
            "name": "prove_balance",
            "value": 70931069,
            "range": "± 86079",
            "unit": "ns/iter"
          },
          {
            "name": "prove_spend",
            "value": 156884669,
            "range": "± 113908",
            "unit": "ns/iter"
          },
          {
            "name": "verify_balance_proof",
            "value": 9077213,
            "range": "± 9418",
            "unit": "ns/iter"
          },
          {
            "name": "verify_spend_proof",
            "value": 8152555,
            "range": "± 6971",
            "unit": "ns/iter"
          },
          {
            "name": "prove_spend_sequential/2",
            "value": 315935837,
            "range": "± 76801",
            "unit": "ns/iter"
          },
          {
            "name": "prove_spend_sequential/4",
            "value": 632109363,
            "range": "± 551882",
            "unit": "ns/iter"
          },
          {
            "name": "build_tx_parallel/2",
            "value": 246952053,
            "range": "± 20052258",
            "unit": "ns/iter"
          },
          {
            "name": "build_tx_parallel/4",
            "value": 475732954,
            "range": "± 11680991",
            "unit": "ns/iter"
          },
          {
            "name": "serialize_tx",
            "value": 58682,
            "range": "± 69",
            "unit": "ns/iter"
          },
          {
            "name": "deserialize_tx",
            "value": 104605,
            "range": "± 87",
            "unit": "ns/iter"
          }
        ]
      }
    ]
  }
}