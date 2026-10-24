| Scenario | windows | malicious | TP | FP | FN | TN | Precision | Recall | F1 | Accuracy |
|---|---|---|---|---|---|---|---|---|---|---|
| S1 Benign | 566 | 0 | 0 | 0 | 0 | 566 | 1.000 | n/a | n/a | 1.000 |
| S2 Port scan | 515 | 6 | 6 | 1 | 0 | 508 | 0.857 | 1.000 | 0.923 | 0.998 |
| S3 SYN flood | 500 | 18 | 18 | 3 | 0 | 479 | 0.857 | 1.000 | 0.923 | 0.994 |
| S4 Brute force + ARP | 599 | 12 | 12 | 1 | 0 | 586 | 0.923 | 1.000 | 0.960 | 0.998 |
| S5 Ambiguous | 1020 | 17 | 17 | 4 | 0 | 999 | 0.809 | 1.000 | 0.895 | 0.996 |
| **Overall** | 3200 | 53 | 53 | 9 | 0 | 3138 | 0.855 | 1.000 | 0.922 | 0.997 |

| Layer | TP | FP | FN | Precision | Recall | F1 |
|---|---|---|---|---|---|---|
| rules only | 31 | 0 | 22 | 1.000 | 0.585 | 0.738 |
| RandomForest only | 49 | 1 | 4 | 0.980 | 0.924 | 0.952 |
| IsolationForest only | 47 | 9 | 6 | 0.839 | 0.887 | 0.862 |
| hybrid (final) | 53 | 9 | 0 | 0.855 | 1.000 | 0.922 |
| hybrid, medium+ severity | 35 | 1 | 18 | 0.972 | 0.660 | 0.786 |

| Attack | windows | flagged | detected | right class | time to detect (s) |
|---|---|---|---|---|---|
| SYN scan of 999 ports on 192.168.10.50 at ~230 probes/s | 6 | 6 | True | True | 10.0 |
| SYN scan of 60 ports on 192.168.10.12 at ~2 probes/s | 6 | 6 | True | True | 0.5 |
| SYN flood on 192.168.10.50:80 at ~1300 pps from 6 bots | 18 | 18 | True | True | 10.0 |
| SSH brute force, 225 attempts on 192.168.10.50:22 | 5 | 5 | True | True | 10.0 |
| FTP brute force, 60 attempts on 192.168.10.50:21 | 3 | 3 | True | True | 10.0 |
| ARP poisoning of 3 victims (gateway 192.168.10.1 -> 02:00:00:00:00:63) | 4 | 4 | True | True | 10.0 |
| low-and-slow SYN scan, 17 ports, one probe every ~12 s | 17 | 17 | True | True | 10.0 |

| Scenario | packets | extract s | detect s | packets/s | ms/window | x real time |
|---|---|---|---|---|---|---|
| S1 Benign | 29251 | 0.598 | 0.154 | 38894 | 0.272 | 158.6 |
| S2 Port scan | 27264 | 0.437 | 0.938 | 19829 | 1.822 | 87.2 |
| S3 SYN flood | 73449 | 1.433 | 2.55 | 18441 | 5.1 | 30.1 |
| S4 Brute force + ARP | 30293 | 0.465 | 1.524 | 15232 | 2.544 | 76.9 |
| S5 Ambiguous | 47350 | 0.869 | 2.584 | 13711 | 2.533 | 104.4 |
