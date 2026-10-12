# Label experiments

Same temporal split (test: CVEs published 2022-2024), same features and models; only the label and the training years change. Bootstrap 95% confidence intervals in brackets. Produced by `scripts/train.py` (see `--label`, `--train-start`, `--out`).

## KEV within 365 days (reported result, train 2016-2021)

Train: 93,159 CVEs, 175 positive (0.19%). Test: 91,882 CVEs, 165 positive (0.18%).

| model | AUROC | PR-AUC | ECE | mean predicted | observed rate |
|---|---|---|---|---|---|
| CVSS | 0.735 [0.695, 0.766] | 0.005 [0.004, 0.006] | 0.7027 | 0.7045 | 0.0018 |
| EPSS at publication | 0.632 [0.579, 0.674] | 0.035 [0.014, 0.063] | 0.0038 | 0.0045 | 0.0018 |
| Logistic regression | 0.775 [0.741, 0.812] | 0.009 [0.006, 0.014] | 0.0011 | 0.0019 | 0.0018 |
| Gradient-boosted trees | 0.806 [0.776, 0.835] | 0.009 [0.007, 0.014] | 0.0006 | 0.0016 | 0.0018 |
| MLP | 0.719 [0.680, 0.759] | 0.006 [0.004, 0.009] | 0.0023 | 0.0020 | 0.0018 |

## KEV within 365 days, train 2020-2021 only

Train: 38,471 CVEs, 175 positive (0.45%). Test: 91,882 CVEs, 165 positive (0.18%).

| model | AUROC | PR-AUC | ECE | mean predicted | observed rate |
|---|---|---|---|---|---|
| CVSS | 0.735 [0.695, 0.766] | 0.005 [0.004, 0.006] | 0.7027 | 0.7045 | 0.0018 |
| EPSS at publication | 0.632 [0.579, 0.674] | 0.035 [0.014, 0.063] | 0.0038 | 0.0045 | 0.0018 |
| Logistic regression | 0.753 [0.707, 0.794] | 0.009 [0.006, 0.014] | 0.0027 | 0.0037 | 0.0018 |
| Gradient-boosted trees | 0.826 [0.795, 0.849] | 0.013 [0.008, 0.022] | 0.0015 | 0.0032 | 0.0018 |
| MLP | 0.596 [0.561, 0.640] | 0.003 [0.002, 0.003] | 0.0088 | 0.0105 | 0.0018 |

## Exploit-DB exploit within 365 days (cleaned)

Train: 92,290 CVEs, 3,310 positive (3.59%). Test: 91,882 CVEs, 311 positive (0.34%).

| model | AUROC | PR-AUC | ECE | mean predicted | observed rate |
|---|---|---|---|---|---|
| CVSS | 0.664 [0.633, 0.695] | 0.006 [0.005, 0.008] | 0.7013 | 0.7046 | 0.0034 |
| EPSS at publication | 0.639 [0.604, 0.675] | 0.019 [0.012, 0.029] | 0.0038 | 0.0048 | 0.0034 |
| Logistic regression | 0.689 [0.657, 0.711] | 0.009 [0.007, 0.017] | 0.0365 | 0.0399 | 0.0034 |
| Gradient-boosted trees | 0.691 [0.668, 0.715] | 0.008 [0.006, 0.014] | 0.0375 | 0.0409 | 0.0034 |
| MLP | 0.689 [0.658, 0.716] | 0.006 [0.006, 0.008] | 0.0352 | 0.0386 | 0.0034 |

## What the experiments show

* **Exploit-DB label (the plan's second label).** The model still beats CVSS and EPSS at publication on AUROC (0.691 vs 0.664 and 0.639), but the gain is small and the probabilities are unusable: the positive rate falls from 6-8% for CVEs published in 2016-2018 to 0.3-0.8% in 2022-2025 (Exploit-DB publishes fewer exploits), so the model predicts 4.1% on a test set whose true rate is 0.34% (ECE 0.0375; EPSS at publication is better calibrated). KEV is the better target for calibrated probabilities.
* **Exploit-DB data quality.** 869 of 4,179 training positives (21%) were CVEs whose only exploit is dated more than 30 days before the CVE existed (for example a 2012 exploit listed for a 2024 CVE): CVE-id mapping errors, not labels. They are excluded from the cleaned label.
* **Metasploit label: not feasible with this source.** The Metasploit modules mirrored in Exploit-DB end in May 2020, so only 352 CVEs have one and none in the test years; evaluating this label would need the metasploit-framework repository itself.
* **KEV left truncation.** KEV only started in November 2021, so a CVE published before about 2020 can hardly be a positive of the 365-day label: 2016-2019 have a 0.00% positive rate. Training on 2020-2021 only keeps every positive (175) but drops about 55,000 near-certain negatives, and the gradient-boosted model improves (AUROC 0.826 vs 0.806, ECE 0.0015). The shipped model was trained on all years up to 2024, so retraining it from 2020 is a candidate improvement; the headline comparison with CVSS and EPSS holds either way.
