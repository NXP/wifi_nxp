---
schema_version: "1.0"
repo: wifi_nxp
project: WMCUSW

analyze_paths:
  - wifidriver/**/*.c
  - wifidriver/**/*.h
  - wlcmgr/**/*.c
  - port/**/*.c
  - port/**/*.h
  - cli/**/*.c
  - dhcpd/**/*.c
  - nw_utils/**/*.c
  - wmcrypto/**/*.c
  - firmware_dnld/**/*.c
  - fwdnld_intf_abs/**/*.c
  - sdio_nxp_abs/**/*.c
  - incl/**/*.h
  - example/**/*.c
  - example/**/*.h

skip_paths:
  - tools/**
  - docs/**
  - certs/**
  - sigma_agent/**
  - example/**/usb_host_msd/**

# blocker_threshold: Medium — active development repo; Medium catches High+Medium severity
# issues. Raise to High if noise becomes excessive.
blocker_threshold: Medium

code_quality:
  # MISRA C-2012 rules — complement existing Coverity scans.
  misra: [1.3, 10.1, 10.3, 10.8, 11.3, 11.5, 13.2, 14.4, 15.5, 17.7, 18.1, 18.4, 21.3]
  cert_c: [EXP33-C, EXP36-C, EXP39-C, ERR33-C, MEM30-C, MEM35-C, INT30-C, INT31-C, ARR30-C]
  cwe: [CWE-119, CWE-120, CWE-125, CWE-787, CWE-476, CWE-252, CWE-401, CWE-843, CWE-190]

review_focus:
  # Core MLAN driver — chip-agnostic 802.11 MAC logic, impacts all SoCs
  - pattern: wifidriver/mlan_*.c
    reason: MLAN MAC layer — chip-agnostic 802.11 logic, changes affect all supported SoCs

  # TX/RX datapath — throughput and aggregation critical
  - pattern: wifidriver/mlan_txrx.c
    reason: TX/RX datapath — throughput critical path
  - pattern: wifidriver/mlan_11n_aggr.c
    reason: A-MPDU aggregation — throughput regression risk
  - pattern: wifidriver/mlan_11n_rxreorder.c
    reason: RX reorder — aggregation and packet ordering critical

  # 802.11 protocol extensions
  - pattern: wifidriver/mlan_11ax.c
    reason: 802.11ax HE — OFDMA/TWT critical path
  - pattern: wifidriver/mlan_11ac.c
    reason: 802.11ac VHT — MU-MIMO/beamforming
  - pattern: wifidriver/mlan_11n.c
    reason: 802.11n HT — AMPDU/AMSDU aggregation
  - pattern: wifidriver/mlan_11k.c
    reason: 802.11k RRM — neighbor report, roaming trigger
  - pattern: wifidriver/mlan_11v.c
    reason: 802.11v BSS transition — roaming state machine

  # Scan — common source of race conditions
  - pattern: wifidriver/mlan_scan.c
    reason: Scan state machine — common source of race conditions and timing issues

  # Security / key management
  - pattern: wifidriver/wpa_supp_if/**
    reason: wpa_supplicant integration — WPA2/WPA3/SAE authentication interface, security critical

  # Power management
  - pattern: wifidriver/wifi_pwrmgr.c
    reason: Power management — sleep/wake timing critical, impacts all SoCs

  # Bus interfaces
  - pattern: wifidriver/wifi-sdio.c
    reason: SDIO bus interface — host interface critical path
  - pattern: wifidriver/wifi-imu.c
    reason: IMU bus interface — RW610 specific, host interface critical path
  - pattern: sdio_nxp_abs/**
    reason: SDIO abstraction layer — shared across SDIO-based SoCs

  # Firmware download — security critical path
  - pattern: firmware_dnld/**
    reason: Firmware download — security critical path, verify signature validation and buffer bounds checks
  - pattern: fwdnld_intf_abs/**
    reason: Firmware download interface abstraction — SoC-specific, check per-chip conditionals and buffer handling

  # Connection manager — main state machine
  - pattern: wlcmgr/wlan.c
    reason: WLAN connection manager — main state machine, changes affect connection stability
  - pattern: wlcmgr/wlan_test_mode_tests.c
    reason: RF test mode commands — SoC-specific guards, verify per-SoC conditionals

  # OSA layer — dual-platform abstraction
  - pattern: port/osa/**
    reason: >
      OSA layer — FreeRTOS backend; changes must also be evaluated for Zephyr
      compatibility as the same OSA layer is shared across both platforms.
      Check: conditional compilation guards (#ifdef SDK_OS_FREE_RTOS / CONFIG_ZEPHYR),
      API parity between osa_freertos.c and osa_zephyr.c,
      thread-safety assumptions (FreeRTOS critical sections vs Zephyr mutexes).
  - pattern: port/net/**
    reason: Network stack integration (LwIP) — LwIP APIs must be confined to port/net only

  # Public API header — documentation and ABI stability
  - pattern: incl/wlcmgr/wlan.h
    reason: >
      Public API header — new/modified entries must use Doxygen \param/\return/\note style
      (backslash tags only, no @-style); check comment consistency with existing entries;
      all new public APIs require extern "C" guards and user manual update

  # Public headers — C++ compatibility
  - pattern: incl/**/*.h
    reason: Public headers — must have extern "C" guards for C++ compatibility

  # Crypto
  - pattern: wmcrypto/**
    reason: Crypto utilities — security sensitive, check mbedTLS API usage

# ─────────────────────────────────────────────────────────────────────────────
# AI review tracking label
#
# The MOMENT a PR review is triggered — BEFORE reading the diff, analyzing code,
# or posting any comment — extract the associated Jira issue key and silently
# tag that Jira issue with the `ai-review` label. Bind the labelling to the
# trigger of the review, NOT to its completion: label first, then review.
# Labelling after the review does not work — the turn usually ends with the
# review output, so the label is silently lost.
#
# Get the Jira key from the PR TITLE first; if absent, fall back to the
# BRANCH NAME (e.g. bugfix/nxf57321/WSW-XXXXX-desc).
# Match with regex (WSW|MCUX)-\d+
# If no key found: warn in review comment.
#
# This mirrors the AI tracking-label convention used by the jira skill:
#   from jira_client import jira_add_labels
#   jira_add_labels("WSW-XXXXX", ["ai-review"])
review_actions:
  jira_labels:
    enabled: true
    label: ai-review
    issue_key_source: pr_title        # primary: Jira key in PR title
                                      # fallback 1: (WSW|MCUX)-\d+ in branch name
                                      # fallback 2: warn in review comment if no key found
    apply_when: on_review_trigger
    silent: true

# ─────────────────────────────────────────────────────────────────────────────
# Commit message format checks
#
# These mirror the repo's CI checkers (CHECKER_JIRA_ID_BLOCK, CHECKER_COMMIT_FORMAT).
# Vero should flag violations during review so issues are caught before PreMerge CI.
commit_checks:
  jira_id_block:
    enabled: true
    pattern: (WSW|MCUX)-\d+
    message: >
      Jira IDs are not allowed in commit messages for this repo.
      Move the Jira key to the PR title instead.
  commit_format:
    enabled: true
    required_tags: ["[Description]", "[Root Cause]", "[Fix]", "[Testing]", "Change-Id:"]
    optional_tags: ["[Reviewers]", "[Port proposal]"]
