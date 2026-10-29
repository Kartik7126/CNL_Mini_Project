import unittest
import time
import sys
import os
import joblib

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
from sniffer import _Bucket
from pipeline import _is_whitelisted, _AlertCooldown


class TestSnifferFeatures(unittest.TestCase):
    def test_single_packet_rate_not_inflated(self):
        """Ensure a single packet does not produce inflated 1000 PPS."""
        bucket = _Bucket(start=time.time())
        bucket.add(size=74, port=443, is_syn=False)
        feat = bucket.to_features(window_duration=2.0)
        
        self.assertLessEqual(feat["packets_per_sec"], 1.5)
        self.assertEqual(feat["avg_packet_size"], 74.0)
        self.assertEqual(feat["unique_ports"], 1)
        self.assertEqual(feat["syn_ratio"], 0.0)

    def test_streaming_traffic_features(self):
        """Simulate YouTube video streaming: high PPS, high packet size, zero SYN ratio."""
        bucket = _Bucket(start=time.time() - 1.0)
        # Add 100 packets across 0.5 seconds
        for _ in range(100):
            bucket.add(size=1400, port=443, is_syn=False)
        feat = bucket.to_features(window_duration=2.0)

        self.assertGreater(feat["packets_per_sec"], 50)
        self.assertEqual(feat["avg_packet_size"], 1400.0)
        self.assertEqual(feat["unique_ports"], 1)
        self.assertEqual(feat["syn_ratio"], 0.0)

    def test_syn_flood_features(self):
        """Simulate SYN flood: high PPS, tiny packets, syn_ratio == 1.0."""
        bucket = _Bucket(start=time.time() - 1.0)
        for _ in range(200):
            bucket.add(size=54, port=80, is_syn=True)
        feat = bucket.to_features(window_duration=2.0)

        self.assertGreater(feat["packets_per_sec"], 100)
        self.assertEqual(feat["avg_packet_size"], 54.0)
        self.assertEqual(feat["unique_ports"], 1)
        self.assertEqual(feat["syn_ratio"], 1.0)

    def test_port_scan_features(self):
        """Simulate port scan: many ports, small packets, syn_ratio == 1.0."""
        bucket = _Bucket(start=time.time() - 1.0)
        for p in range(1, 101):
            bucket.add(size=60, port=p, is_syn=True)
        feat = bucket.to_features(window_duration=2.0)

        self.assertEqual(feat["avg_packet_size"], 60.0)
        self.assertEqual(feat["unique_ports"], 100)
        self.assertEqual(feat["syn_ratio"], 1.0)


class TestTrainedModel(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        model_path = os.path.join(os.path.dirname(__file__), "..", "data", "network_model.pkl")
        cls.clf = joblib.load(model_path)

    def test_youtube_video_stream_is_normal(self):
        """High PPS video streaming must be classified as normal (0)."""
        # [pps, avg_packet_size, unique_ports, syn_ratio]
        X = [[450.0, 1350.0, 1, 0.0]]
        pred = self.clf.predict(X)[0]
        proba = self.clf.predict_proba(X)[0]
        self.assertEqual(pred, 0, f"Expected normal (0), got {pred} with proba {proba}")

    def test_google_web_search_is_normal(self):
        """Google web browsing traffic must be classified as normal (0)."""
        X = [[30.0, 650.0, 2, 0.02]]
        pred = self.clf.predict(X)[0]
        self.assertEqual(pred, 0)

    def test_high_pps_download_is_normal(self):
        """1200 PPS file download (e.g. fast broadband) must be classified as normal (0)."""
        X = [[1200.0, 1420.0, 1, 0.0]]
        pred = self.clf.predict(X)[0]
        self.assertEqual(pred, 0)

    def test_syn_flood_detected(self):
        """Volumetric SYN flood must be classified as syn_flood (2)."""
        X = [[2500.0, 54.0, 1, 0.98]]
        pred = self.clf.predict(X)[0]
        self.assertEqual(pred, 2)

    def test_port_scan_detected(self):
        """Port sweep must be classified as port_scan (1)."""
        X = [[40.0, 60.0, 150, 0.95]]
        pred = self.clf.predict(X)[0]
        self.assertEqual(pred, 1)

    def test_attacker_source_ip_scan_detected(self):
        """Simulated port scan from 198.51.100.99 across 500 ports."""
        X = [[50.0, 60.0, 500, 1.0]]
        proba = self.clf.predict_proba(X)[0]
        self.assertEqual(int(proba.argmax()), 1)
        self.assertGreaterEqual(float(proba[1]), 0.85)

    def test_attacker_source_ip_flood_detected(self):
        """Simulated SYN flood from 198.51.100.99 with 750 PPS."""
        X = [[750.0, 54.0, 1, 1.0]]
        proba = self.clf.predict_proba(X)[0]
        self.assertEqual(int(proba.argmax()), 2)
        self.assertGreaterEqual(float(proba[2]), 0.85)


    def test_fast_port_scan_detected(self):
        """Fast port scan sweep (800 PPS, 500 ports) must classify as port_scan with >=95% confidence."""
        X = [[800.0, 54.0, 500, 1.0]]
        proba = self.clf.predict_proba(X)[0]
        self.assertEqual(int(proba.argmax()), 1)
        self.assertGreaterEqual(float(proba[1]), 0.95)

    def test_stealth_port_scan_detected(self):
        """Stealth port scan (15 PPS, 80 ports) must classify as port_scan with >=85% confidence."""
        X = [[15.0, 60.0, 80, 0.90]]
        proba = self.clf.predict_proba(X)[0]
        self.assertEqual(int(proba.argmax()), 1)
        self.assertGreaterEqual(float(proba[1]), 0.85)


class TestGeolocation(unittest.TestCase):
    def test_private_ip_returns_local_network(self):
        from alerts import geolocate
        for ip in ("127.0.0.1", "192.168.1.10", "10.0.0.5", "172.16.0.1"):
            geo = geolocate(ip)
            self.assertEqual(geo["country"], "Local/Private Network")


class TestFirewallState(unittest.TestCase):
    def test_firewall_redirect_tracking(self):
        from unittest.mock import patch
        from firewall import redirect_to_honeypot, remove_redirect, active_redirects, flush_all_redirects
        test_ip = "203.0.113.77"
        with patch("firewall._run", return_value=True):
            redirect_to_honeypot(test_ip)
            self.assertIn(test_ip, active_redirects())
            remove_redirect(test_ip)
            self.assertNotIn(test_ip, active_redirects())


class TestAlertCooldown(unittest.TestCase):
    def test_distinct_attacks_from_same_ip_not_blocked(self):
        cooldown = _AlertCooldown(60.0)
        # Record a SYN flood from attacker
        cooldown.record("198.51.100.99", 2)
        # Same attack is on cooldown
        self.assertFalse(cooldown.allowed("198.51.100.99", 2))
        # Different attack (port scan) is allowed immediately
        self.assertTrue(cooldown.allowed("198.51.100.99", 1))

    def test_same_attack_cooldown_expires(self):
        cooldown = _AlertCooldown(1.0)
        cooldown.record("198.51.100.99", 2, now=100.0)
        self.assertFalse(cooldown.allowed("198.51.100.99", 2, now=100.5))
        self.assertTrue(cooldown.allowed("198.51.100.99", 2, now=101.5))


class TestWhitelist(unittest.TestCase):
    def test_loopback_whitelisted(self):
        self.assertTrue(_is_whitelisted("127.0.0.1"))
        self.assertTrue(_is_whitelisted("::1"))

    def test_external_not_whitelisted_by_default(self):
        self.assertFalse(_is_whitelisted("198.51.100.23"))


class TestCumulativeScanTracker(unittest.TestCase):
    def setUp(self):
        from pipeline import CumulativeScanTracker
        self.tracker = CumulativeScanTracker(
            history_seconds=120.0,
            threshold_ports=20,
            min_syn_ratio=0.75,
            max_avg_pkt_size=120.0,
        )

    def test_single_burst_below_threshold_does_not_trigger(self):
        feat = {
            "ports_set": set(range(1, 11)),
            "unique_ports": 10,
            "packet_count": 10,
            "packets_per_sec": 5.0,
            "syn_count": 10,
            "syn_ratio": 1.0,
            "avg_packet_size": 60.0,
        }
        is_scan, cum_feat = self.tracker.record_and_evaluate("198.51.100.77", feat, now=100.0)
        self.assertFalse(is_scan)
        self.assertEqual(cum_feat["unique_ports"], 10)

    def test_chunked_bursts_accumulate_and_trigger(self):
        # 1st burst: 12 ports at t=100s
        feat1 = {
            "ports_set": set(range(1, 13)),
            "unique_ports": 12,
            "packet_count": 12,
            "packets_per_sec": 6.0,
            "syn_count": 12,
            "syn_ratio": 1.0,
            "avg_packet_size": 60.0,
        }
        is_scan1, _ = self.tracker.record_and_evaluate("198.51.100.77", feat1, now=100.0)
        self.assertFalse(is_scan1)

        # 2nd burst: 12 different ports at t=105s (cumulative unique = 24 >= 20)
        feat2 = {
            "ports_set": set(range(13, 25)),
            "unique_ports": 12,
            "packet_count": 12,
            "packets_per_sec": 6.0,
            "syn_count": 12,
            "syn_ratio": 1.0,
            "avg_packet_size": 60.0,
        }
        is_scan2, cum_feat2 = self.tracker.record_and_evaluate("198.51.100.77", feat2, now=105.0)
        self.assertTrue(is_scan2)
        self.assertEqual(cum_feat2["unique_ports"], 24)
        self.assertEqual(cum_feat2["syn_ratio"], 1.0)
        self.assertLessEqual(cum_feat2["avg_packet_size"], 120.0)

    def test_repeated_same_port_does_not_trigger_scan(self):
        # 20 packets to the same port 80
        feat = {
            "ports_set": {80},
            "unique_ports": 1,
            "packet_count": 20,
            "packets_per_sec": 20.0,
            "syn_count": 20,
            "syn_ratio": 1.0,
            "avg_packet_size": 60.0,
        }
        is_scan, cum_feat = self.tracker.record_and_evaluate("198.51.100.77", feat, now=100.0)
        self.assertFalse(is_scan)
        self.assertEqual(cum_feat["unique_ports"], 1)

    def test_benign_traffic_not_flagged(self):
        # 25 unique ports but payload traffic (low syn_ratio, large packets)
        feat = {
            "ports_set": set(range(1024, 1049)),
            "unique_ports": 25,
            "packet_count": 100,
            "packets_per_sec": 50.0,
            "syn_count": 2,
            "syn_ratio": 0.02,
            "avg_packet_size": 1200.0,
        }
        is_scan, _ = self.tracker.record_and_evaluate("198.51.100.77", feat, now=100.0)
        self.assertFalse(is_scan)

    def test_old_bursts_expire_past_window(self):
        # 1st burst at t=100s
        feat1 = {
            "ports_set": set(range(1, 13)),
            "unique_ports": 12,
            "packet_count": 12,
            "packets_per_sec": 6.0,
            "syn_count": 12,
            "syn_ratio": 1.0,
            "avg_packet_size": 60.0,
        }
        self.tracker.record_and_evaluate("198.51.100.77", feat1, now=100.0)

        # 2nd burst at t=250s (> 120s later -> feat1 has expired)
        feat2 = {
            "ports_set": set(range(13, 25)),
            "unique_ports": 12,
            "packet_count": 12,
            "packets_per_sec": 6.0,
            "syn_count": 12,
            "syn_ratio": 1.0,
            "avg_packet_size": 60.0,
        }
        is_scan2, cum_feat2 = self.tracker.record_and_evaluate("198.51.100.77", feat2, now=250.0)
        self.assertFalse(is_scan2)
        self.assertEqual(cum_feat2["unique_ports"], 12)


class TestISTConversion(unittest.TestCase):
    def test_utc_to_ist_conversion(self):
        import pandas as pd
        from utils import to_ist
        s = pd.Series(["2026-10-17T10:00:00+00:00"])
        ist = to_ist(s)
        self.assertEqual(ist.iloc[0], "2026-10-17 15:30:00 IST")


if __name__ == "__main__":
    unittest.main()

