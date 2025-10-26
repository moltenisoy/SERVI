"""
Anti-cheat module for PES server
Provides detection and prevention of various cheating methods:
- Cheat Engine and memory manipulation
- Intentional lag/connection manipulation
- Modified game clients
- Network limiters and throttling
"""

import time
import hashlib
import struct
from datetime import datetime, timedelta
from twisted.internet import defer
from fiveserver import log


class PacketTimingAnalyzer:
    """
    Analyzes packet timing patterns to detect suspicious behavior
    such as intentional lag or network manipulation
    """
    
    def __init__(self, window_size=100, lag_threshold=2.0):
        self.window_size = window_size
        self.lag_threshold = lag_threshold  # seconds
        self.packet_times = []
        self.response_times = []
        self.last_packet_time = None
        self.anomaly_count = 0
        self.lag_spike_history = []
        self.micro_lag_patterns = []
        
    def record_packet(self, packet_id):
        """Record incoming packet timestamp"""
        current_time = time.time()
        
        if self.last_packet_time:
            time_delta = current_time - self.last_packet_time
            self.packet_times.append(time_delta)
            
            # Keep only recent history
            if len(self.packet_times) > self.window_size:
                self.packet_times.pop(0)
                
            # Detect suspicious patterns
            if time_delta > self.lag_threshold:
                self.anomaly_count += 1
                self.lag_spike_history.append({
                    'time': current_time,
                    'duration': time_delta,
                    'packet_id': packet_id
                })
                log.msg(f'ANTICHEAT: Suspicious lag detected: {time_delta:.2f}s (packet: 0x{packet_id:04x})')
            
            # Detect micro-lag patterns (rapid small delays that sum up)
            if 0.5 < time_delta < 1.5:
                self.micro_lag_patterns.append(current_time)
                # Keep only recent micro-lags
                cutoff = current_time - 30
                self.micro_lag_patterns = [t for t in self.micro_lag_patterns if t > cutoff]
                
                # If too many micro-lags in short period
                if len(self.micro_lag_patterns) > 10:
                    log.msg(f'ANTICHEAT: Micro-lag pattern detected (possible lag manipulation)')
        
        self.last_packet_time = current_time
        
    def record_response_time(self, response_time):
        """Record packet response time"""
        self.response_times.append(response_time)
        if len(self.response_times) > self.window_size:
            self.response_times.pop(0)
    
    def get_average_latency(self):
        """Calculate average latency"""
        if not self.response_times:
            return 0.0
        return sum(self.response_times) / len(self.response_times)
    
    def detect_lag_spike_pattern(self):
        """
        Detect patterns indicating intentional lag generation
        Returns True if suspicious pattern detected
        """
        if len(self.packet_times) < 20:
            return False
        
        # Clean old lag spike history
        current_time = time.time()
        cutoff = current_time - 300  # 5 minutes
        self.lag_spike_history = [
            spike for spike in self.lag_spike_history 
            if spike['time'] > cutoff
        ]
        
        # Check for alternating fast/slow pattern (lag switch behavior)
        alternating_count = 0
        for i in range(1, min(20, len(self.packet_times))):
            if (self.packet_times[i] > self.lag_threshold and 
                self.packet_times[i-1] < 0.1):
                alternating_count += 1
        
        if alternating_count > 3:
            log.msg('ANTICHEAT: Lag switch pattern detected!')
            return True
        
        # Check for periodic lag spikes (another lag switch signature)
        if len(self.lag_spike_history) >= 5:
            spike_times = [spike['time'] for spike in self.lag_spike_history[-5:]]
            intervals = [spike_times[i+1] - spike_times[i] for i in range(len(spike_times)-1)]
            avg_interval = sum(intervals) / len(intervals) if intervals else 0
            
            # If spikes occur at regular intervals (within 20% variance)
            if avg_interval > 0:
                variance = sum((x - avg_interval) ** 2 for x in intervals) / len(intervals)
                if variance / (avg_interval ** 2) < 0.04:  # 20% coefficient of variation
                    log.msg('ANTICHEAT: Periodic lag spike pattern detected!')
                    return True
            
        return False
    
    def detect_strategic_lag(self):
        """
        Detect lag that occurs at strategically important moments
        This is harder to detect but we can look for patterns
        Returns True if suspicious strategic lag detected
        """
        if len(self.lag_spike_history) < 3:
            return False
        
        # Check if lag spikes cluster together (burst lag)
        recent_spikes = [spike for spike in self.lag_spike_history[-10:]]
        if len(recent_spikes) >= 3:
            spike_times = [spike['time'] for spike in recent_spikes]
            # If multiple spikes within 10 seconds
            if spike_times[-1] - spike_times[0] < 10:
                log.msg('ANTICHEAT: Burst lag pattern detected!')
                return True
        
        return False
    
    def get_anomaly_score(self):
        """Calculate anomaly score based on behavior"""
        if not self.packet_times:
            return 0
            
        score = 0
        
        # High anomaly count
        if self.anomaly_count > 10:
            score += 30
        elif self.anomaly_count > 5:
            score += 15
            
        # Lag spike pattern
        if self.detect_lag_spike_pattern():
            score += 40
        
        # Strategic lag detection
        if self.detect_strategic_lag():
            score += 35
        
        # Micro-lag pattern
        if len(self.micro_lag_patterns) > 10:
            score += 25
            
        # Inconsistent timing variance
        if len(self.packet_times) >= 10:
            variance = sum((x - sum(self.packet_times)/len(self.packet_times))**2 
                          for x in self.packet_times) / len(self.packet_times)
            if variance > 1.0:
                score += 20
                
        return min(100, score)


class ClientIntegrityChecker:
    """
    Checks client integrity through various methods to detect
    modified clients or memory manipulation (Cheat Engine)
    """
    
    def __init__(self):
        self.known_client_hashes = {}
        self.integrity_violations = {}
        
    def register_known_version(self, version_name, expected_hash):
        """Register a known legitimate client version hash"""
        self.known_client_hashes[version_name] = expected_hash
        
    def verify_client_hash(self, user_hash, provided_hash):
        """
        Verify client executable hash
        Returns (is_valid, violation_reason)
        """
        # Check against known legitimate versions
        if provided_hash in self.known_client_hashes.values():
            return True, None
            
        # If no match found with known versions
        if self.known_client_hashes:
            log.msg(f'ANTICHEAT: Unknown client hash detected for user {user_hash}')
            return False, "Unknown client version"
            
        # If no known hashes registered, allow (permissive mode)
        return True, None
    
    def check_packet_integrity(self, packet_data, expected_structure):
        """
        Verify packet structure hasn't been tampered with
        Returns True if packet appears legitimate
        """
        if len(packet_data) != expected_structure.get('length', len(packet_data)):
            log.msg('ANTICHEAT: Packet length mismatch detected')
            return False
            
        # Additional integrity checks can be added here
        return True
    
    def record_violation(self, user_hash, violation_type):
        """Record integrity violation for user"""
        if user_hash not in self.integrity_violations:
            self.integrity_violations[user_hash] = []
            
        self.integrity_violations[user_hash].append({
            'type': violation_type,
            'timestamp': datetime.now()
        })
        
        log.msg(f'ANTICHEAT: Integrity violation recorded for {user_hash}: {violation_type}')
    
    def get_violation_count(self, user_hash):
        """Get total violation count for user"""
        return len(self.integrity_violations.get(user_hash, []))


class MemoryIntegrityMonitor:
    """
    Monitor for memory manipulation and Cheat Engine detection
    Uses packet checksums and expected value validation
    """
    
    def __init__(self):
        self.value_history = {}
        self.checksum_failures = {}
        self.value_change_frequency = {}
        self.statistical_baseline = {}
        
    def validate_game_values(self, user_hash, values_dict):
        """
        Validate that game values are within expected ranges
        values_dict: {'points': 1000, 'stats': {...}, etc}
        Returns (is_valid, violations)
        """
        violations = []
        
        # Check for impossible values
        if 'points' in values_dict:
            points = values_dict['points']
            if points < 0 or points > 999999999:
                violations.append('impossible_points_value')
                log.msg(f'ANTICHEAT: Impossible points value detected: {points}')
            # Detect suspiciously round numbers (common Cheat Engine signature)
            elif points > 0 and points % 100000 == 0 and points > 100000:
                violations.append('suspicious_round_points')
                log.msg(f'ANTICHEAT: Suspiciously round points value: {points}')
        
        if 'goals_scored' in values_dict:
            goals = values_dict['goals_scored']
            if goals < 0 or goals > 999999:
                violations.append('impossible_goals_value')
                log.msg(f'ANTICHEAT: Impossible goals value detected: {goals}')
        
        # Check for sudden impossible changes
        if user_hash in self.value_history:
            old_values = self.value_history[user_hash]
            
            if 'points' in values_dict and 'points' in old_values:
                point_change = abs(values_dict['points'] - old_values['points'])
                # Maximum realistic point change in one game
                if point_change > 1000:
                    violations.append('suspicious_point_change')
                    log.msg(f'ANTICHEAT: Suspicious point change: {point_change}')
                
                # Track frequency of value changes (rapid changes = possible memory scanning)
                self._track_value_change_frequency(user_hash, 'points')
        
        # Detect statistical anomalies
        if self._detect_statistical_anomaly(user_hash, values_dict):
            violations.append('statistical_anomaly')
        
        # Store current values for future comparison
        self.value_history[user_hash] = values_dict.copy()
        
        return len(violations) == 0, violations
    
    def _track_value_change_frequency(self, user_hash, value_name):
        """
        Track how frequently values are changing
        Frequent changes may indicate memory scanning with Cheat Engine
        """
        if user_hash not in self.value_change_frequency:
            self.value_change_frequency[user_hash] = {}
        
        if value_name not in self.value_change_frequency[user_hash]:
            self.value_change_frequency[user_hash][value_name] = {
                'count': 0,
                'last_change': time.time(),
                'changes': []
            }
        
        freq_data = self.value_change_frequency[user_hash][value_name]
        current_time = time.time()
        freq_data['count'] += 1
        freq_data['changes'].append(current_time)
        
        # Keep only changes in last 5 minutes
        cutoff = current_time - 300
        freq_data['changes'] = [t for t in freq_data['changes'] if t > cutoff]
        
        # If more than 20 changes in 5 minutes, suspicious
        if len(freq_data['changes']) > 20:
            log.msg(f'ANTICHEAT: Rapid value changes detected for {user_hash}: {value_name}')
            return True
        
        return False
    
    def _detect_statistical_anomaly(self, user_hash, values_dict):
        """
        Use statistical analysis to detect anomalous patterns
        Returns True if anomaly detected
        """
        if user_hash not in self.statistical_baseline:
            self.statistical_baseline[user_hash] = {
                'points_history': [],
                'goals_history': []
            }
        
        baseline = self.statistical_baseline[user_hash]
        
        # Track points progression
        if 'points' in values_dict:
            points = values_dict['points']
            baseline['points_history'].append(points)
            
            # Keep only recent history
            if len(baseline['points_history']) > 50:
                baseline['points_history'].pop(0)
            
            # Detect sudden jumps that deviate from normal progression
            if len(baseline['points_history']) >= 10:
                recent = baseline['points_history'][-10:]
                avg = sum(recent) / len(recent)
                
                # If current value is way outside normal range
                if points > avg * 2 and points > 10000:
                    log.msg(f'ANTICHEAT: Statistical anomaly in points for {user_hash}')
                    return True
        
        return False
    
    def verify_packet_checksum(self, user_hash, packet, expected_checksum):
        """
        Verify packet checksum to detect memory manipulation
        """
        actual_checksum = hashlib.md5(packet.data).hexdigest()
        
        if actual_checksum != expected_checksum:
            if user_hash not in self.checksum_failures:
                self.checksum_failures[user_hash] = 0
            self.checksum_failures[user_hash] += 1
            
            log.msg(f'ANTICHEAT: Checksum mismatch for user {user_hash}')
            return False
            
        return True


class NetworkBehaviorMonitor:
    """
    Monitor network behavior patterns to detect throttling,
    limiters, or other network-level cheating
    """
    
    def __init__(self):
        self.connection_stats = {}
        self.packet_counts = {}
        self.bandwidth_samples = {}
        self.upload_pattern_history = {}
        self.jitter_samples = {}
        
    def record_packet_size(self, user_hash, packet_size):
        """Record packet size for bandwidth analysis"""
        if user_hash not in self.bandwidth_samples:
            self.bandwidth_samples[user_hash] = {
                'sizes': [],
                'timestamps': [],
                'start_time': time.time(),
                'upload_sizes': [],
                'upload_timestamps': []
            }
        
        stats = self.bandwidth_samples[user_hash]
        current_time = time.time()
        stats['sizes'].append(packet_size)
        stats['timestamps'].append(current_time)
        
        # Track upload bandwidth specifically for saturation detection
        if packet_size > 100:  # Only count substantial packets as uploads
            stats['upload_sizes'].append(packet_size)
            stats['upload_timestamps'].append(current_time)
        
        # Keep only recent samples (last 60 seconds)
        cutoff_time = current_time - 60
        while stats['timestamps'] and stats['timestamps'][0] < cutoff_time:
            stats['timestamps'].pop(0)
            stats['sizes'].pop(0)
        
        # Clean upload samples
        while stats['upload_timestamps'] and stats['upload_timestamps'][0] < cutoff_time:
            stats['upload_timestamps'].pop(0)
            stats['upload_sizes'].pop(0)
        
        # Record jitter for variance analysis
        self._record_jitter(user_hash, current_time)
    
    def _record_jitter(self, user_hash, current_time):
        """Record packet arrival jitter for network quality analysis"""
        if user_hash not in self.jitter_samples:
            self.jitter_samples[user_hash] = {
                'intervals': [],
                'last_time': current_time
            }
            return
        
        jitter_data = self.jitter_samples[user_hash]
        interval = current_time - jitter_data['last_time']
        jitter_data['intervals'].append(interval)
        jitter_data['last_time'] = current_time
        
        # Keep only recent samples
        if len(jitter_data['intervals']) > 100:
            jitter_data['intervals'].pop(0)
    
    def detect_upload_saturation(self, user_hash):
        """
        Detect intentional upload bandwidth saturation
        Returns True if saturation pattern detected
        """
        if user_hash not in self.bandwidth_samples:
            return False
        
        stats = self.bandwidth_samples[user_hash]
        
        if len(stats['upload_sizes']) < 10:
            return False
        
        # Calculate upload bytes per second
        total_upload = sum(stats['upload_sizes'])
        time_span = stats['upload_timestamps'][-1] - stats['upload_timestamps'][0]
        
        if time_span <= 0:
            return False
        
        upload_bps = total_upload / time_span
        
        # Detect suspiciously high upload rates (potential saturation attack)
        # Typical game traffic should be < 50KB/s
        if upload_bps > 51200:  # 50KB/s threshold
            log.msg(f'ANTICHEAT: Upload saturation detected for {user_hash}: {upload_bps:.2f} B/s')
            return True
        
        # Check for burst patterns (alternating high/low upload)
        if len(stats['upload_sizes']) >= 20:
            recent_uploads = stats['upload_sizes'][-20:]
            avg_size = sum(recent_uploads) / len(recent_uploads)
            bursts = sum(1 for size in recent_uploads if size > avg_size * 3)
            if bursts > 10:
                log.msg(f'ANTICHEAT: Upload burst pattern detected for {user_hash}')
                return True
        
        return False
    
    def detect_network_variance_anomaly(self, user_hash):
        """
        Detect anomalous network variance patterns that may indicate
        manipulation of network conditions
        Returns True if suspicious variance detected
        """
        if user_hash not in self.jitter_samples:
            return False
        
        intervals = self.jitter_samples[user_hash]['intervals']
        
        if len(intervals) < 20:
            return False
        
        # Calculate variance in packet intervals
        mean_interval = sum(intervals) / len(intervals)
        variance = sum((x - mean_interval) ** 2 for x in intervals) / len(intervals)
        std_dev = variance ** 0.5
        
        # High coefficient of variation indicates unstable connection
        # which could be artificial
        if mean_interval > 0:
            cv = std_dev / mean_interval
            if cv > 2.0:  # Very high variation
                log.msg(f'ANTICHEAT: High network variance detected for {user_hash}: CV={cv:.2f}')
                return True
        
        return False
    
    def detect_bandwidth_throttling(self, user_hash):
        """
        Detect artificial bandwidth limiting
        Returns True if throttling detected
        """
        if user_hash not in self.bandwidth_samples:
            return False
            
        stats = self.bandwidth_samples[user_hash]
        
        if len(stats['sizes']) < 10:
            return False
        
        # Calculate bytes per second
        total_bytes = sum(stats['sizes'])
        time_span = stats['timestamps'][-1] - stats['timestamps'][0]
        
        if time_span <= 0:
            return False
            
        bytes_per_second = total_bytes / time_span
        
        # Suspiciously low bandwidth (less than 1KB/s)
        if bytes_per_second < 1024:
            log.msg(f'ANTICHEAT: Bandwidth throttling detected for {user_hash}: {bytes_per_second:.2f} B/s')
            return True
        
        # Check for consistent low-bandwidth pattern (network limiter signature)
        if len(stats['sizes']) >= 30:
            recent_samples = stats['sizes'][-30:]
            avg_size = sum(recent_samples) / len(recent_samples)
            # If all packets are suspiciously similar size, may indicate limiting
            size_variance = sum((x - avg_size) ** 2 for x in recent_samples) / len(recent_samples)
            if avg_size < 200 and size_variance < 100:
                log.msg(f'ANTICHEAT: Network limiter signature detected for {user_hash}')
                return True
            
        return False
    
    def analyze_packet_pattern(self, user_hash, packet_id):
        """Analyze packet sending patterns"""
        if user_hash not in self.packet_counts:
            self.packet_counts[user_hash] = {}
        
        if packet_id not in self.packet_counts[user_hash]:
            self.packet_counts[user_hash][packet_id] = 0
            
        self.packet_counts[user_hash][packet_id] += 1
        
        # Detect spam patterns
        if self.packet_counts[user_hash][packet_id] > 100:
            log.msg(f'ANTICHEAT: Packet spam detected for {user_hash}, packet 0x{packet_id:04x}')
            return False
            
        return True


class AntiCheatSystem:
    """
    Main anti-cheat system coordinating all detection methods
    """
    
    def __init__(self, config=None):
        self.config = config or {}
        self.enabled = self.config.get('enabled', True)
        
        # Initialize subsystems
        self.timing_analyzer = {}  # per-user
        self.integrity_checker = ClientIntegrityChecker()
        self.memory_monitor = MemoryIntegrityMonitor()
        self.network_monitor = NetworkBehaviorMonitor()
        
        # Violation tracking
        self.user_violations = {}
        self.ban_threshold = self.config.get('ban_threshold', 100)
        
        log.msg('AntiCheat System initialized')
    
    def get_timing_analyzer(self, user_hash):
        """Get or create timing analyzer for user"""
        if user_hash not in self.timing_analyzer:
            self.timing_analyzer[user_hash] = PacketTimingAnalyzer()
        return self.timing_analyzer[user_hash]
    
    def on_packet_received(self, user_hash, packet):
        """Called when a packet is received from a client"""
        if not self.enabled:
            return True
            
        # Record packet timing
        analyzer = self.get_timing_analyzer(user_hash)
        analyzer.record_packet(packet.header.id)
        
        # Record packet size for bandwidth analysis
        self.network_monitor.record_packet_size(user_hash, packet.header.length)
        
        # Analyze packet patterns
        if not self.network_monitor.analyze_packet_pattern(user_hash, packet.header.id):
            self.record_violation(user_hash, 'packet_spam')
        
        # Check for bandwidth throttling
        if self.network_monitor.detect_bandwidth_throttling(user_hash):
            self.record_violation(user_hash, 'bandwidth_throttling')
        
        # Check for upload saturation attacks
        if self.network_monitor.detect_upload_saturation(user_hash):
            self.record_violation(user_hash, 'upload_saturation')
        
        # Check for network variance anomalies
        if self.network_monitor.detect_network_variance_anomaly(user_hash):
            self.record_violation(user_hash, 'network_variance_anomaly')
        
        return True
    
    def verify_client_version(self, user_hash, roster_hash):
        """Verify client version through roster hash"""
        if not self.enabled:
            return True, None
            
        # The roster hash can be used to verify client version
        is_valid, reason = self.integrity_checker.verify_client_hash(user_hash, roster_hash)
        
        if not is_valid:
            self.record_violation(user_hash, f'client_version: {reason}')
            
        return is_valid, reason
    
    def validate_game_state(self, user_hash, game_values):
        """Validate game state values for tampering"""
        if not self.enabled:
            return True
            
        is_valid, violations = self.memory_monitor.validate_game_values(
            user_hash, game_values)
        
        if not is_valid:
            for violation in violations:
                self.record_violation(user_hash, f'memory_integrity: {violation}')
                
        return is_valid
    
    def record_violation(self, user_hash, violation_type):
        """Record a violation and update user score"""
        if user_hash not in self.user_violations:
            self.user_violations[user_hash] = {
                'score': 0,
                'violations': [],
                'first_violation': datetime.now()
            }
        
        self.user_violations[user_hash]['violations'].append({
            'type': violation_type,
            'timestamp': datetime.now()
        })
        
        # Update violation score
        severity_map = {
            'packet_spam': 10,
            'bandwidth_throttling': 15,
            'upload_saturation': 20,
            'network_variance_anomaly': 18,
            'client_version': 30,
            'memory_integrity': 40,
            'suspicious_round_points': 35,
            'statistical_anomaly': 30,
            'lag_switch': 25
        }
        
        # Find severity for this violation type
        severity = 10  # default
        for key, value in severity_map.items():
            if key in violation_type:
                severity = value
                break
        
        self.user_violations[user_hash]['score'] += severity
        
        log.msg(f'ANTICHEAT: Violation recorded for {user_hash}: {violation_type} '
                f'(score: {self.user_violations[user_hash]["score"]})')
    
    def should_ban_user(self, user_hash):
        """Check if user should be banned based on violations"""
        if not self.enabled:
            return False
            
        if user_hash not in self.user_violations:
            return False
            
        score = self.user_violations[user_hash]['score']
        
        # Also check timing anomalies
        if user_hash in self.timing_analyzer:
            anomaly_score = self.timing_analyzer[user_hash].get_anomaly_score()
            score += anomaly_score
        
        if score >= self.ban_threshold:
            log.msg(f'ANTICHEAT: Ban threshold reached for {user_hash} (score: {score})')
            return True
            
        return False
    
    def get_user_report(self, user_hash):
        """Get anti-cheat report for user"""
        report = {
            'violations': self.user_violations.get(user_hash, {}).get('violations', []),
            'score': self.user_violations.get(user_hash, {}).get('score', 0),
            'timing_anomaly_score': 0,
            'should_ban': False
        }
        
        if user_hash in self.timing_analyzer:
            report['timing_anomaly_score'] = self.timing_analyzer[user_hash].get_anomaly_score()
        
        report['should_ban'] = self.should_ban_user(user_hash)
        
        return report
    
    def cleanup_user(self, user_hash):
        """Clean up tracking data for disconnected user"""
        if user_hash in self.timing_analyzer:
            del self.timing_analyzer[user_hash]
        # Keep violation history for potential re-connection


# Global anti-cheat instance
_anticheat_instance = None


def get_anticheat_system(config=None):
    """Get or create the global anti-cheat system instance"""
    global _anticheat_instance
    if _anticheat_instance is None:
        _anticheat_instance = AntiCheatSystem(config)
    return _anticheat_instance
