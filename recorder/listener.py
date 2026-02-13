#!/usr/bin/env python3
"""
FLLC - Voice-Activated Recorder (listener.py)
=====================================================
Monitors the default microphone and records audio clips
when ambient volume exceeds 50dB threshold.

Saves compressed audio to the MP3 drive (J:).

Dependencies:
    pip install pyaudio numpy pydub

For MP3 encoding, pydub needs ffmpeg OR lame on PATH.
If neither is available, falls back to WAV format.

AUTHORIZED USE ONLY.
FLLC
"""

import os
import sys
import wave
import math
import time
import struct
import logging
import argparse
import tempfile
from pathlib import Path
from datetime import datetime
from threading import Thread, Event

try:
    import pyaudio
except ImportError:
    print("[!] pyaudio not installed. Run: pip install pyaudio")
    sys.exit(1)

try:
    import numpy as np
    HAS_NUMPY = True
except ImportError:
    HAS_NUMPY = False

try:
    from pydub import AudioSegment
    HAS_PYDUB = True
except ImportError:
    HAS_PYDUB = False


# ============================================================================
#  CONFIGURATION
# ============================================================================

DEFAULT_CONFIG = {
    # Audio settings
    'sample_rate': 16000,       # 16kHz - good for voice
    'channels': 1,              # Mono
    'chunk_size': 1024,         # Samples per buffer
    'sample_format': pyaudio.paInt16,
    'bits_per_sample': 16,

    # Trigger settings
    'db_threshold': 50.0,       # dB threshold to start recording
    'silence_timeout': 3.0,     # Seconds of silence before stopping
    'min_clip_duration': 1.0,   # Minimum clip length (seconds)
    'max_clip_duration': 300.0, # Maximum clip length (5 minutes)

    # Storage
    'output_format': 'mp3',     # 'mp3' or 'wav'
    'mp3_bitrate': '32k',      # Low bitrate for space efficiency
    'max_storage_mb': 180,      # Stop when this much space is used

    # Behavior
    'pre_buffer_seconds': 0.5,  # Keep 0.5s of audio before trigger
}


# ============================================================================
#  UTILITY FUNCTIONS
# ============================================================================

def rms_to_db(rms, ref=1.0):
    """Convert RMS amplitude to decibels."""
    if rms <= 0:
        return -100.0
    return 20.0 * math.log10(rms / ref)


def calculate_rms(data, sample_width=2):
    """Calculate RMS of audio data."""
    if HAS_NUMPY:
        if sample_width == 2:
            samples = np.frombuffer(data, dtype=np.int16)
        else:
            samples = np.frombuffer(data, dtype=np.int8)
        if len(samples) == 0:
            return 0.0
        return float(np.sqrt(np.mean(samples.astype(np.float64) ** 2)))
    else:
        # Pure Python fallback
        count = len(data) // sample_width
        if count == 0:
            return 0.0
        fmt = f'<{count}h'
        try:
            shorts = struct.unpack(fmt, data)
        except struct.error:
            return 0.0
        sum_sq = sum(s * s for s in shorts)
        return math.sqrt(sum_sq / count)


def get_storage_used_mb(directory):
    """Calculate total size of files in directory in MB."""
    total = 0
    try:
        for f in Path(directory).rglob('*'):
            if f.is_file():
                total += f.stat().st_size
    except Exception:
        pass
    return total / (1024 * 1024)


def find_output_drive():
    """Auto-detect the MP3 drive (J:) or fallback."""
    # Windows: Check for J: drive
    if sys.platform == 'win32':
        for letter in ['J', 'K', 'L', 'M']:
            drive = f"{letter}:\\"
            if os.path.exists(drive):
                return drive

    # Linux/Mac: look for MP3 labeled mount
    for mount_base in ['/media', '/mnt', '/run/media']:
        if os.path.isdir(mount_base):
            for d in os.listdir(mount_base):
                full = os.path.join(mount_base, d)
                if 'MP3' in d.upper() or 'mp3' in d:
                    return full
                if os.path.isdir(full):
                    for sub in os.listdir(full):
                        if 'MP3' in sub.upper():
                            return os.path.join(full, sub)

    # Fallback to script directory
    return os.path.dirname(os.path.abspath(__file__))


# ============================================================================
#  VOICE-ACTIVATED RECORDER
# ============================================================================

class VoiceActivatedRecorder:
    def __init__(self, config=None, output_dir=None):
        self.config = {**DEFAULT_CONFIG, **(config or {})}
        self.output_base = output_dir or find_output_drive()
        self.recordings_dir = os.path.join(self.output_base, 'recordings')
        os.makedirs(self.recordings_dir, exist_ok=True)

        # Setup logging
        log_path = os.path.join(self.output_base, 'listener.log')
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s | %(levelname)s | %(message)s',
            handlers=[
                logging.FileHandler(log_path, encoding='utf-8'),
            ]
        )
        self.logger = logging.getLogger('listener')

        # Audio
        self.audio = pyaudio.PyAudio()
        self.stream = None

        # State
        self.is_running = Event()
        self.is_recording = False
        self.clip_count = 0
        self.total_recorded_seconds = 0

        # Pre-buffer (circular buffer for pre-trigger audio)
        pre_buf_chunks = int(
            self.config['pre_buffer_seconds'] *
            self.config['sample_rate'] /
            self.config['chunk_size']
        )
        self.pre_buffer_size = max(pre_buf_chunks, 1)
        self.pre_buffer = []

        # Check pydub/ffmpeg availability
        self.can_mp3 = False
        if HAS_PYDUB:
            try:
                # Quick check if ffmpeg is available
                AudioSegment.converter  # This will fail if ffmpeg not found
                self.can_mp3 = True
            except Exception:
                pass

        if not self.can_mp3 and self.config['output_format'] == 'mp3':
            self.logger.warning("pydub/ffmpeg not available, falling back to WAV format")
            self.config['output_format'] = 'wav'

        self.logger.info(f"Recorder initialized. Output: {self.recordings_dir}")
        self.logger.info(f"Threshold: {self.config['db_threshold']}dB, "
                         f"Format: {self.config['output_format']}, "
                         f"Max storage: {self.config['max_storage_mb']}MB")

    def _open_stream(self):
        """Open the audio input stream."""
        try:
            self.stream = self.audio.open(
                format=self.config['sample_format'],
                channels=self.config['channels'],
                rate=self.config['sample_rate'],
                input=True,
                frames_per_buffer=self.config['chunk_size'],
            )
            self.logger.info("Audio stream opened")
            return True
        except Exception as e:
            self.logger.error(f"Failed to open audio stream: {e}")
            return False

    def _close_stream(self):
        """Close the audio stream."""
        if self.stream:
            try:
                self.stream.stop_stream()
                self.stream.close()
            except Exception:
                pass
        self.stream = None

    def _save_clip(self, frames):
        """Save recorded frames as an audio file."""
        if not frames:
            return None

        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        base_name = f"clip_{timestamp}"

        # Calculate duration
        total_samples = sum(len(f) for f in frames) // (self.config['bits_per_sample'] // 8)
        duration = total_samples / self.config['sample_rate']

        if duration < self.config['min_clip_duration']:
            self.logger.debug(f"Clip too short ({duration:.1f}s), discarding")
            return None

        # Save as WAV first
        wav_path = os.path.join(self.recordings_dir, f"{base_name}.wav")
        try:
            with wave.open(wav_path, 'wb') as wf:
                wf.setnchannels(self.config['channels'])
                wf.setsampwidth(self.config['bits_per_sample'] // 8)
                wf.setframerate(self.config['sample_rate'])
                wf.writeframes(b''.join(frames))
        except Exception as e:
            self.logger.error(f"Failed to save WAV: {e}")
            return None

        # Convert to MP3 if possible
        final_path = wav_path
        if self.config['output_format'] == 'mp3' and self.can_mp3:
            mp3_path = os.path.join(self.recordings_dir, f"{base_name}.mp3")
            try:
                audio_seg = AudioSegment.from_wav(wav_path)
                audio_seg.export(mp3_path, format='mp3',
                                 bitrate=self.config['mp3_bitrate'])
                os.remove(wav_path)  # Remove WAV to save space
                final_path = mp3_path
            except Exception as e:
                self.logger.warning(f"MP3 conversion failed, keeping WAV: {e}")

        self.clip_count += 1
        self.total_recorded_seconds += duration
        file_size = os.path.getsize(final_path) / 1024  # KB

        self.logger.info(
            f"Clip saved: {os.path.basename(final_path)} "
            f"({duration:.1f}s, {file_size:.0f}KB) "
            f"[Total: {self.clip_count} clips, "
            f"{self.total_recorded_seconds:.0f}s recorded]"
        )
        return final_path

    def _check_storage(self):
        """Check if we've exceeded storage limits."""
        used = get_storage_used_mb(self.recordings_dir)
        if used >= self.config['max_storage_mb']:
            self.logger.warning(
                f"Storage limit reached ({used:.1f}MB / "
                f"{self.config['max_storage_mb']}MB). Stopping."
            )
            return False
        return True

    def run(self):
        """Main recording loop."""
        self.logger.info("=== VOICE-ACTIVATED RECORDER STARTED ===")

        if not self._open_stream():
            return

        self.is_running.set()
        silence_start = None
        recording_frames = []
        recording_start = None

        try:
            while self.is_running.is_set():
                # Read audio chunk
                try:
                    data = self.stream.read(
                        self.config['chunk_size'],
                        exception_on_overflow=False
                    )
                except Exception as e:
                    self.logger.error(f"Stream read error: {e}")
                    time.sleep(0.1)
                    continue

                # Calculate volume
                rms = calculate_rms(data, sample_width=self.config['bits_per_sample'] // 8)
                db = rms_to_db(rms, ref=32768.0) + 96  # Normalize: silence ~0dB, max ~96dB

                # Maintain pre-buffer
                self.pre_buffer.append(data)
                if len(self.pre_buffer) > self.pre_buffer_size:
                    self.pre_buffer.pop(0)

                if not self.is_recording:
                    # Not currently recording - check if we should start
                    if db >= self.config['db_threshold']:
                        self.is_recording = True
                        recording_start = time.time()
                        silence_start = None
                        # Include pre-buffer
                        recording_frames = list(self.pre_buffer)
                        self.pre_buffer.clear()
                        self.logger.info(f"Recording triggered (volume: {db:.1f}dB)")
                else:
                    # Currently recording
                    recording_frames.append(data)
                    elapsed = time.time() - recording_start

                    if db >= self.config['db_threshold']:
                        # Still loud - reset silence timer
                        silence_start = None
                    else:
                        # Silence detected
                        if silence_start is None:
                            silence_start = time.time()
                        elif (time.time() - silence_start) >= self.config['silence_timeout']:
                            # Silence timeout reached - stop recording
                            self.logger.info(
                                f"Silence detected, stopping recording "
                                f"({elapsed:.1f}s)"
                            )
                            self._save_clip(recording_frames)
                            recording_frames = []
                            self.is_recording = False
                            silence_start = None

                            # Check storage
                            if not self._check_storage():
                                self.is_running.clear()
                                break

                    # Check max clip duration
                    if elapsed >= self.config['max_clip_duration']:
                        self.logger.info(
                            f"Max clip duration reached ({elapsed:.1f}s), "
                            f"saving and continuing"
                        )
                        self._save_clip(recording_frames)
                        recording_frames = []
                        recording_start = time.time()

                        if not self._check_storage():
                            self.is_running.clear()
                            break

        except KeyboardInterrupt:
            self.logger.info("Interrupted by user")
        finally:
            # Save any remaining recording
            if recording_frames:
                self._save_clip(recording_frames)

            self._close_stream()
            self.audio.terminate()

            self.logger.info(
                f"=== RECORDER STOPPED === "
                f"Clips: {self.clip_count}, "
                f"Total recorded: {self.total_recorded_seconds:.0f}s"
            )

    def stop(self):
        """Signal the recorder to stop."""
        self.is_running.clear()


# ============================================================================
#  MAIN
# ============================================================================

def main():
    parser = argparse.ArgumentParser(
        description='FLLC - Voice-Activated Recorder'
    )
    parser.add_argument(
        '--output', '-o', default=None,
        help='Output directory for recordings (default: auto-detect MP3 drive)'
    )
    parser.add_argument(
        '--threshold', '-t', type=float, default=50.0,
        help='dB threshold to trigger recording (default: 50)'
    )
    parser.add_argument(
        '--silence', '-s', type=float, default=3.0,
        help='Seconds of silence before stopping recording (default: 3)'
    )
    parser.add_argument(
        '--format', '-f', choices=['mp3', 'wav'], default='mp3',
        help='Output format (default: mp3)'
    )
    parser.add_argument(
        '--bitrate', '-b', default='32k',
        help='MP3 bitrate (default: 32k)'
    )
    parser.add_argument(
        '--max-storage', '-m', type=int, default=180,
        help='Maximum storage in MB (default: 180)'
    )
    parser.add_argument(
        '--sample-rate', type=int, default=16000,
        help='Sample rate in Hz (default: 16000)'
    )

    args = parser.parse_args()

    config = {
        'db_threshold': args.threshold,
        'silence_timeout': args.silence,
        'output_format': args.format,
        'mp3_bitrate': args.bitrate,
        'max_storage_mb': args.max_storage,
        'sample_rate': args.sample_rate,
    }

    recorder = VoiceActivatedRecorder(config=config, output_dir=args.output)

    print(f"""
  =============================================
   FLLC - Voice-Activated Recorder
  =============================================
   Threshold:   {args.threshold} dB
   Silence:     {args.silence}s
   Format:      {args.format} ({args.bitrate})
   Max Storage: {args.max_storage} MB
   Output:      {recorder.recordings_dir}
  =============================================
   Listening... (Ctrl+C to stop)
""")

    recorder.run()


if __name__ == '__main__':
    main()
