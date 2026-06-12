# version.py - application version module
# Purpose: Compose SystemShield version metadata from MainProgram.EngineVersion.DetectionVersion.

VERSION_SCHEME = "MainProgram.EngineVersion.DetectionVersion"
MAIN_PROGRAM_VERSION = "1"
ENGINE_VERSION = "4"
DETECTION_VERSION = "2"
VERSION = f"{MAIN_PROGRAM_VERSION}.{ENGINE_VERSION}.{DETECTION_VERSION}"
APP_USER_MODEL_ID = f"WebGeeks.SystemShield.{VERSION}"
