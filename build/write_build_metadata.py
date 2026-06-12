# write_build_metadata.py - build metadata generator module
# Purpose: Generate PyInstaller version resources and release notes from SystemShield version metadata.

from pathlib import Path
import re
import sys
import textwrap


PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from core.version import VERSION  # noqa: E402


def _version_tuple(version: str) -> tuple[int, int, int, int]:
    parts = []
    for chunk in version.split("."):
        try:
            parts.append(int(chunk))
        except ValueError:
            parts.append(0)
    while len(parts) < 4:
        parts.append(0)
    return tuple(parts[:4])


def _build_version_resource(version: str) -> str:
    version_tuple = _version_tuple(version)
    return textwrap.dedent(
        f"""\
        VSVersionInfo(
          ffi=FixedFileInfo(
            filevers={version_tuple},
            prodvers={version_tuple},
            mask=0x3F,
            flags=0x0,
            OS=0x40004,
            fileType=0x1,
            subtype=0x0,
            date=(0, 0)
          ),
          kids=[
            StringFileInfo(
              [
                StringTable(
                  '040904B0',
                  [
                    StringStruct('CompanyName', 'WebGeeks'),
                    StringStruct('FileDescription', 'WebGeeks SystemShield'),
                    StringStruct('FileVersion', '{version}'),
                    StringStruct('InternalName', 'SystemShield'),
                    StringStruct('OriginalFilename', 'SystemShield.exe'),
                    StringStruct('ProductName', 'WebGeeks SystemShield'),
                    StringStruct('ProductVersion', '{version}'),
                    StringStruct('Comments', 'Windows security auditing and remediation guidance')
                  ]
                )
              ]
            ),
            VarFileInfo([VarStruct('Translation', [1033, 1200])])
          ]
        )
        """
    )


def _build_release_notes(version: str) -> str:
    version_variants = (
        version,
        version.replace(".", "_"),
    )
    changelog_candidates = (
        *(PROJECT_ROOT / f"CHANGELOG_{variant}.md" for variant in version_variants),
        *(PROJECT_ROOT / "docs" / f"CHANGELOG_{variant}.md" for variant in version_variants),
    )
    for changelog_path in changelog_candidates:
        if changelog_path.exists():
            content = changelog_path.read_text(encoding="utf-8").strip()
            summary_only = re.split(r"\r?\n## ", content, maxsplit=1)[0].strip()
            return summary_only + "\n"

    return textwrap.dedent(
        f"""\
        # SystemShield v{version}

        - Updated the Python desktop packaging workflow for the current application version.
        - Refreshed release metadata generation for PyInstaller and GitHub release publication.
        """
    )


def main() -> int:
    docs_dir = PROJECT_ROOT / "docs"
    docs_dir.mkdir(parents=True, exist_ok=True)

    version_resource_path = docs_dir / "systemshield-version-info.txt"
    version_resource_path.write_text(_build_version_resource(VERSION), encoding="utf-8")

    release_notes_path = docs_dir / "release-notes.md"
    release_notes_path.write_text(_build_release_notes(VERSION), encoding="utf-8")

    print(version_resource_path)
    print(release_notes_path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
