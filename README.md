# Sentry-AV

Windows / macOS 공용 백신 + 랜섬웨어 차단 도구 (Python 3.10+). Windows 는 관리자 권한(UAC)으로, macOS 는 암호 입력 없이 현재 사용자 권한으로 실행됩니다.

| 기능 | 설명 |
|---|---|
| `scan` | 해시 시그니처(EICAR·abuse.ch 피드) + 휴리스틱(섀도 복사본 삭제, 랜섬노트, 암호화된 문서, 드로퍼 패턴 등) + 선택적 YARA 로 파일 검사. 서명이 온전한 앱의 원본 파일은 제외, `--quarantine` 로 격리 |
| `monitor` | 실시간 보호: 파일 이벤트 + 미끼(카나리) 파일 + 프로세스 명령줄 규칙 + 프로세스별 디스크 쓰기량 추적 → 공격 프로세스 종료·스크립트 격리 |
| `quarantine` | XOR 난독화 격리 저장소 목록/복원/삭제 (파일 권한 보존) |
| `whitelist` | 신뢰 프로세스/경로 추가. Riot Vanguard, EasyAntiCheat, BattlEye, Defender, XProtect, 클라우드 동기화 클라이언트는 기본 포함 |
| `service` | 부팅/로그온 시 자동 실행 (Windows 작업 스케줄러 최고 권한 / macOS LaunchAgent, root 면 LaunchDaemon / systemd) |
| `selftest` | 무해한 테스트 샘플을 만들어 검사 엔진 확인 |

## 다른 PC에 설치

**A. 소스로 실행 (Python 3.10+ 만 있으면 됨)**

1. `sentry-av-0.1.0-src.zip` 을 풀어 원하는 폴더에 둡니다.
2. Windows: python.org 설치 시 "Add python.exe to PATH" 체크 → 폴더에서 `run.bat selftest`. 처음 한 번 `.venv` 를 만들고 의존성을 받습니다(인터넷 필요).
   macOS/Linux: `./run.sh selftest` (Python 3 는 macOS 에 기본 포함; 없으면 `xcode-select --install`).
3. 이후 `run.bat monitor` / `./run.sh monitor`, 부팅 시 자동 실행은 `run.bat service install` / `./run.sh service install`.

**B. 단일 실행 파일 (Python 불필요)**

- 빌드는 **대상 OS 위에서** 해야 합니다. Windows: `build.bat` → `dist\sentry.exe` (UAC 자동 요청 매니페스트 포함). macOS/Linux: `./build.sh` → `dist/sentry`.
- Windows PC 가 없으면 **GitHub Actions** 로 만듭니다. `.github/workflows/build-windows.yml` 이 `main` 에 푸시될 때마다 Windows 러너에서 테스트·빌드·자가 진단을 거쳐 `sentry-windows-x64` 아티팩트(`sentry.exe`)를 올립니다. 받기: `gh run download -n sentry-windows-x64 -D <폴더>` (저장소 `yunch0315/sentry-av`, 비공개). PyInstaller 는 교차 빌드를 지원하지 않으므로 Mac 에서 직접 exe 를 만들 수는 없습니다. 수동 실행은 Actions 탭의 Run workflow.
- 만들어진 파일 하나만 복사하면 됩니다. 같은 OS·CPU 아키텍처에서만 동작합니다 (`sentry-macos-arm64` 는 Apple Silicon Mac 전용, Intel Mac 은 그 Mac 에서 `./build.sh`).
- 사용법은 동일: `sentry.exe scan`, `sentry.exe monitor`, `./sentry-macos-arm64 selftest` 등. 더블클릭으로 실행하면 번호 메뉴가 뜨고, 작업이 끝나면 "엔터를 누르면 창이 닫힙니다" 에서 엔터를 누르면 창이 닫힙니다(macOS 터미널은 Finder 로 연 창만 자동으로 닫고, 이미 쓰던 셸 창은 그대로 둠). 터미널에서 직접 실행했을 때는 이 대기 없이 바로 끝납니다. macOS 에서 서명되지 않은 바이너리는 첫 실행 시 `xattr -d com.apple.quarantine ./sentry-macos-arm64` 가 필요할 수 있습니다.
- Windows Defender/SmartScreen 이 서명 없는 새 exe 를 경고할 수 있습니다. 프로세스를 종료하고 파일을 격리하는 도구이므로 다른 백신의 예외 목록에 설치 폴더와 `%USERPROFILE%\.sentry-av` 를 넣어 두는 것이 좋습니다.

설정·격리·로그는 어느 방식이든 사용자 홈의 `.sentry-av` 폴더에 저장되므로 프로그램 폴더는 어디에 두어도 됩니다.

## 자동 업데이트 (GitHub Releases)

단일 실행 파일은 GitHub Releases 에서 **스스로 새 버전으로 교체**됩니다 (`sentry/selfupdate.py`).

- **배포 측**: `./release.sh 0.2.0` 이 버전을 올리고 태그 `v0.2.0` 을 푸시합니다. `.github/workflows/release.yml` 이 Windows 러너와 Apple Silicon 러너에서 테스트·빌드·자가 진단을 거쳐 `sentry-windows-x64.exe`, `sentry-macos-arm64`, `SHA256SUMS.txt` 를 Release 에 올립니다(태그와 `__version__` 이 다르면 실패). 진행 확인: `gh run watch`.
- **설치된 프로그램 측**:
  - 어떤 명령이든 실행하면 하루에 한 번(`update_check_interval_hours`) 백그라운드에서 최신 릴리스를 확인하고, 새 버전이 있으면 한 줄로 알립니다. 메뉴 화면에도 표시됩니다.
  - `sentry upgrade` (메뉴 9번): 확인 → 다운로드 → `SHA256SUMS.txt` 와 대조 → 실행 파일을 원자적으로 교체(이전 파일은 `sentry.old` 로 남겼다가 다음 실행 때 삭제) → 새 버전 재실행. `--check` 는 확인만(새 버전 있으면 종료 코드 3), `--yes` 는 묻지 않음.
  - **실시간 보호(`monitor`, 서비스 포함)** 는 `auto_update: true`(기본) 일 때 주기적으로 확인해 새 버전을 설치하고 **스스로 재시작**합니다(macOS 는 같은 PID 로 `execv`, Windows 는 새 프로세스 기동 후 종료 — 예약 작업/LaunchAgent 는 그대로 유지).
  - 소스 체크아웃(`run.sh`/`run.bat`)에서는 교체하지 않고 `git pull` 을 안내합니다.
- **비공개 저장소**: GitHub 의 Release API 는 비공개 저장소에서 토큰이 필요합니다. 테스트용으로는 환경변수 `SENTRY_GITHUB_TOKEN` 또는 `config.json` 의 `update_token` (해당 저장소 Contents 읽기 권한만 있는 fine-grained PAT) 을 넣습니다. **판매·배포 시에는 토큰을 나눠 줄 수 없으므로** 저장소를 공개로 바꾸거나, 바이너리만 올리는 공개 저장소(예: `yunch0315/sentry-av-releases`)를 만들고 `update_repo` 를 그곳으로 바꿔야 합니다.
- HTTPS 는 OS 신뢰 저장소(`truststore`)로 검증하고, 안 되면 번들된 `certifi` 를 씁니다(CI 에서 빌드한 Python 은 자체 CA 번들이 없어 그냥 두면 macOS 에서 인증서 오류).
- 다운로드 파일은 반드시 같은 Release 의 `SHA256SUMS.txt` 와 일치해야 설치되며, 불일치·누락 시 아무것도 바꾸지 않습니다. 저장소 쓰기 권한(태그 푸시)을 가진 사람만 업데이트를 배포할 수 있으므로 GitHub 계정의 2단계 인증을 켜 두세요.

## 실행

```sh
./run.sh selftest                 # macOS/Linux (첫 실행 시 .venv 생성)
./run.sh scan ~/Downloads
./run.sh monitor                  # 암호 입력 없음(현재 사용자 권한). 루트가 필요하면 ./run.sh --sudo monitor
run.bat monitor                   # Windows (UAC 상승 자동)
```

**권한.** Windows 에서는 `scan`/`monitor`/`service` 실행 시 UAC 창으로 관리자 권한을 요청하고, 거부하면 제한된 권한으로 계속합니다. macOS/Linux 에서는 **암호를 묻지 않고 현재 사용자 권한으로 바로 실행**됩니다. 사용자 권한 모드에서도 내 계정이 실행한 프로세스(랜섬웨어는 보통 사용자 권한으로 실행됨)와 내 파일은 모두 보호되며, 다른 사용자·시스템 프로세스 제어와 시스템 전역 서비스 등록만 제한됩니다. `service install` 은 로그인 시 실행되는 사용자 LaunchAgent 로 등록합니다. 루트가 꼭 필요하면 `--sudo` 를 붙이면 로그인 암호를 물어 sudo 로 실행하고(Ctrl+C 로 건너뛰면 사용자 권한으로 계속), 또는 `sudo ./run.sh ...` 로 직접 실행해도 됩니다. `--no-elevate` 는 Windows 에서도 권한 요청을 생략하고, `--dry-run` 은 감지·기록만 하고 절대 종료하지 않습니다.

## 파일 검사가 판단하는 방식 (오탐 정책)

파일 검사는 **이름이 아니라 내용**을 봅니다. 단서는 두 등급으로 나뉩니다.

- **강한 단서**: 악성코드 외에는 거의 쓰지 않는 것. 섀도 복사본·백업 삭제(`vssadmin delete shadows`, `wbadmin`, `tmutil deletelocalsnapshots`), 복구 비활성화(`bcdedit`), Defender 끄기, 랜섬노트 문구("your files have been encrypted"), 재귀 암호화 루프, 보안 프로그램 강제 종료, 리버스 셸, 실제 페이로드가 붙은 `-EncodedCommand` 등.
- **약한 단서**: 정상 프로그램에도 흔한 것. base64 덩어리, 암호화 API, "bitcoin" 같은 단어, 다국어 파일의 제로폭 문자, PowerShell 숨김 플래그, `Invoke-Expression` 등.

**강한 단서가 하나 이상 있거나, 서로 다른 약한 단서가 4개 이상 쌓여 8점 이상**일 때만 보고합니다(전형적인 드로퍼는 약한 단서만으로 이루어져 있으므로). 약한 단서 한두 개로는 절대 보고하지 않습니다. 점수 8 이상 high, 5 이상 medium, 3 이상 low 이며, low 는 표에서 생략하고 JSON 보고서에만 남깁니다(`--show-low`).

추가로 다음을 적용합니다.

- **서명 검증**: 보고 직전에 그 파일이 서명이 온전한 앱의 원본인지 확인합니다. macOS 는 앱 번들의 `_CodeSignature/CodeResources` 봉인 목록에 있는 SHA-256 과 파일 해시를 대조하고 번들 실행 파일의 서명(Apple·App Store·Developer ID)을 검증합니다. Mach-O 는 `codesign --verify` 로 직접, Windows 는 `Get-AuthenticodeSignature` 로 확인합니다. 통과하면 휴리스틱 결과를 버립니다(해시 시그니처 일치는 서명과 무관하게 항상 보고). 발견된 파일에 대해서만 수행하므로 비용이 작습니다. 끄려면 설정 `trust_signed_files: false`.
- **압축 파일**(`.jar`, `.zip`, `.whl`, `.asar` 등)은 내용 문자열 검사를 하지 않고 해시만 대조합니다. 압축된 바이트에서 문자열을 찾는 것은 의미가 없습니다.
- **랜섬웨어 산출물**: 확장자 목록(`.locked` 등)은 원래 문서 확장자가 남아 있거나(`보고서.docx.locked`) 내용이 난수일 때만 인정합니다. `.lock`, `.java` 같은 흔한 확장자는 목록에서 뺐습니다. 이중 확장자와 "헤더 불일치"도 내용이 알려진 다른 형식(JPEG 이 `.png` 로 저장된 경우 등)이 아니고 엔트로피가 난수 수준일 때만 봅니다. 랜섬노트는 파일 이름만으로는 절대 보고하지 않고 본문 문구가 함께 있어야 합니다(`README.txt`, `help.html` 은 보고되지 않음).
- **자기 자신 제외**: 이 프로그램의 소스·빌드는 검사에서 뺍니다. 탐지 규칙 자체가 탐지 대상 문자열을 담고 있기 때문입니다.

빠른 검사(메뉴 1번)는 사용자 폴더·임시 폴더·자동 실행 항목만 봅니다. `/Applications` 와 시스템 전체는 전체 디스크 검사(메뉴 2번)에서 봅니다.

## 실시간 차단이 동작하는 방식

1. **감지** (`realtime/detector.py`): 10초 창 안의 이벤트를 집계합니다. 카나리 파일 변조(내용 해시가 실제로 바뀐 경우만), 랜섬웨어 확장자/미지 확장자로의 대량 rename, 문서 파일의 고엔트로피 덮어쓰기, 랜섬노트 생성. 강한 신호 2개 이상 또는 강한 신호 1개 + 이벤트 폭주 → `ransomware`. 카나리 적중·rename 폭주 시 판단 루프를 즉시 깨웁니다.
2. **귀속** (`realtime/responder.py`): 신뢰되지 않은 모든 프로세스에 증거 점수를 매깁니다.

   | 증거 | 점수 | 종류 |
   |---|---|---|
   | 피해 파일/디렉터리에 열린 핸들 | +10 | 직접 |
   | 명령줄에 피해 디렉터리 포함 | +6 | 직접 |
   | 작업 디렉터리가 피해 디렉터리 안 | +4 | 직접 |
   | 방금 시작 / 30분 내 시작 | +3 / +1 | 표적 |
   | 임시·다운로드 폴더에서 실행 | +2 | |
   | 창 내 쓰기 ≥32KB / ≥320KB / 최다 쓰기 | +4 / +2 / +2 | |
   | 창 내 CPU 사용 | +1 | |
   | 유효한 코드 서명(Developer ID / Authenticode) | −4 | |

   **종료**: 점수 ≥ `kill_score`(10) 이고 표적 증거가 있는 프로세스. 직접 증거가 있는 용의자가 있으면 그것만 종료합니다. **정지**: 점수 ≥ `suspend_score`(5) + 표적 증거 → `suspend_hold_seconds`(30초) 동안 동결 후 자동 재개. 쓰기만 많은 장기 실행 프로세스(IDE·브라우저)는 보고만 합니다(`--aggressive` 에서는 정지·종료). 자기 자신과 조상 프로세스(터미널, IDE)는 절대 건드리지 않습니다.
3. **격리**: 종료한 프로세스의 실행 파일(신뢰 경로/서명 제외)과 인터프리터에 넘겨진 스크립트를 격리합니다.
4. **명령줄 규칙** (`realtime/process_watch.py`): `vssadmin delete shadows`, `bcdedit recoveryenabled no`, `tmutil deletelocalsnapshots`, Defender 비활성화 등은 누가 실행하든 즉시 종료(신뢰 안 된 부모 포함).

프로세스별 쓰기량은 Windows/Linux 에서 `psutil.io_counters`, macOS 에서 `proc_pid_rusage` 로 1초마다 샘플링합니다(`realtime/activity.py`).

## 테스트

```sh
.venv/bin/python -m pytest -q tests            # 단위 테스트 (감지기, 귀속 정책, 규칙, 샘플러)
```

실시간 차단 통합 테스트 — 무해한 시뮬레이터가 **지정 폴더 안의 파일만** 덮어쓰고 rename 합니다:

```sh
T=$(mktemp -d); mkdir $T/victim $T/home
for i in $(seq 1 80); do printf '%%PDF-1.4 doc %d\n' $i > $T/victim/d$i.pdf; done
cat > $T/sim.py <<'PY'
import os, sys, time
d = sys.argv[1]
for n in sorted(os.listdir(d)):
    p = os.path.join(d, n)
    with open(p, "r+b") as f: f.write(os.urandom(4096))
    os.rename(p, p + ".locked"); time.sleep(0.02)
PY
SENTRY_HOME=$T/home .venv/bin/python -m sentry --no-elevate monitor $T/victim &
sleep 6; python3 $T/sim.py $T/victim; echo "exit=$?"
kill -INT %1; cat $T/home/.sentry-av/incidents.jsonl
```

기대 결과: 시뮬레이터가 1초 안에 종료(exit 137)되고 대부분의 파일이 보존되며, `sim.py` 가 격리됩니다.

## 설정

`~/.sentry-av/config.json` (처음 실행 시 기본값으로 생성). 주요 키: `monitor_paths`, `excluded_paths`, `whitelist_process_names`, `whitelist_path_prefixes`, `trusted_team_ids`, `kill_score`, `suspend_score`, `min_write_bytes`, `suspend_hold_seconds`, `aggressive`, `signature_urls`, 자동 업데이트 `update_repo`, `auto_update`, `update_check_interval_hours`, `update_token`. 마지막 확인 시각·최신 버전은 `~/.sentry-av/update_state.json`.

로그 `~/.sentry-av/sentry.log`, 사건 기록 `~/.sentry-av/incidents.jsonl`, 격리 `~/.sentry-av/quarantine/`.

## 한계

- 사용자 모드 도구입니다. 커널 드라이버/ESF 기반 제품처럼 쓰기를 **사전** 차단하지는 못하며, 감지 후 수백 ms 안에 종료하므로 그 사이 일부 파일은 암호화될 수 있습니다. 백업과 함께 사용하세요.
- 다른 사용자의 프로세스를 다루려면 관리자/루트 권한이 필요합니다.
- 서명 검사는 `codesign` / `Get-AuthenticodeSignature` 를 호출하므로 첫 검사에 수백 ms 가 걸릴 수 있습니다(경로별 캐시).
