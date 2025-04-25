# WHS_Secure_Coding

## 📦 중고거래 사이트 - 환경 설정 및 실행 방법

---

## 🖥️ 요구 사항

- Python 3.11 이상
- Linux (Ubuntu) 또는 Windows 환경
- Git 설치
- (권장) Miniconda 또는 Python Virtual Environment 사용

---

## 🛠️ 의존성 설치

```bash
pip install -r requirements.txt
```

---

## ⚙️ 환경 설정

### Linux (Ubuntu) 기준

```bash
# git 설치
sudo apt update
sudo apt install git

# Python 및 venv 설치
sudo apt install python3 python3-venv python3-pip

# 프로젝트 클론
git clone https://github.com/HanTul/WHS_Secure_Coding.git
cd WHS_Secure_Coding

# 가상환경 생성 및 활성화
python3 -m venv venv
source venv/bin/activate

# 의존성 설치
pip install -r requirements.txt
```

### Windows 기준 (CMD)

```bash
: git 설치 (https://git-scm.com/download/win 에서 설치)
:: Python 설치 (https://www.python.org/downloads/)

:: 프로젝트 클론
git clone https://github.com/HanTul/WHS_Secure_Coding.git
cd WHS_Secure_Coding

:: 가상환경 생성 및 활성화
python -m venv venv
venv\Scripts\activate

:: 의존성 설치
pip install -r requirements.txt
```

---

## ▶️ 실행 방법

```bash
python app.py
```

---

## 🛡️ 관리자 계정 정보

첫 실행 시 `admin / 1` 계정이 자동 생성됩니다.

해당 계정 정보는 `app.py`에 하드코딩되어 있으므로 실제 서비스 배포 시 반드시 수정이 필요합니다.