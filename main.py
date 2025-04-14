import os, sys, time, cmd, base64, json, math
import qrcode, requests, schedule
from datetime import datetime, timedelta
import xml.etree.ElementTree as ET
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import coloredlogs, logging
from rich import print, box
from rich.console import Console
from rich.table import Table
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# 파일 암호화 복원
PASSWORD = os.getenv("LIB_PASSWORD")
enc_file_path = 'secrets/variables.json_enc'
kdf = PBKDF2HMAC(algorithm=hashes.SHA256(),
                 length=32,
                 salt=b'salt',
                 iterations=390000)
key = base64.urlsafe_b64encode(kdf.derive(bytes(PASSWORD, 'utf-8')))
fernet = Fernet(key)
# opening the encrypted file
with open(enc_file_path, 'rb') as enc_file:
    encrypted = enc_file.read()
# decrypting the file
decrypted = fernet.decrypt(encrypted).decode('utf8')
data = json.loads(decrypted)

#변수 선언
API_ENDPOINT = data['API_ENDPOINT']
qr_path = data['qr_path']
assign_path = data['assign_path']
info_path = data['info_path']
extend_path = data['extend_path']
return_path = data['return_path']
USER_AGENT = data['User-Agent']
userID = data['userID']
userIDs = data['userIDs']
console = Console()

# 로그 생성
logger = logging.getLogger()
# 로그 색상
coloredlogs.install(logger=logger)
# 로그의 출력 기준 설정
logger.setLevel(logging.INFO)
# log 출력 형식
formatter = logging.Formatter(
    '%(asctime)s, %(levelname)-8s [%(filename)s:%(module)s:%(funcName)s:%(lineno)d] %(message)s'
)
# # log를 console에 출력
# stream_handler = logging.StreamHandler()
# stream_handler.setFormatter(formatter)
# logger.addHandler(stream_handler)
# log를 파일에 출력
file_handler = logging.FileHandler('log.txt', encoding='utf-8')
file_handler.setFormatter(formatter)
logger.addHandler(file_handler)


class Library(cmd.Cmd):
    # 인트로 테이블
    intro = Table(title=f"도서관 도우미 / [turquoise2]ID : {userID}[/turquoise2]",
                  box=box.ASCII2,
                  show_header=True,
                  header_style="blue",
                  show_lines=True)
    intro.add_column("명령어", style="dim")
    intro.add_column("제목")
    intro.add_column("매개변수, *은 선택", style="bold yellow")
    intro.add_row("set", "기본 유저 설정", "userID")
    intro.add_row("qr", "QR 생성", "*userID")
    intro.add_row("assign", "자리 할당", "*userID roomNo seatNo")
    intro.add_row("info", "자리 정보", "*userID")
    intro.add_row("extend", "연장", "*userID")
    intro.add_row("return", "반납", "*userID")
    intro.add_row("exit", "종료", "*userID")
    intro.add_row("loop", "루프", "roomNo seatNo")
    intro.add_row("stateAll", "모든 좌석", "")
    intro.add_row("swap", "자리 스왑", "fromUserID toUserID")
    intro.add_row("autoexpand", "자동 연장", "*userID")
    intro.add_row("book", "예약", "time roomNo SeatNo")
    prompt = '(입력) : '

    def onecmd(self, line):
        try:
            return super().onecmd(line)
        except KeyboardInterrupt:
            return False
        except Exception as e:
            # display error message
            logger.error(e)
            return False

    def preloop(self):
        #나의 아이디
        self.userID = userID
        #모든 아이디 print
        # print(userIDs)
        #인트로
        # console.print(self.intro)

        # 세션 생성
        self.session = requests.Session()
        retry = Retry(total=100000, backoff_factor=0)
        adapter = HTTPAdapter(max_retries=retry)
        self.session.mount('http://', adapter)
        self.session.mount('https://', adapter)
        self.session.headers.update({
            "Content-Type": "application/x-www-form-urlencoded",
            "User-Agent": USER_AGENT
        })

        self.do_info()
        self.do_qr()

    def postcmd(self, stop, line):
        if stop:
            logger.info("프로그램을 종료합니다...")
            return True
        # console.print(self.intro)

    def do_help(self, *arg):
        console.print(self.intro)

    def do_set(self, *arg):
        """기본 유저를 설정합니다."""
        self.userID = arg[0]
        logger.info(f"기본 유저를 {self.userID}로 설정함")

    def do_qr(self, *arg):
        """qr코드를 생성합니다"""
        _userID = self.get_userid(self, arg)
        payload = {"userID": _userID}
        response = self.session.post(f"{API_ENDPOINT}{qr_path}", data=payload)
        root = ET.fromstring(response.text)
        resultCode = root[0].text

        if resultCode == "0":
            qrCode = root[2][4].text
            logger.info(f"{_userID}의 QR코드 : {qrCode}")
            self.genQR(qrCode)
        else:
            logger.critical("QR코드 생성 실패")

    def do_assign(self, arg):
        """자리를 할당합니다."""
        try:
            _ = [s for s in arg.split()]
            if len(_) == 3:
                _userID = _[0]
                _roomNo = _[1]
                _seatNo = _[2]
            elif len(_) == 2:
                _userID = self.userID
                _roomNo = _[0]
                _seatNo = _[1]
            else:
                raise Exception
        except:
            logger.warning("올바른 매개수를 입력하세요.")
            return False
        payload = {"userID": _userID, "seatNo": _seatNo, "roomNo": _roomNo}
        response = self.session.post(f"{API_ENDPOINT}{assign_path}",
                                     data=payload)
        try:
            root = ET.fromstring(response.text)
            resultCode = root[0][0].text
            resultMsg = root[0][1].text
            logger.info(resultMsg)
        except:
            logger.critical(f"response.status_code : {response.status_code}")

    def do_info(self, *arg, output=True):
        """자리 상태를 확인합니다."""
        # if arg and arg[0]: _userID = arg[0]
        # else : _userID = self.userID
        _userID = self.get_userid(self, arg)
        payload = {"userID": _userID}
        response = self.session.post(f"{API_ENDPOINT}{info_path}",
                                     data=payload)
        root = ET.fromstring(response.text)
        mySeat = {
            "roomNm": root[2][0][1].text,
            "roomNo": root[2][0][2].text,
            "seatNo": root[2][0][3].text,
            "seat_use_time": root[2][0][4].text,
            "reverseYn": root[2][0][11].text,
            "remTm": root[2][0][7].text
        }
        self.seatNo = mySeat['seatNo']
        self.roomNo = mySeat['roomNo']
        self.reverseYn = mySeat['reverseYn']
        self.remTm = mySeat['remTm']
        self.endTm = root[2][0][6].text
        self.contCnt = root[2][0][8].text

        if output:
            print(f"[turquoise2]ID : {_userID}[/turquoise2] | ", end="")
            for key, value in mySeat.items():
                print(f"{key} : {value} | ", end="")
            print()

    def do_extend(self, *arg):
        """자리를 연장합니다."""
        _userID = self.get_userid(self, arg)
        self.do_info(_userID, output=False)
        payload = {
            "userID": _userID,
            "seatNo": self.seatNo,
            "roomNo": self.roomNo
        }
        response = self.session.post(f"{API_ENDPOINT}{extend_path}",
                                     data=payload)
        root = ET.fromstring(response.text)
        resultMsg = root[0][1].text
        logger.info(resultMsg)

    def do_return(self, *arg):
        """자리를 반납합니다."""
        _userID = self.get_userid(self, arg)
        self.do_info(_userID, output=False)
        payload = {
            "userID": _userID,
            "seatNo": self.seatNo,
            "roomNo": self.roomNo
        }
        response = self.session.post(f"{API_ENDPOINT}{return_path}",
                                     data=payload)
        root = ET.fromstring(response.text)
        resultMsg = root[0][1].text
        logger.info(f"{_userID} : {resultMsg}")

    def do_exit(self, *arg):
        """ 종료합니다 """
        return True

    def do_loop(self, arg):
        userIDs = ["wise10", "wise11", "wise12", "wise13", "wise14"]

        self.do_info(userIDs[0])
        _roomNo, _seatNo = [s for s in arg.split()]
        if self.roomNo != None or self.seatNo != None:
            self.do_return((userIDs[0]))
        logger.info(f"선택 자리 : {_roomNo} / {_seatNo}")
        i = 0
        while True:
            if i == len(userIDs):
                i = 0
            _userID = userIDs[i]
            self.do_assign(f"{_userID} {_roomNo} {_seatNo}")
            self.do_info((_userID))
            if self.roomNo != _roomNo and self.seatNo != _seatNo:
                logger.critical("예약 실패")
                return False
            logger.info("15분 타이머 시작...")
            self.timer(15)
            self.do_return((_userID))
            i = i + 1

    def do_stateAll(self, arg):
        """모든 아이디의 자리 현황을 출력합니다."""
        _userID = self.userID  #임시저장
        for id in userIDs:
            self.do_info((id))
        self.userID = _userID  #다시 저장

    def do_swap(self, arg):
        """자리를 교환합니다"""
        fromUserID, toUserID = [s for s in arg.split()]
        # toUser의 자리 반납 확인
        self.do_info((toUserID))
        if self.seatNo != None or self.seatNo != None:
            answer = input(f"{toUserID}의 자리를 반납하고 계속하시겠습니까? y/n : ")
            if answer == "y":
                self.do_return((toUserID))
            else:
                logger.info("자리 교환을 취소합니다.")
                return False
        #자리 교환
        self.do_info((fromUserID))
        if self.userID == None or self.roomNo == None:
            logger.critical(f"예약 정보가 확인되지 않음")
            return False
        self.do_return((fromUserID))
        _roomNo = self.roomNo
        _seatNo = self.seatNo
        self.do_assign((f"{toUserID} {_roomNo} {_seatNo}"))

    def do_autoexpand(self, *arg):
        """자리 자동 연장"""
        if arg and arg[0]: _userID = arg[0]
        else: _userID = self.userID
        self.do_info((_userID))
        if self.endTm == None:
            logger.critical("예약 정보가 확인되지 않음")
            return False
        elif self.reverseYn == 'Y':
            logger.critical("예약 상태에서는 연장이 불가능")
            return False

        self.update_remain_extend_num(_userID)
        while (self.extend_num < 4):
            self.timer(self.wait)
            self.do_extend((_userID))

            self.update_remain_extend_num(_userID)
        logger.info("연장 횟수가 끝났습니다.")

    def do_book(self, arg):
        """예약
        """
        _time, _roomNo, _seatNo = [s for s in arg.split()]
        # schedule.every().day.at("11:05").do(self.do_loop(self, f"{_roomNo} {_seatNo}"))
        schedule.every().day.at("12:05").do(self.do_info(self))
        # schedule.run_pending()

    def do_show(self):
        """자리 번호 확인"""
        pass

    def get_userid(self, *arg) -> str:
        """userid를 얻음
        """
        if arg[len(arg) - 1] and arg[len(arg) - 1][0]:
            _userID = arg[len(arg) - 1][0]
        else:
            _userID = self.userID
        return _userID

    def timer(self, min):
        """min분 타이머"""
        # 현재 시간을 가져옴
        now = datetime.now()
        # 다음 정각 시간을 계산 (분, 초를 0으로 설정)
        next_min = (now + timedelta(minutes=min))
        # 남은 시간을 계산
        wait_time = int((next_min - now).total_seconds())
        # 남은 시간만큼 대기
        for i in range(wait_time):
            remain_second = wait_time - i
            print("타이머 {}분 | 남은 시간: {}분 {}초...".format(
                min, math.floor(remain_second / 60), remain_second % 60),
                  end="\r")
            time.sleep(1)
        print("\n")

    def update_remain_extend_num(self, id) -> None:
        """남은 시간 & 연장 횟수

        Args:
            id (int): 학번
        """
        self.do_info((id), output=False)
        remain_text = self.remTm.strip().split("시간")
        if len(remain_text) == 2:
            remain_min = int(remain_text[0]) * 60 + int(
                remain_text[1].split("분")[0])
        elif len(remain_text) == 1:
            remain_min = int(remain_text[1].split("분")[0])
        logger.info(f"지금까지 남은 시간은 {remain_min}분")
        # 연장 횟수 확인
        logger.info(f"지금까지 연장 횟수는 {self.contCnt}")
        extend_num = int(self.contCnt.strip().split("/")[0])

        if (remain_min < 120):
            wait = 0
        elif (remain_min > 120):
            wait = remain_min - 120 + 1  # +1: 오차 보정

        self.wait = wait
        self.remain_min = remain_min
        self.extend_num = extend_num

    def genQR(self, data):
        """QR 이미지 생성"""
        qr = qrcode.QRCode(version=1,
                           error_correction=qrcode.constants.ERROR_CORRECT_H,
                           box_size=5)
        qr.add_data(data)
        qr.make(fit=True)

        img = qr.make_image(fill_color="black", back_color="white")
        img.save('qr.png')
        img = qr.make_image(fill_color="white", back_color="black")
        img.save('qr-invert.png')

        qr.print_ascii()

    def do_bad(self, arg):
        """오류 생성 테스트"""
        er = arg[0]


if __name__ == '__main__':
    Library().cmdloop()
