from rich.console import Console
from rich.table import Table
from rich import box

console = Console()

table = Table(title="부산대 도서관 도움말", box=box.ROUNDED, show_header=True, header_style="blue", show_lines=True)
table.add_column("number", style="dim")
table.add_column("제목")
table.add_column("매개변수", style="bold yellow")
table.add_column("설명")
table.add_row(
    "1",
    "QR 생성",
    "", 
    "출입에 필요한 QR를 생성합니다."
)
table.add_row(
    "2",
    "자리 할당",
    "roomNo seatNo",
    "자리를 할당합니다.",
)
table.add_row(
    "3",
    "내 자리",
    "",
    "내 자리 현황을 확인합니다.",
)
table.add_row(
    "4",
    "연장",
    "",
    "내 자리를 연장합니다.",
)
table.add_row(
    "5",
    "반납",
    "",
    "내 자리를 반납합니다.",
)
table.add_row(
    "6",
    "종료",
    "",
    "프로그램을 종료합니다.",
)
table.add_row(
    "loop",
    "지정석",
    "roomNo seatNo",
    "자리를 계속 예약합니다.",
)
table.add_row(
    "stateAll",
    "모든 자리 확인",
    "",
    "내 아이디의 모든 자리를 확인합니다.",
)

console.print(table)

