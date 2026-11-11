import logging
import json
from fastapi import Request, Response
import time
import uuid

# Настройка цветов ANSI
class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    GRAY = '\033[90m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    RESET = '\033[0m'

def get_status_color(status_code: int) -> str:
    """Возвращает цвет для статус кода"""
    if 100 <= status_code < 200:
        return Colors.CYAN
    elif 200 <= status_code < 300:
        return Colors.GREEN
    elif 300 <= status_code < 400:
        return Colors.BLUE
    elif 400 <= status_code < 500:
        return Colors.YELLOW
    else:
        return Colors.RED

def get_status_emoji(status_code: int) -> str:
    """Возвращает emoji для статус кода"""
    if 200 <= status_code < 300:
        return "✅"
    elif 300 <= status_code < 400:
        return "↪️"
    elif 400 <= status_code < 500:
        return "⚠️"
    else:
        return "❌"

async def log_request_info(request: Request, request_id: str):
    """Логирование информации о входящем запросе с цветами"""
    
    # Короткий ID для красоты
    short_id = request_id[:8]
    
    print(f"\n{Colors.BOLD}{Colors.MAGENTA}╔═══════════════════════════════════════════════════════════════{Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.MAGENTA}║ 📥 INCOMING REQUEST [{short_id}]{Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.MAGENTA}╠═══════════════════════════════════════════════════════════════{Colors.RESET}")
    
    # Базовая информация
    print(f"{Colors.BOLD}{Colors.WHITE}║ {Colors.CYAN}Method: {Colors.BOLD}{request.method}{Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.WHITE}║ {Colors.CYAN}URL: {Colors.WHITE}{request.url}{Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.WHITE}║ {Colors.CYAN}Client: {Colors.WHITE}{request.client.host if request.client else 'Unknown'}{Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.WHITE}║ {Colors.CYAN}User-Agent: {Colors.WHITE}{request.headers.get('user-agent', 'Unknown')}{Colors.RESET}")
    
    # Заголовки
    headers = dict(request.headers)
    sensitive_headers = ['authorization', 'cookie', 'proxy-authorization']
    
    print(f"{Colors.BOLD}{Colors.WHITE}║ {Colors.CYAN}Headers:{Colors.RESET}")
    for header, value in headers.items():
        if header.lower() in sensitive_headers:
            print(f"{Colors.BOLD}{Colors.WHITE}║   {Colors.GRAY}{header}: {Colors.RED}***{Colors.RESET}")
        else:
            print(f"{Colors.BOLD}{Colors.WHITE}║   {Colors.GRAY}{header}: {Colors.WHITE}{value}{Colors.RESET}")
    
    # Тело запроса для не-GET запросов
    if request.method not in ["GET", "HEAD"]:
        try:
            body = await request.body()
            if body:
                print(f"{Colors.BOLD}{Colors.WHITE}║ {Colors.CYAN}Body:{Colors.RESET}")
                try:
                    body_json = json.loads(body.decode())
                    formatted_body = json.dumps(body_json, indent=2, ensure_ascii=False)
                    for line in formatted_body.split('\n'):
                        print(f"{Colors.BOLD}{Colors.WHITE}║   {Colors.GREEN}{line}{Colors.RESET}")
                except json.JSONDecodeError:
                    body_text = body.decode()[:500]  # Ограничиваем длину
                    print(f"{Colors.BOLD}{Colors.WHITE}║   {Colors.YELLOW}{body_text}{Colors.RESET}")
        except Exception as e:
            print(f"{Colors.BOLD}{Colors.WHITE}║   {Colors.RED}Body error: {str(e)}{Colors.RESET}")
    
    print(f"{Colors.BOLD}{Colors.MAGENTA}╚═══════════════════════════════════════════════════════════════{Colors.RESET}\n")

async def log_response_info(response: Response, request_id: str, processing_time: float):
    """Логирование информации об ответе с цветами"""
    
    short_id = request_id[:8]
    status_color = get_status_color(response.status_code)
    emoji = get_status_emoji(response.status_code)
    
    print(f"\n{Colors.BOLD}{status_color}╔═══════════════════════════════════════════════════════════════{Colors.RESET}")
    print(f"{Colors.BOLD}{status_color}║ {emoji} RESPONSE [{short_id}]{Colors.RESET}")
    print(f"{Colors.BOLD}{status_color}╠═══════════════════════════════════════════════════════════════{Colors.RESET}")
    
    print(f"{Colors.BOLD}{Colors.WHITE}║ {Colors.CYAN}Status: {status_color}{Colors.BOLD}{response.status_code} {Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.WHITE}║ {Colors.CYAN}Time: {Colors.WHITE}{processing_time:.3f}s{Colors.RESET}")
    
    # Заголовки ответа
    headers = dict(response.headers)
    if headers:
        print(f"{Colors.BOLD}{Colors.WHITE}║ {Colors.CYAN}Response Headers:{Colors.RESET}")
        for header, value in headers.items():
            print(f"{Colors.BOLD}{Colors.WHITE}║   {Colors.GRAY}{header}: {Colors.WHITE}{value}{Colors.RESET}")
    
    print(f"{Colors.BOLD}{status_color}╚═══════════════════════════════════════════════════════════════{Colors.RESET}\n")