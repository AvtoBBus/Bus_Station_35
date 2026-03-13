from fastapi import UploadFile
import aiohttp
import re
import json
import random

async def describe_image(file_data: bytes, file: UploadFile, userIp: str):
    url = "https://facee.ru/api/public/describe-image"
    
    headers = {
        "accept": "*/*",
        "accept-language": "ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7",
        "authorization": "Bearer null",
        "cache-control": "no-cache",
        "pragma": "no-cache",
        "sec-ch-ua": "\"Chromium\";v=\"142\", \"Google Chrome\";v=\"142\", \"Not_A Brand\";v=\"99\"",
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": "\"Windows\"",
        "sec-fetch-dest": "empty",
        "sec-fetch-mode": "cors",
        "sec-fetch-site": "same-origin",
        "x-forwarded-for": userIp
    }
    
    data = aiohttp.FormData()
    data.add_field('file', file_data, filename=file.filename, content_type=file.content_type)
    data.add_field('filename', file.filename)
    data.add_field('describeType', 'calories-by-photo')
    
    async with aiohttp.ClientSession() as session:
        async with session.post(url, headers=headers, data=data) as response:
            result = await response.text()
            print(f"Status Code: {response.status}")
            print(f"Response: {result}")

            try:
                checkError = json.loads(result)
                if 'message' in checkError:
                    return checkError['message']
            except:
                print(result)

            return parse_text(result)
        
def parse_text(text: str):
    """Расширенная версия с дополнительными паттернами"""
    patterns = [
        # Паттерн 1: с звездочками и БЖУ с единицами измерения (дробные числа)
        r'\*\*(\d+[,.]?\d*)(?:-(\d+[,.]?\d*))?\*\*.*?БЖУ:\s*(\d+[,.]?\d*(?:-\d+[,.]?\d*)?)\s*г?\s*белков\s*/\s*(\d+[,.]?\d*(?:-\d+[,.]?\d*)?)\s*г?\s*жиров\s*/\s*(\d+[,.]?\d*(?:-\d+[,.]?\d*)?)\s*г?\s*углеводов',
        
        # Паттерн 2: без звездочек и БЖУ с единицами измерения (дробные числа)
        r'калорий.*?порции:\s*(\d+[,.]?\d*)(?:-(\d+[,.]?\d*))?;.*?БЖУ:\s*(\d+[,.]?\d*(?:-\d+[,.]?\d*)?)\s*г?\s*белков\s*/\s*(\d+[,.]?\d*(?:-\d+[,.]?\d*)?)\s*г?\s*жиров\s*/\s*(\d+[,.]?\d*(?:-\d+[,.]?\d*)?)\s*г?\s*углеводов',
        
        # Паттерн 3: с звездочками (оригинальный с дробными числами)
        r'\*\*(\d+[,.]?\d*)(?:-(\d+[,.]?\d*))?\*\*.*?БЖУ:\s*(\d+[,.]?\d*(?:-\d+[,.]?\d*)?)\s*белков\s*/\s*(\d+[,.]?\d*(?:-\d+[,.]?\d*)?)\s*жиров\s*/\s*(\d+[,.]?\d*(?:-\d+[,.]?\d*)?)\s*углеводов',
        
        # Паттерн 4: без звездочек (оригинальный с дробными числами)  
        r'калорий.*?порции:\s*(\d+[,.]?\d*)(?:-(\d+[,.]?\d*))?;.*?БЖУ:\s*(\d+[,.]?\d*(?:-\d+[,.]?\d*)?)\s*белков\s*/\s*(\d+[,.]?\d*(?:-\d+[,.]?\d*)?)\s*жиров\s*/\s*(\d+[,.]?\d*(?:-\d+[,.]?\d*)?)\s*углеводов',
    ]
    
    for pattern in patterns:
        match = re.search(pattern, text, re.IGNORECASE | re.DOTALL | re.MULTILINE)
        if match:
            # Функция для преобразования строки в число (заменяет запятую на точку)
            def parse_number(value_str):
                if not value_str:
                    return 0
                # Берем первое число если есть диапазон
                first_part = value_str.split('-')[0].strip()
                # Заменяем запятую на точку и преобразуем в float
                return float(first_part.replace(',', '.'))
            
            # Обработка калорий
            calories_min = parse_number(match.group(1))
            calories_max = parse_number(match.group(2)) if match.group(2) else calories_min
            
            # Обработка БЖУ (группы 3, 4, 5)
            proteins = parse_number(match.group(3))
            fats = parse_number(match.group(4))
            carbs = parse_number(match.group(5))
            
            return {
                'calories_min': calories_min,
                'calories_max': calories_max,
                'proteins': proteins,
                'fats': fats,
                'carbs': carbs,
                'origin_text': text
            }
    
    return None